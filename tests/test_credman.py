"""Client PIN and credential management, driven by python-fido2 as the browser."""

import hashlib
import logging
import os
import unittest
from dataclasses import replace
from unittest.mock import patch

from fido2.client import ClientError, Fido2Client
from fido2.cose import CoseKey, ES256
from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2
from fido2.ctap2.credman import CredentialManagement
from fido2.ctap2.pin import ClientPin, PinProtocolV1, PinProtocolV2
from fido2.hid import CTAPHID
from fido2.server import Fido2Server
from fido2.webauthn import (
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    ResidentKeyRequirement,
)

from localpasskey import cbor, clientpin
from localpasskey.clientpin import PinManager
from localpasskey.store import MAX_CREDENTIALS_PER_USER
from localpasskey.ctap2 import Verdict

from .helpers import Harness

PIN = "1234"
RP = CredentialManagement.RESULT
PARAM = CredentialManagement.PARAM


class _DummyClient:
    """The bare client python-fido2's ClientPin and CredentialManagement need."""

    def __init__(self, ctap, info):
        self.ctap2 = ctap
        self.info = info
        self.user_interaction = None

    def make_credential(self, rp, user, key_params, pin_uv_param=None, event=None, on_keepalive=None):
        return self.ctap2.make_credential(
            b"\0" * 32, rp, user, key_params, pin_uv_param=pin_uv_param, event=event
        )


class PinTestCase(unittest.TestCase):
    def setUp(self):
        self.h = Harness()
        self.ctap = Ctap2(self.h.device)
        self.client = _DummyClient(self.ctap, self.ctap.info)
        self.uid = self.h.requester.uid
        self.username = self.h.requester.username

    def tearDown(self):
        self.h.close()

    def pin_client(self, protocol=None):
        return ClientPin(self.ctap, protocol)

    def enrol(self, protocol=None, pin=PIN):
        # The first PIN goes in through the daemon, like `localpasskey pin set`:
        # getInfo omits "clientPin" until one exists, and python-fido2's own
        # set_pin refuses to send SET_PIN without that key. Replacing the cached
        # info is what a client that asks again after setting one would see.
        self.h.pins.set(self.uid, self.username, pin.encode())
        self.ctap._info = self.client.info = self.ctap.get_info()
        return self.pin_client(protocol)


class PinProtocolTests(PinTestCase):
    """Both PIN/UV auth protocol versions reach the same PIN state."""

    def test_set_pin_and_read_it_back(self):
        for protocol in (PinProtocolV1(), PinProtocolV2()):
            with self.subTest(protocol=protocol.VERSION):
                client = self.enrol(protocol)
                self.assertEqual(client.get_pin_retries()[0], clientpin.MAX_PIN_RETRIES)
                self.assertTrue(self.h.pins.is_set(self.uid, self.username))
                token = client.get_pin_token(PIN)
                self.assertTrue(client.protocol.validate_token(token))
                self.assertEqual(token, self.h.pins.token_for(self.h.requester))
                self.h.pins.remove(self.uid, self.username)

    def test_change_pin(self):
        client = self.enrol(PinProtocolV2())
        client.change_pin(PIN, "5678")
        self.assertEqual(client.get_pin_retries()[0], clientpin.MAX_PIN_RETRIES)
        client.get_pin_token("5678")
        with self.assertRaises(CtapError) as caught:
            client.change_pin("0000", "9999")
        self.assertEqual(caught.exception.code, CtapError.ERR.PIN_INVALID)
        self.assertEqual(client.get_pin_retries()[0], clientpin.MAX_PIN_RETRIES - 1)

    def test_set_pin_is_refused_once_a_pin_exists(self):
        self.enrol(PinProtocolV1())
        with self.assertRaises(CtapError) as caught:
            self.pin_client(PinProtocolV1()).set_pin("5678")
        self.assertEqual(caught.exception.code, CtapError.ERR.PIN_AUTH_INVALID)
        # The old PIN still works, so nothing was replaced.
        self.pin_client(PinProtocolV1()).get_pin_token(PIN)

    def test_wrong_pin_counting_and_recovery(self):
        client = self.enrol(PinProtocolV1())
        for expected in (7, 6):
            with self.subTest(retries=expected):
                self.wrong_pin(client, expected)
        client.get_pin_token(PIN)  # a correct PIN restores the count
        self.assertEqual(client.get_pin_retries()[0], clientpin.MAX_PIN_RETRIES)

    def test_forged_pin_macs_and_a_wrong_pin_are_refused(self):
        protocol = PinProtocolV2()
        key_agreement, secret = protocol.encapsulate(self.h.pins.key_agreement())
        pin_enc = protocol.encrypt(secret, b"5678".ljust(64, b"\0"))
        hash_enc = protocol.encrypt(secret, clientpin.pin_hash(PIN.encode()))
        for sub_command, extra in (
            (ClientPin.CMD.SET_PIN, {}),
            (ClientPin.CMD.CHANGE_PIN, {"pin_hash_enc": hash_enc}),
        ):
            with self.subTest(sub_command=sub_command):
                with self.assertRaises(CtapError) as caught:
                    self.ctap.client_pin(
                        protocol.VERSION, sub_command, key_agreement=key_agreement,
                        new_pin_enc=pin_enc, pin_uv_param=b"\0" * 32, **extra,
                    )
                self.assertEqual(caught.exception.code, CtapError.ERR.PIN_AUTH_INVALID)
                self.h.pins.set(self.uid, self.username, PIN.encode())  # CHANGE_PIN needs one
        client = self.enrol(protocol)
        before = self.h.pins.key_agreement()
        self.wrong_pin(client, clientpin.MAX_PIN_RETRIES - 1)
        self.assertNotEqual(self.h.pins.key_agreement()[-2], before[-2])
        client.get_pin_token(PIN)
        with self.assertRaises(CtapError) as caught:
            self.ctap.get_assertion(
                "example.com", b"\0" * 32, pin_uv_param=b"\0" * 32, pin_uv_protocol=2
            )
        self.assertEqual(caught.exception.code, CtapError.ERR.PIN_AUTH_INVALID)

    def wrong_pin(self, client, expected_retries):
        protocol = client.protocol
        _, secret = protocol.encapsulate(self.h.pins.key_agreement())
        pin_hash_enc = protocol.encrypt(secret, clientpin.pin_hash(b"0000"))
        with self.assertRaises(CtapError) as caught:
            self.ctap.client_pin(
                protocol.VERSION,
                ClientPin.CMD.GET_TOKEN_USING_PIN_LEGACY,
                key_agreement=self.h.pins.key_agreement(),
                pin_hash_enc=pin_hash_enc,
            )
        self.assertEqual(caught.exception.code, CtapError.ERR.PIN_INVALID)
        self.assertEqual(
            self.ctap.client_pin(protocol.VERSION, ClientPin.CMD.GET_PIN_RETRIES)[
                ClientPin.RESULT.PIN_RETRIES
            ],
            expected_retries,
        )

    def test_three_wrong_pins_block_the_authenticator(self):
        client = self.enrol(PinProtocolV2())
        for _ in range(clientpin.AUTH_BLOCK_AFTER - 1):
            with self.assertRaises(CtapError) as caught:
                client.get_pin_token("0000")
            self.assertEqual(caught.exception.code, CtapError.ERR.PIN_INVALID)
        # The third mismatch itself blocks, and so does the right PIN after it.
        for pin in ("0000", PIN):
            with self.assertRaises(CtapError) as caught:
                client.get_pin_token(pin)
            self.assertEqual(caught.exception.code, CtapError.ERR.PIN_AUTH_BLOCKED)
        # Restarting the daemon is the "power cycle" that clears the block.
        self.h.pins._mismatches.clear()
        self.assertEqual(client.get_pin_token(PIN), self.h.pins.token_for(self.h.requester))

    def test_retries_run_out_and_persist(self):
        self.enrol(PinProtocolV1())
        state = self.h.store.pin(self.uid, self.username)
        state.retries = 1
        self.h.store.set_pin(self.uid, self.username, state)
        for pin in ("0000", PIN):  # the last attempt is spent, then even the right PIN fails
            with self.assertRaises(CtapError) as caught:
                self.pin_client(PinProtocolV1()).get_pin_token(pin)
            self.assertEqual(caught.exception.code, CtapError.ERR.PIN_BLOCKED)
        # The count survives a daemon restart, unlike the mismatch counter.
        restarted = PinManager(self.h.store)
        self.assertEqual(restarted.retries(self.uid, self.username), 0)

    def test_pin_policy_violations(self):
        protocol = PinProtocolV2()
        for pin in (b"123", b"x" * 64, b"\xff\xfe\xfd\xfc"):
            with self.subTest(pin=pin):
                # Sent by hand: python-fido2 refuses a short PIN before sending it.
                key_agreement, secret = protocol.encapsulate(self.h.pins.key_agreement())
                pin_enc = protocol.encrypt(secret, pin.ljust(64, b"\0"))
                with self.assertRaises(CtapError) as caught:
                    self.ctap.client_pin(
                        protocol.VERSION, ClientPin.CMD.SET_PIN, key_agreement=key_agreement,
                        new_pin_enc=pin_enc, pin_uv_param=protocol.authenticate(secret, pin_enc),
                    )
                self.assertEqual(caught.exception.code, CtapError.ERR.PIN_POLICY_VIOLATION)
        self.assertFalse(self.h.pins.is_set(self.uid, self.username))

    def test_unknown_subcommands_are_rejected(self):
        for sub_command in (0x06, 0x07, 0x09, 0x7F):
            with self.subTest(sub_command=sub_command):
                with self.assertRaises(CtapError) as caught:
                    self.ctap.client_pin(1, sub_command, key_agreement=self.h.pins.key_agreement())
                self.assertEqual(caught.exception.code, CtapError.ERR.INVALID_SUBCOMMAND)

    def test_a_broken_key_agreement_is_an_invalid_parameter(self):
        self.enrol(PinProtocolV1())
        for key_agreement, expected in (
            ({}, CtapError.ERR.INVALID_PARAMETER),
            ({1: 2, -2: b"x" * 32}, CtapError.ERR.INVALID_PARAMETER),
            ({1: 2, -2: b"\0" * 32, -3: b"\0" * 32}, CtapError.ERR.INVALID_PARAMETER),  # not on the curve
            ("nope", CtapError.ERR.CBOR_UNEXPECTED_TYPE),
        ):
            with self.subTest(key_agreement=key_agreement):
                with self.assertRaises(CtapError) as caught:
                    self.ctap.client_pin(
                        1, ClientPin.CMD.GET_TOKEN_USING_PIN_LEGACY,
                        key_agreement=key_agreement, pin_hash_enc=b"x" * 16,
                    )
                self.assertEqual(caught.exception.code, expected)
        self.assertEqual(self.h.pins.retries(self.uid, self.username), clientpin.MAX_PIN_RETRIES)

    def test_a_client_can_still_set_the_first_pin_by_hand(self):
        # Without "clientPin" in getInfo no platform sends SET_PIN, but a client
        # that does must still be obeyed, and still ask for the password.
        self.assertNotIn("clientPin", self.ctap.info.options)
        protocol = PinProtocolV2()
        key_agreement, secret = protocol.encapsulate(self.h.pins.key_agreement())
        pin_enc = protocol.encrypt(secret, PIN.encode().ljust(64, b"\0"))
        prompts = len(self.h.verifier.messages)
        self.ctap.client_pin(
            protocol.VERSION, ClientPin.CMD.SET_PIN, key_agreement=key_agreement,
            new_pin_enc=pin_enc, pin_uv_param=protocol.authenticate(secret, pin_enc),
        )
        self.assertEqual(len(self.h.verifier.messages), prompts + 1)
        self.assertEqual(
            self.h.verifier.messages[-1],
            "Test Browser wants to set a PIN for the passkeys stored on this computer.",
        )
        self.assertTrue(self.h.pins.is_set(self.uid, self.username))

    def test_get_pin_token_needs_approval(self):
        self.enrol(PinProtocolV1())
        client = self.pin_client(PinProtocolV1())
        prompts = len(self.h.verifier.messages)
        client.get_pin_token(PIN)
        self.assertEqual(len(self.h.verifier.messages), prompts + 1)
        self.assertEqual(
            self.h.verifier.messages[-1],
            "Test Browser wants to manage the passkeys stored on this computer.",
        )
        self.h.verifier.verdict = Verdict.DENIED
        with self.assertRaises(CtapError) as caught:
            client.get_pin_token(PIN)
        self.assertEqual(caught.exception.code, CtapError.ERR.OPERATION_DENIED)

    def test_change_pin_needs_approval(self):
        self.enrol(PinProtocolV2())
        client = self.pin_client(PinProtocolV2())
        client.change_pin(PIN, "5678")
        self.assertEqual(
            self.h.verifier.messages[-1],
            "Test Browser wants to change the PIN for the passkeys stored on this computer.",
        )

    def test_permissions_are_rejected_when_a_token_is_requested(self):
        self.enrol(PinProtocolV1())
        key_agreement, _ = PinProtocolV1().encapsulate(self.h.pins.key_agreement())
        with self.assertRaises(CtapError) as caught:
            self.ctap.client_pin(
                1,
                ClientPin.CMD.GET_TOKEN_USING_PIN_LEGACY,
                key_agreement=key_agreement,
                pin_hash_enc=b"x" * 16,
                permissions=ClientPin.PERMISSION.CREDENTIAL_MGMT,
            )
        self.assertEqual(caught.exception.code, CtapError.ERR.INVALID_PARAMETER)


class CredentialManagementTests(PinTestCase):
    """Enumerating, renaming and deleting passkeys the way Chrome does."""

    def setUp(self):
        super().setUp()
        self.github = Fido2Server(PublicKeyCredentialRpEntity(id="github.com", name="GitHub"))
        self.example = Fido2Server(PublicKeyCredentialRpEntity(id="example.com", name="example"))
        self.creds = [self.register(self.github, b"alice", "alice"),
                      self.register(self.github, b"bob", "bob"),
                      self.register(self.example, b"alice", "alice")]

    def register(self, server, user_id, name):
        options, state = server.register_begin(
            PublicKeyCredentialUserEntity(id=user_id, name=name, display_name=name.title()),
            resident_key_requirement=ResidentKeyRequirement.REQUIRED,
        )
        result = Fido2Client(self.h.device, f"https://{server.rp.id}").make_credential(
            options["publicKey"]
        )
        return server.register_complete(state, result.client_data, result.attestation_object)

    def manager(self, protocol=None):
        client = self.enrol(protocol)
        return client, CredentialManagement(self.ctap, client.protocol, client.get_pin_token(PIN))

    def test_metadata_counts_live_discoverable_passkeys(self):
        _, credman = self.manager(PinProtocolV2())
        metadata = credman.get_metadata()
        self.assertEqual(metadata[RP.EXISTING_CRED_COUNT], 3)
        self.assertEqual(
            metadata[RP.MAX_REMAINING_COUNT], MAX_CREDENTIALS_PER_USER - 3
        )

    def test_metadata_hides_the_trash_but_the_cap_does_not(self):
        _, credman = self.manager()
        self.h.store.remove(self.uid, self.username, [self.creds[0].credential_data.credential_id])
        metadata = credman.get_metadata()
        self.assertEqual(metadata[RP.EXISTING_CRED_COUNT], 2, "a trashed passkey is gone")
        self.assertEqual(
            metadata[RP.MAX_REMAINING_COUNT], MAX_CREDENTIALS_PER_USER - 3,
            "the trash still takes space",
        )

    def test_enumerate_rps_and_credentials(self):
        _, credman = self.manager(PinProtocolV2())
        rps = credman.enumerate_rps()
        self.assertEqual([rp[RP.RP]["id"] for rp in rps], ["example.com", "github.com"])
        self.assertEqual([rp[RP.RP_ID_HASH] for rp in rps],
                         [hashlib.sha256(rp.encode()).digest() for rp in ("example.com", "github.com")])

        github_hash = hashlib.sha256(b"github.com").digest()
        entries = credman.enumerate_creds(github_hash)
        self.assertEqual(len(entries), 2)
        self.assertEqual(sorted(e[RP.USER]["name"] for e in entries), ["alice", "bob"])
        by_name = {e[RP.USER]["name"]: e for e in entries}
        self.assertEqual(by_name["alice"][RP.USER]["displayName"], "Alice")
        self.assertEqual(bytes(by_name["alice"][RP.CREDENTIAL_ID]["id"]),
                         self.creds[0].credential_data.credential_id)
        self.assertEqual(by_name["alice"][RP.CRED_PROTECT], 1)
        # The public key is the attested one: a signature made with the stored
        # private key verifies against it.
        key = CoseKey.parse(by_name["alice"][RP.PUBLIC_KEY])
        self.assertIsInstance(key, ES256)
        self.assertEqual(dict(key), dict(self.creds[0].credential_data.public_key))

    def test_enumerate_an_unknown_site_returns_nothing(self):
        _, credman = self.manager()
        self.assertEqual(credman.enumerate_creds(hashlib.sha256(b"nowhere.test").digest()), [])

    def test_enumerate_empty_authenticator(self):
        self.h.store.remove(
            self.uid, self.username, [c.credential_data.credential_id for c in self.creds]
        )
        client, _ = self.manager()
        credman = CredentialManagement(self.ctap, client.protocol, client.get_pin_token(PIN))
        with self.assertRaises(CtapError) as caught:
            credman.enumerate_rps_begin()
        self.assertEqual(caught.exception.code, CtapError.ERR.NO_CREDENTIALS)

    def test_get_next_without_a_begin_is_not_allowed(self):
        client, credman = self.manager()
        for call in (credman.enumerate_rps_next, credman.enumerate_creds_next):
            with self.subTest(call=call.__name__):
                with self.assertRaises(CtapError) as caught:
                    call()
                self.assertEqual(caught.exception.code, CtapError.ERR.NOT_ALLOWED)

    def test_get_next_cannot_change_requester(self):
        _, credman = self.manager()
        credman.enumerate_rps_begin()
        other = replace(self.h.requester, uid=self.h.requester.uid + 1)
        with patch.object(self.h.authenticator.resolver, "requester", other):
            with self.assertRaises(CtapError) as caught:
                credman.enumerate_rps_next()
        self.assertEqual(caught.exception.code, CtapError.ERR.NOT_ALLOWED)

    def test_enumerations_do_not_mix(self):
        client, credman = self.manager()
        credman.enumerate_rps_begin()
        with self.assertRaises(CtapError) as caught:
            credman.enumerate_creds_next()
        self.assertEqual(caught.exception.code, CtapError.ERR.NOT_ALLOWED)

    def test_a_get_next_past_the_last_item_is_not_allowed(self):
        # Round one: Begin itself returns the only entry of each kind, so no
        # item is left to hand out.
        self.h.store.remove(self.uid, self.username, [self.creds[1].credential_data.credential_id])
        self.h.store.remove(self.uid, self.username, [self.creds[2].credential_data.credential_id])
        _, credman = self.manager()
        github_hash = hashlib.sha256(b"github.com").digest()
        for begin, next_call in (
            (credman.enumerate_rps_begin, credman.enumerate_rps_next),
            (lambda: credman.enumerate_creds_begin(github_hash), credman.enumerate_creds_next),
        ):
            with self.subTest(next_call=next_call.__name__):
                begin()
                with self.assertRaises(CtapError) as caught:
                    next_call()
                self.assertEqual(caught.exception.code, CtapError.ERR.NOT_ALLOWED)

    def test_an_abandoned_enumeration_expires(self):
        client, credman = self.manager()
        credman.enumerate_rps_begin()
        state = self.h.connection.transport._channels[self.h.device._channel_id]
        state.credman.deadline = 0.0
        with self.assertRaises(CtapError) as caught:
            credman.enumerate_rps_next()
        self.assertEqual(caught.exception.code, CtapError.ERR.NOT_ALLOWED)
        self.assertIsNone(state.credman)

    def test_another_command_clears_the_enumeration(self):
        client, credman = self.manager()
        credman.enumerate_rps_begin()
        self.ctap.get_info()
        with self.assertRaises(CtapError) as caught:
            credman.enumerate_rps_next()
        self.assertEqual(caught.exception.code, CtapError.ERR.NOT_ALLOWED)

    def test_delete_moves_the_passkey_to_the_trash(self):
        client, credman = self.manager(PinProtocolV2())
        cred_id = self.creds[0].credential_data.credential_id
        credman.delete_cred({"id": cred_id, "type": "public-key"})
        self.assertEqual([c.id for c in self.h.store.trash(self.uid, self.username)], [cred_id])
        self.assertEqual(len(self.h.credentials()), 2)
        self.assertNotIn(cred_id, [c.id for c in self.h.credentials()])
        self.assertEqual(credman.get_metadata()[RP.EXISTING_CRED_COUNT], 2)
        self.assertEqual(
            self.h.notifier.notes[-1],
            ("Passkey moved to the trash", "Test Browser moved the passkey for github.com to the trash.", "activity"),
        )
        # It no longer signs in, discoverable or by allow list, and is not reported
        # as an excluded credential either.
        server = self.github
        options, _ = server.authenticate_begin(None)
        selection = Fido2Client(self.h.device, "https://github.com").get_assertion(options["publicKey"])
        self.assertEqual([r.user["id"] for r in selection.get_assertions()], [b"bob"])
        options, _ = server.authenticate_begin(
            [PublicKeyCredentialDescriptor(type="public-key", id=cred_id)]
        )
        with self.assertRaises(ClientError):
            Fido2Client(self.h.device, "https://github.com").get_assertion(options["publicKey"])
        options, state = server.register_begin(
            PublicKeyCredentialUserEntity(id=b"alice", name="alice", display_name="Alice"),
            [PublicKeyCredentialDescriptor(type="public-key", id=cred_id)],
        )
        Fido2Client(self.h.device, "https://github.com").make_credential(options["publicKey"])

    def test_one_request_looks_up_its_requester_once(self):
        client, credman = self.manager()
        resolver = self.h.authenticator.resolver
        with patch.object(resolver, "resolve", wraps=resolver.resolve) as resolve:
            credman.delete_cred({"id": self.creds[0].credential_data.credential_id, "type": "public-key"})
            self.assertEqual(resolve.call_count, 1)
            client.change_pin(PIN, "5678")
            self.assertEqual(resolve.call_count, 2, "getKeyAgreement needs no requester")

    def test_deleting_an_unknown_passkey_is_refused(self):
        client, credman = self.manager()
        with self.assertRaises(CtapError) as caught:
            credman.delete_cred({"id": os.urandom(32), "type": "public-key"})
        self.assertEqual(caught.exception.code, CtapError.ERR.NO_CREDENTIALS)

    def test_trashed_passkeys_are_not_enumerated(self):
        client, credman = self.manager()
        self.h.store.remove(self.uid, self.username, [self.creds[0].credential_data.credential_id])
        entries = credman.enumerate_creds(hashlib.sha256(b"github.com").digest())
        self.assertEqual([e[RP.USER]["name"] for e in entries], ["bob"])

    def test_update_user_information(self):
        client, credman = self.manager()
        cred_id = self.creds[0].credential_data.credential_id
        credman.update_user_info(
            {"id": cred_id, "type": "public-key"},
            {"id": b"alice", "name": "alice-renamed", "displayName": "Alice Renamed"},
        )
        [stored] = [c for c in self.h.credentials() if c.id == cred_id]
        self.assertEqual((stored.user_name, stored.user_display_name), ("alice-renamed", "Alice Renamed"))
        entry = credman.enumerate_creds(hashlib.sha256(b"github.com").digest())[0]
        self.assertEqual(entry[RP.USER]["name"], "alice-renamed")

    def test_site_names_stay_out_of_the_default_log(self):
        client, credman = self.manager()
        descriptor = {"id": self.creds[0].credential_data.credential_id, "type": "public-key"}
        with self.assertLogs("localpasskey", logging.INFO) as logs:
            credman.update_user_info(descriptor, {"id": b"alice", "name": "alice-renamed"})
            credman.delete_cred(descriptor)
        self.assertEqual([r.getMessage() for r in logs.records if "github.com" in r.getMessage()], [])

    def test_update_user_information_clears_a_null_name(self):
        client, credman = self.manager()
        cred_id = self.creds[0].credential_data.credential_id
        # python-fido2 cannot encode null, so the request is built by hand.
        sub_params = {2: {"id": cred_id, "type": "public-key"}, 3: {"id": b"alice", "name": None}}
        mac = client.protocol.authenticate(credman.pin_uv.token, b"\x07" + cbor.encode(sub_params))
        request = cbor.encode({1: 7, 2: sub_params, 3: client.protocol.VERSION, 4: mac})
        self.assertEqual(self.h.device.call(CTAPHID.CBOR, b"\x0a" + request)[0], 0)
        [stored] = [c for c in self.h.credentials() if c.id == cred_id]
        self.assertEqual((stored.user_name, stored.user_display_name), ("", ""))

    def test_update_user_information_with_a_different_user_id(self):
        client, credman = self.manager()
        with self.assertRaises(CtapError) as caught:
            credman.update_user_info(
                {"id": self.creds[0].credential_data.credential_id, "type": "public-key"},
                {"id": b"someone-else", "name": "x"},
            )
        self.assertEqual(caught.exception.code, CtapError.ERR.INVALID_PARAMETER)

    def test_missing_pin_uv_auth_param_is_puat_required(self):
        key_agreement, _ = PinProtocolV2().encapsulate(self.h.pins.key_agreement())
        with self.assertRaises(CtapError) as caught:
            self.ctap.credential_mgmt(0x01)
        self.assertEqual(caught.exception.code, CtapError.ERR.PUAT_REQUIRED)

    def test_a_token_of_another_requester_is_refused(self):
        client, credman = self.manager()
        other = replace(self.h.requester, pid=self.h.requester.pid + 1)
        with patch.object(self.h.authenticator.resolver, "requester", other):
            with self.assertRaises(CtapError) as caught:
                self.ctap.credential_mgmt(
                    0x01,
                    pin_uv_protocol=client.protocol.VERSION,
                    pin_uv_param=client.protocol.authenticate(
                        self.h.pins.token_for(self.h.requester), bytes([0x01])
                    ),
                )
        self.assertEqual(caught.exception.code, CtapError.ERR.PIN_AUTH_INVALID)

    def test_a_forged_mac_is_refused(self):
        client, _ = self.manager()
        with self.assertRaises(CtapError) as caught:
            self.ctap.credential_mgmt(
                0x01, pin_uv_protocol=client.protocol.VERSION, pin_uv_param=b"\0" * 16
            )
        self.assertEqual(caught.exception.code, CtapError.ERR.PIN_AUTH_INVALID)


class PinFlowTests(PinTestCase):
    """Ordinary WebAuthn flows with a PIN set, and the zero-length pinUvAuthParam."""

    def setUp(self):
        super().setUp()
        self.server = Fido2Server(PublicKeyCredentialRpEntity(id="example.com", name="example"))

    def register(self):
        options, state = self.server.register_begin(
            PublicKeyCredentialUserEntity(id=b"alice", name="alice", display_name="Alice")
        )
        result = Fido2Client(self.h.device, "https://example.com").make_credential(
            options["publicKey"]
        )
        return self.server.register_complete(state, result.client_data, result.attestation_object)

    def test_signing_in_still_works_and_prompts_once_with_a_pin_set(self):
        self.h.pins.set(self.uid, self.username, PIN.encode())
        prompts = len(self.h.verifier.messages)
        registration = self.register()
        self.assertEqual(len(self.h.verifier.messages), prompts + 1)
        options, state = self.server.authenticate_begin([registration.credential_data])
        selection = Fido2Client(self.h.device, "https://example.com").get_assertion(options["publicKey"])
        response = selection.get_response(0)
        self.server.authenticate_complete(
            state, [registration.credential_data], response.credential_id, response.client_data,
            response.authenticator_data, response.signature,
        )
        self.assertEqual(len(self.h.verifier.messages), prompts + 2, "one prompt per ceremony")

    def test_zero_length_pin_uv_auth_param_at_the_protocol_level(self):
        for pin, expected in ((None, CtapError.ERR.PIN_NOT_SET), (PIN, CtapError.ERR.PIN_INVALID)):
            with self.subTest(expected=expected):
                if pin is not None:
                    self.h.pins.set(self.uid, self.username, pin.encode())
                prompts = len(self.h.verifier.messages)
                with self.assertRaises(CtapError) as caught:
                    self.ctap.make_credential(
                        b"\0" * 32, {"id": ".dummy"}, {"id": b"\x01", "name": "dummy"},
                        [{"type": "public-key", "alg": -7}], pin_uv_param=b"",
                    )
                self.assertEqual(caught.exception.code, expected)
                self.assertEqual(len(self.h.verifier.messages), prompts + 1, "the user is asked first")

    def test_a_pin_uv_auth_param_without_the_protocol_is_refused(self):
        self.h.pins.set(self.uid, self.username, PIN.encode())
        with self.assertRaises(CtapError) as caught:
            self.ctap.make_credential(
                b"\0" * 32, {"id": ".dummy"}, {"id": b"\x01", "name": "dummy"},
                [{"type": "public-key", "alg": -7}], pin_uv_param=b"\0" * 16,
            )
        self.assertEqual(caught.exception.code, CtapError.ERR.MISSING_PARAMETER)

    def test_a_pin_uv_auth_param_of_the_wrong_type_is_refused(self):
        # Any local client can send this; it must not look like a failure.
        self.enrol(PinProtocolV2())
        self.register()
        notes = len(self.h.notifier.notes)
        for send in (
            lambda: self.ctap.credential_mgmt(1, pin_uv_protocol=2, pin_uv_param=5),
            lambda: self.ctap.get_assertion(
                "example.com", b"\0" * 32, pin_uv_param=5, pin_uv_protocol=2
            ),
            lambda: self.ctap.make_credential(
                b"\0" * 32, {"id": "example.com"}, {"id": b"bob", "name": "bob"},
                [{"type": "public-key", "alg": -7}], pin_uv_param=5, pin_uv_protocol=2,
            ),
        ):
            with self.subTest(send=send):
                with self.assertRaises(CtapError) as caught:
                    send()
                self.assertEqual(caught.exception.code, CtapError.ERR.CBOR_UNEXPECTED_TYPE)
                self.assertEqual(len(self.h.notifier.notes), notes, "no error notification")

    def test_chromes_pin_fallback_asks_again_for_the_ceremony(self):
        # After the user declines built-in UV, Chrome asks for the PIN, gets a
        # token and resends the request with a pinUvAuthParam. That token only
        # proves the PIN, so the ceremony still asks-and names its site.
        registration = self.register()
        client = self.enrol(PinProtocolV2())
        cdh = os.urandom(32)
        allow = [{"type": "public-key", "id": registration.credential_data.credential_id}]
        for send in (
            lambda param: self.ctap.get_assertion(
                "example.com", cdh, allow, pin_uv_param=param, pin_uv_protocol=2
            ),
            lambda param: self.ctap.make_credential(
                cdh, {"id": "example.com"}, {"id": b"bob", "name": "bob"},
                [{"type": "public-key", "alg": -7}], pin_uv_param=param, pin_uv_protocol=2,
            ),
        ):
            with self.subTest(send=send):
                prompts = len(self.h.verifier.messages)
                token = client.get_pin_token(PIN)
                self.assertEqual(len(self.h.verifier.messages), prompts + 1)
                send(client.protocol.authenticate(token, cdh))
                self.assertEqual(
                    len(self.h.verifier.messages), prompts + 2, "the token approves nothing"
                )
                # And the ceremony's own approval is used up too.
                send(client.protocol.authenticate(token, cdh))
                self.assertEqual(len(self.h.verifier.messages), prompts + 3)

    def test_a_pin_token_approval_covers_nothing_else(self):
        registration = self.register()
        client = self.enrol(PinProtocolV2())
        allow = [{"type": "public-key", "id": registration.credential_data.credential_id}]
        with self.subTest("a sign-in without the token"):
            client.get_pin_token(PIN)
            prompts = len(self.h.verifier.messages)
            self.ctap.get_assertion("example.com", os.urandom(32), allow, options={"uv": True})
            self.assertEqual(len(self.h.verifier.messages), prompts + 1)
        with self.subTest("a sign-in after credential management used the approval"):
            token = client.get_pin_token(PIN)
            CredentialManagement(self.ctap, client.protocol, token).get_metadata()
            prompts = len(self.h.verifier.messages)
            cdh = os.urandom(32)
            self.ctap.get_assertion(
                "example.com", cdh, allow,
                pin_uv_param=client.protocol.authenticate(token, cdh), pin_uv_protocol=2,
            )
            self.assertEqual(len(self.h.verifier.messages), prompts + 1)

    def test_a_stale_token_is_refused(self):
        client = self.enrol(PinProtocolV2())
        self.h.pins.remove(self.uid, self.username)
        with self.assertRaises(CtapError) as caught:
            self.ctap.get_assertion(
                "example.com", b"\0" * 32,
                pin_uv_param=b"\0" * 32, pin_uv_protocol=client.protocol.VERSION,
            )
        self.assertEqual(caught.exception.code, CtapError.ERR.PIN_AUTH_INVALID)


class PendingAssertionTrashTests(PinTestCase):
    def test_a_passkey_trashed_during_the_chooser_is_not_signed(self):
        server = Fido2Server(PublicKeyCredentialRpEntity(id="example.com", name="example"))
        creds = []
        for name in ("alice", "bob"):
            options, state = server.register_begin(
                PublicKeyCredentialUserEntity(id=name.encode(), name=name, display_name=name),
                resident_key_requirement=ResidentKeyRequirement.REQUIRED,
            )
            result = Fido2Client(self.h.device, "https://example.com").make_credential(
                options["publicKey"]
            )
            creds.append(server.register_complete(state, result.client_data, result.attestation_object))

        self.assertEqual(
            self.ctap.get_assertion("example.com", b"\0" * 32).number_of_credentials, 2
        )
        self.h.store.remove(self.uid, self.username, [creds[0].credential_data.credential_id])
        with self.assertRaises(CtapError) as caught:
            self.ctap.get_next_assertion()
        self.assertEqual(caught.exception.code, CtapError.ERR.NO_CREDENTIALS)
