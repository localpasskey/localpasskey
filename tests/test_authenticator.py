import hashlib
import os
import threading
import time
import unittest
from dataclasses import replace
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import rsa
from fido2.client import ClientError, Fido2Client
from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2
from fido2.hid import CTAPHID
from fido2.server import Fido2Server
from fido2.webauthn import (
    PublicKeyCredentialParameters,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialType,
    PublicKeyCredentialUserEntity,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from localpasskey import cbor, cose
from localpasskey.ctap2 import Verdict
from localpasskey.store import StoreError, StoreFull

from .helpers import Harness


def site(rp_id):
    return Fido2Server(PublicKeyCredentialRpEntity(id=rp_id, name=rp_id))


class FlowTestCase(unittest.TestCase):
    """Full registrations and sign-ins: python-fido2's Fido2Client plays the
    browser and Fido2Server plays the website that verifies the results."""

    def setUp(self):
        self.h = Harness()
        self.clients = {}

    def tearDown(self):
        self.h.close()

    def client(self, rp_id):
        if rp_id not in self.clients:
            self.clients[rp_id] = Fido2Client(self.h.device, f"https://{rp_id}")
        return self.clients[rp_id]

    def register(self, server, user_id, name, resident=ResidentKeyRequirement.REQUIRED, exclude=None):
        options, state = server.register_begin(
            PublicKeyCredentialUserEntity(id=user_id, name=name, display_name=name.title()),
            credentials=exclude,
            resident_key_requirement=resident,
            user_verification=UserVerificationRequirement.PREFERRED,
        )
        result = self.client(server.rp.id).make_credential(options["publicKey"])
        return server.register_complete(state, result.client_data, result.attestation_object)

    def sign_in(self, server, credentials, allow_list=True):
        options, state = server.authenticate_begin(
            credentials if allow_list else None, user_verification=UserVerificationRequirement.PREFERRED
        )
        selection = self.client(server.rp.id).get_assertion(options["publicKey"])
        responses = []
        for index, assertion in enumerate(selection.get_assertions()):
            response = selection.get_response(index)
            server.authenticate_complete(
                state, credentials, response.credential_id, response.client_data,
                response.authenticator_data, response.signature,
            )
            responses.append((response, assertion.user))
        return responses


class WebAuthnFlowTests(FlowTestCase):
    def test_register_and_sign_in_with_a_passkey(self):
        server = site("example.com")
        registration = self.register(server, b"alice-id", "alice")
        self.assertTrue(registration.is_user_present())
        self.assertTrue(registration.is_user_verified())
        self.assertEqual(bytes(registration.credential_data.aaguid), bytes(16))
        [stored] = self.h.credentials()
        self.assertTrue(stored.discoverable)
        self.assertEqual((stored.rp_id, stored.user_name), ("example.com", "alice"))
        self.assertEqual(
            self.h.verifier.messages[-1], "Test Browser wants to save a passkey for “alice” on example.com."
        )

        [(response, user)] = self.sign_in(server, [registration.credential_data], allow_list=False)
        self.assertEqual(response.user_handle, b"alice-id")
        self.assertEqual(user["name"], "alice")
        self.assertTrue(response.authenticator_data.is_user_verified())
        self.assertEqual(
            self.h.verifier.messages[-1],
            "Test Browser wants to sign in to example.com as “alice” with a passkey stored on this computer.",
        )

    def test_polkit_substitutions_in_site_text_are_escaped(self):
        self.register(site("example.com"), b"x-id", "a$(user)b")
        self.assertNotIn("$(", self.h.verifier.messages[-1])

    def test_several_accounts_and_sites(self):
        example, other = site("example.com"), site("other.example.org")
        alice = self.register(example, b"alice-id", "alice").credential_data
        bob = self.register(example, b"bob-id", "bob").credential_data
        carol = self.register(other, b"carol-id", "carol").credential_data
        self.assertEqual(len(self.h.credentials()), 3)
        prompts = len(self.h.verifier.messages)

        responses = self.sign_in(example, [alice, bob], allow_list=False)
        self.assertEqual([r.user_handle for r, _ in responses], [b"bob-id", b"alice-id"])
        self.assertEqual([u["displayName"] for _, u in responses], ["Bob", "Alice"])
        self.assertEqual(len(self.h.verifier.messages), prompts + 1, "one prompt for all accounts")
        self.assertIn("with one of your 2 passkeys", self.h.verifier.messages[-1])

        [(response, _)] = self.sign_in(other, [carol], allow_list=False)
        self.assertEqual(response.user_handle, b"carol-id")

    def test_passkeys_only_work_on_their_own_site(self):
        alice = self.register(site("example.com"), b"alice-id", "alice").credential_data
        self.h.authenticator.prompt_timeout = 0.3
        prompts = len(self.h.verifier.messages)
        with self.assertRaises(ClientError) as caught:
            self.sign_in(site("evil.example.net"), [alice])
        self.assertEqual(caught.exception.cause.code, CtapError.ERR.USER_ACTION_TIMEOUT)
        self.assertEqual(len(self.h.verifier.messages), prompts)
        self.assertIn("No passkey for evil.example.net", self.h.notifier.notes[-1][1])

    def test_registering_an_account_again_replaces_its_passkey(self):
        server = site("example.com")
        self.register(server, b"alice-id", "alice")
        second = self.register(server, b"alice-id", "alice")
        [stored] = self.h.credentials()
        self.assertEqual(stored.id, second.credential_data.credential_id)

    def test_exclude_list_blocks_a_duplicate_registration(self):
        server = site("example.com")
        alice = self.register(server, b"alice-id", "alice").credential_data
        with self.assertRaises(ClientError) as caught:
            self.register(server, b"alice-id", "alice", exclude=[alice])
        self.assertEqual(caught.exception.cause.code, CtapError.ERR.CREDENTIAL_EXCLUDED)
        self.assertIn("already stored on this computer", self.h.verifier.messages[-1])
        self.assertEqual(len(self.h.credentials()), 1)

    def test_server_side_credentials_need_an_allow_list(self):
        server = site("example.com")
        registration = self.register(server, b"dave-id", "dave", ResidentKeyRequirement.DISCOURAGED)
        [stored] = self.h.credentials()
        self.assertFalse(stored.discoverable)
        [(response, _)] = self.sign_in(server, [registration.credential_data])
        self.assertIsNone(response.user_handle)
        self.h.authenticator.prompt_timeout = 0.3
        with self.assertRaises(ClientError) as caught:
            self.sign_in(server, [registration.credential_data], allow_list=False)
        self.assertEqual(caught.exception.cause.code, CtapError.ERR.USER_ACTION_TIMEOUT)

    def test_every_supported_algorithm(self):
        for alg in cose.SUPPORTED_ALGORITHMS:
            with self.subTest(alg=cose.ALGORITHM_NAMES[alg]):
                server = site("example.com")
                server.allowed_algorithms = [PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, alg)]
                registration = self.register(server, f"user{alg}".encode(), f"user{alg}")
                self.assertEqual(registration.credential_data.public_key[3], alg)
                self.sign_in(server, [registration.credential_data])

    def test_nothing_is_saved_when_the_user_declines(self):
        self.h.verifier.verdict = Verdict.DENIED
        with self.assertRaises(ClientError) as caught:
            self.register(site("example.com"), b"alice-id", "alice")
        self.assertEqual(caught.exception.cause.code, CtapError.ERR.OPERATION_DENIED)
        self.assertEqual(self.h.credentials(), [])

    def test_user_is_told_when_no_dialog_can_be_shown(self):
        self.h.verifier.verdict = Verdict.UNAVAILABLE
        with self.assertRaises(ClientError):
            self.register(site("example.com"), b"alice-id", "alice")
        self.assertEqual(self.h.notifier.notes[0][0], "Passkey request blocked")


class NotificationTests(FlowTestCase):
    """What the user is told about passkey activity and failures."""

    def test_saving_and_using_a_passkey_are_reported(self):
        server = site("example.com")
        alice = self.register(server, b"alice-id", "alice").credential_data
        self.assertEqual(
            self.h.notifier.notes,
            [("Passkey saved", "Test Browser saved a passkey for “alice” on example.com.", "activity")],
        )
        self.sign_in(server, [alice])
        self.assertEqual(
            self.h.notifier.notes[-1],
            ("Signed in with a passkey", "Test Browser used a passkey to sign in to example.com as “alice”.", "activity"),
        )

    def test_account_chooser_sign_in_is_reported_once(self):
        server = site("example.com")
        alice = self.register(server, b"alice-id", "alice").credential_data
        bob = self.register(server, b"bob-id", "bob").credential_data
        notes = len(self.h.notifier.notes)
        self.sign_in(server, [alice, bob], allow_list=False)
        self.assertEqual(
            self.h.notifier.notes[notes:],
            [("Signed in with a passkey", "Test Browser used a passkey to sign in to example.com.", "activity")],
        )

    def test_declined_and_timed_out_requests_are_reported(self):
        for verdict, summary in (
            (Verdict.DENIED, "Passkey request declined"),
            (Verdict.TIMED_OUT, "Passkey request timed out"),
        ):
            with self.subTest(verdict=verdict):
                self.h.verifier.verdict = verdict
                with self.assertRaises(ClientError):
                    self.register(site("example.com"), b"alice-id", "alice")
                self.assertEqual(self.h.notifier.notes[-1][0], summary)
                self.assertEqual(self.h.notifier.notes[-1][2], "problem")
                self.assertIn("save a passkey on example.com", self.h.notifier.notes[-1][1])
                self.assertNotIn("Passkey saved", self.h.notifier.summaries())

    def test_problem_notifications_leave_out_site_supplied_account_names(self):
        self.h.verifier.verdict = Verdict.TIMED_OUT
        with self.assertRaises(ClientError):
            self.register(site("example.com"), b"x", "alice” on bank.example — call 555-0100")
        self.assertNotIn("555-0100", self.h.notifier.notes[-1][1])

    def test_repeated_problems_are_reported_once_but_every_use_is(self):
        server = site("example.com")
        alice = self.register(server, b"alice-id", "alice").credential_data
        self.sign_in(server, [alice])
        self.sign_in(server, [alice])
        self.assertEqual(self.h.notifier.summaries().count("Signed in with a passkey"), 2)
        self.h.verifier.verdict = Verdict.TIMED_OUT
        for _ in range(3):
            with self.assertRaises(ClientError):
                self.sign_in(server, [alice])
        self.assertEqual(self.h.notifier.summaries().count("Passkey request timed out"), 1)
        with patch("localpasskey.ctap2.time.monotonic", return_value=time.monotonic() + 61):
            with self.assertRaises(ClientError):
                self.sign_in(server, [alice])
        self.assertEqual(self.h.notifier.summaries().count("Passkey request timed out"), 2)

    def test_cancelled_requests_are_not_reported(self):
        self.h.verifier.verdict = Verdict.CANCELLED
        with self.assertRaises(ClientError):
            self.register(site("example.com"), b"alice-id", "alice")
        self.assertEqual(self.h.notifier.notes, [])

    def test_existing_passkey_is_reported_on_registration(self):
        server = site("example.com")
        alice = self.register(server, b"alice-id", "alice").credential_data
        with self.assertRaises(ClientError):
            self.register(server, b"alice-id", "alice", exclude=[alice])
        self.assertEqual(self.h.notifier.notes[-1][0], "Passkey already saved")

    def test_full_store_is_reported_as_an_error(self):
        with patch.object(self.h.store, "add", side_effect=StoreFull("full")), self.assertRaises(ClientError):
            self.register(site("example.com"), b"alice-id", "alice")
        self.assertEqual(self.h.notifier.notes[-1][0], "Passkey not saved")
        self.assertEqual(self.h.notifier.notes[-1][2], "error")

    def test_internal_errors_are_reported(self):
        server = site("example.com")
        alice = self.register(server, b"alice-id", "alice").credential_data
        for error in (StoreError("broken"), RuntimeError("bug")):
            with self.subTest(error=error):
                with patch.object(self.h.store, "unseal", side_effect=error), self.assertRaises(ClientError):
                    self.sign_in(server, [alice])
                self.assertEqual(self.h.notifier.notes[-1][0], "Passkey request failed")
                self.assertEqual(self.h.notifier.notes[-1][2], "error")
                self.assertNotEqual(self.h.notifier.notes[-2][0], "Signed in with a passkey")

    def test_notifier_failure_does_not_break_requests(self):
        self.h.notifier.notify = lambda *args: (_ for _ in ()).throw(OSError("no bus"))
        server = site("example.com")
        alice = self.register(server, b"alice-id", "alice").credential_data
        self.sign_in(server, [alice])


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.h = Harness()
        self.ctap = Ctap2(self.h.device)

    def tearDown(self):
        self.h.close()

    def make(self, user_id=b"u1", name="alice", rk=True, rp_id="example.com", **kwargs):
        return self.ctap.make_credential(
            os.urandom(32), {"id": rp_id, "name": rp_id}, {"id": user_id, "name": name},
            [{"type": "public-key", "alg": cose.ES256}], options={"rk": rk, "uv": True}, **kwargs,
        )

    @staticmethod
    def descriptor(attestation):
        return {"type": "public-key", "id": attestation.auth_data.credential_data.credential_id}

    def raw(self, command, params):
        return self.h.device.call(CTAPHID.CBOR, bytes([command]) + cbor.encode(params))[0]

    def test_get_info(self):
        info = self.ctap.info
        self.assertEqual(info.versions, ["FIDO_2_0"])
        self.assertEqual(bytes(info.aaguid), bytes(16))
        self.assertEqual(
            info.options, {"rk": True, "up": True, "uv": True, "plat": False, "credMgmt": True}
        )
        self.assertEqual(info.extensions, ["credProtect"])
        self.assertEqual(info.transports, ["usb"])
        self.assertEqual(info.max_creds_in_list, 8)
        self.assertEqual(info.pin_uv_protocols, [2, 1])
        # pinUvAuthToken would make platforms fetch a UV token before every
        # ordinary sign-in, moving the polkit prompt ahead of the lookup.
        self.assertNotIn("pinUvAuthToken", info.options)

    def test_a_declined_registration_ends_without_a_pin(self):
        # No PIN is set, so getInfo says nothing about PINs and the declining
        # answer stands on its own: Chrome must not fall back to asking for a
        # PIN it cannot set here.
        self.assertNotIn("clientPin", self.ctap.info.options)
        self.h.verifier.verdict = Verdict.DENIED
        with self.assertRaises(CtapError) as caught:
            self.make()
        self.assertEqual(caught.exception.code, CtapError.ERR.OPERATION_DENIED)

    def test_get_info_advertises_the_pin_only_once_one_is_set(self):
        self.assertNotIn("clientPin", self.ctap.info.options)
        self.h.pins.set(self.h.requester.uid, self.h.requester.username, b"1234")
        self.assertTrue(self.ctap.get_info().options["clientPin"])
        with patch.object(self.h.authenticator.resolver, "resolve", return_value=None):
            self.assertNotIn("clientPin", self.ctap.get_info().options)

    def test_signature_counter_never_links_accounts(self):
        # Listing accounts for the chooser signs for all of them; a counter
        # that moved would show the site which accounts share this key.
        alice = self.descriptor(self.make(user_id=b"alice", name="alice"))
        bob = self.descriptor(self.make(user_id=b"bob", name="bob"))
        for _ in range(3):
            assertions = self.ctap.get_assertions("example.com", os.urandom(32))
            self.assertEqual([a.auth_data.counter for a in assertions], [0, 0])
        for cred in (alice, bob):
            assertion = self.ctap.get_assertion("example.com", os.urandom(32), [cred])
            self.assertEqual(assertion.auth_data.counter, 0)

    def test_silent_assertions_skip_the_prompt_and_hide_names(self):
        cred = self.descriptor(self.make())
        prompts = len(self.h.verifier.messages)
        assertion = self.ctap.get_assertion("example.com", os.urandom(32), [cred], options={"up": False})
        self.assertEqual(assertion.auth_data.flags & 0x05, 0, "neither UP nor UV may be set")
        self.assertEqual(assertion.user, {"id": b"u1"})
        self.assertEqual(len(self.h.verifier.messages), prompts)
        self.assertNotIn("Signed in with a passkey", self.h.notifier.summaries())
        self.assertIsNone(self.h.credentials()[0].last_used, "a silent probe is not a use")

    def test_cred_protect_required_hides_credentials_from_silent_requests(self):
        attestation = self.make(extensions={"credProtect": 3})
        self.assertEqual(attestation.auth_data.extensions, {"credProtect": 3})
        cred = self.descriptor(attestation)
        with self.assertRaises(CtapError) as caught:
            self.ctap.get_assertion("example.com", os.urandom(32), [cred], options={"up": False})
        self.assertEqual(caught.exception.code, CtapError.ERR.NO_CREDENTIALS)
        self.ctap.get_assertion("example.com", os.urandom(32), [cred])

    def test_cred_protect_optional_with_list_hides_credentials_from_silent_discovery(self):
        cred = self.descriptor(self.make(extensions={"credProtect": 2}))
        with self.assertRaises(CtapError):
            self.ctap.get_assertion("example.com", os.urandom(32), options={"up": False})
        self.ctap.get_assertion("example.com", os.urandom(32), [cred], options={"up": False})
        self.ctap.get_assertion("example.com", os.urandom(32))

    def test_next_assertion_needs_a_preceding_get_assertion(self):
        with self.assertRaises(CtapError) as caught:
            self.ctap.get_next_assertion()
        self.assertEqual(caught.exception.code, CtapError.ERR.NOT_ALLOWED)
        self.make(user_id=b"a", name="a")
        self.make(user_id=b"b", name="b")
        self.assertEqual(self.ctap.get_assertion("example.com", os.urandom(32)).number_of_credentials, 2)
        self.ctap.get_info()
        with self.assertRaises(CtapError):
            self.ctap.get_next_assertion()

    def test_invalid_requests(self):
        cdh, rp, user = b"\0" * 32, {"id": "example.com"}, {"id": b"u"}
        es256 = [{"type": "public-key", "alg": -7}]
        cases = [
            ("missing clientDataHash", 0x01, {2: rp, 3: user, 4: es256}, CtapError.ERR.MISSING_PARAMETER),
            ("rp is not a map", 0x01, {1: cdh, 2: "example.com", 3: user, 4: es256}, CtapError.ERR.CBOR_UNEXPECTED_TYPE),
            ("unknown algorithm", 0x01, {1: cdh, 2: rp, 3: user, 4: [{"type": "public-key", "alg": -65535}]},
             CtapError.ERR.UNSUPPORTED_ALGORITHM),
            ("up=false registration", 0x01, {1: cdh, 2: rp, 3: user, 4: es256, 7: {"up": False}}, CtapError.ERR.INVALID_OPTION),
            ("PIN auth", 0x01, {1: cdh, 2: rp, 3: user, 4: es256, 8: b"\0" * 16, 9: 1}, CtapError.ERR.PIN_AUTH_INVALID),
            ("clientPin without a subCommand", 0x06, {1: 1}, CtapError.ERR.MISSING_PARAMETER),
            ("clientPin with an unknown subCommand", 0x06, {1: 1, 2: 0x08}, CtapError.ERR.INVALID_SUBCOMMAND),
            ("clientPin with an unknown protocol", 0x06, {1: 9, 2: 1}, CtapError.ERR.INVALID_PARAMETER),
            ("clientPin getKeyAgreement without a protocol", 0x06, {2: 2}, CtapError.ERR.MISSING_PARAMETER),
            ("credentialManagement without a subCommand", 0x0A, {3: 2, 4: b"x"}, CtapError.ERR.MISSING_PARAMETER),
            ("credentialManagement without pinUvAuthParam", 0x0A, {1: 1}, CtapError.ERR.PUAT_REQUIRED),
            ("rk in getAssertion", 0x02, {1: "example.com", 2: cdh, 5: {"rk": True}}, CtapError.ERR.UNSUPPORTED_OPTION),
            ("non-boolean option", 0x02, {1: "example.com", 2: cdh, 5: {"up": 1}}, CtapError.ERR.CBOR_UNEXPECTED_TYPE),
            ("non-boolean uv with default up", 0x02, {1: "example.com", 2: cdh, 5: {"uv": 1}},
             CtapError.ERR.CBOR_UNEXPECTED_TYPE),
            ("non-boolean uv with up=true", 0x02, {1: "example.com", 2: cdh, 5: {"up": True, "uv": 1}},
             CtapError.ERR.CBOR_UNEXPECTED_TYPE),
        ]
        cases.extend(
            (f"non-boolean registration {option}", 0x01,
             {1: cdh, 2: rp, 3: user, 4: es256, 7: {option: 1}}, CtapError.ERR.CBOR_UNEXPECTED_TYPE)
            for option in ("rk", "up", "uv")
        )
        for length in (0, 31, 33):
            cases.extend([
                (f"registration hash length {length}", 0x01,
                 {1: b"x" * length, 2: rp, 3: user, 4: es256}, CtapError.ERR.INVALID_PARAMETER),
                (f"assertion hash length {length}", 0x02,
                 {1: "example.com", 2: b"x" * length, 5: {"up": False}}, CtapError.ERR.INVALID_PARAMETER),
            ])
        cases.extend((f"rp id {bad!r}", 0x01, {1: cdh, 2: {"id": bad}, 3: user, 4: es256},
                      CtapError.ERR.INVALID_PARAMETER) for bad in ("", "a b", "a\tb", "a" * 254))
        for name, command, params, code in cases:
            with self.subTest(name):
                self.assertEqual(self.raw(command, params), code)
        self.assertEqual(self.h.device.call(CTAPHID.CBOR, b"\x01\xa1")[0], CtapError.ERR.INVALID_CBOR)
        self.assertEqual(self.h.device.call(CTAPHID.CBOR, b"\x40")[0], CtapError.ERR.INVALID_COMMAND)
        self.assertEqual(self.h.credentials(), [])

    def test_excluded_credentials_are_not_revealed_without_approval(self):
        descriptor = self.descriptor(self.make())
        for verdict, expected in (
            (Verdict.DENIED, CtapError.ERR.OPERATION_DENIED),
            (Verdict.UNAVAILABLE, CtapError.ERR.OPERATION_DENIED),
            (Verdict.TIMED_OUT, CtapError.ERR.USER_ACTION_TIMEOUT),
            (Verdict.CANCELLED, CtapError.ERR.KEEPALIVE_CANCEL),
        ):
            with self.subTest(verdict=verdict):
                self.h.verifier.verdict = verdict
                with self.assertRaises(CtapError) as caught:
                    self.make(exclude_list=[descriptor])
                self.assertEqual(caught.exception.code, expected)
        self.assertEqual(len(self.h.credentials()), 1)

    def test_next_assertion_cannot_change_requester(self):
        self.make(user_id=b"a")
        self.make(user_id=b"b")
        for requester in (None, replace(self.h.requester, uid=self.h.requester.uid + 1),
                          replace(self.h.requester, pid=self.h.requester.pid + 1)):
            with self.subTest(requester=requester):
                self.ctap.get_assertion("example.com", os.urandom(32))
                with patch.object(self.h.authenticator.resolver, "requester", requester):
                    with self.assertRaises(CtapError) as caught:
                        self.ctap.get_next_assertion()
                self.assertEqual(caught.exception.code, CtapError.ERR.NOT_ALLOWED)
                with self.assertRaises(CtapError):
                    self.ctap.get_next_assertion()

    def test_touch_approval_is_bound_to_its_requester(self):
        self.make()
        other = replace(self.h.requester, uid=self.h.requester.uid + 1, username="other")
        with patch.object(self.h.authenticator.resolver, "requester", other):
            self.make()
        for requester in (other, replace(self.h.requester, pid=self.h.requester.pid + 1)):
            with self.subTest(requester=requester):
                self.make(rp_id="make.me.blink")
                prompts = len(self.h.verifier.messages)
                with patch.object(self.h.authenticator.resolver, "requester", requester):
                    self.ctap.get_assertion("example.com", os.urandom(32))
                self.assertEqual(len(self.h.verifier.messages), prompts + 1)

    def test_missing_requester_is_denied_without_prompting(self):
        self.make()
        prompts = len(self.h.verifier.messages)
        with patch.object(self.h.authenticator.resolver, "requester", None):
            for request in (lambda: self.make(),
                            lambda: self.ctap.get_assertion("example.com", os.urandom(32))):
                with self.assertLogs("localpasskey.ctap2", level="WARNING"), self.assertRaises(CtapError) as caught:
                    request()
                self.assertEqual(caught.exception.code, CtapError.ERR.OPERATION_DENIED)
        self.assertEqual(len(self.h.verifier.messages), prompts)

    def test_full_store_preserves_existing_credential(self):
        self.make()
        with patch("localpasskey.store.MAX_CREDENTIALS_PER_USER", 1):
            with self.assertRaises(CtapError) as caught:
                self.make(user_id=b"other")
        self.assertEqual(caught.exception.code, CtapError.ERR.KEY_STORE_FULL)
        self.assertEqual(len(self.h.credentials()), 1)

    def test_store_failure_returns_protocol_error(self):
        with patch.object(self.h.store, "credentials", side_effect=StoreError("corrupt test store")):
            with self.assertLogs("localpasskey.ctap2", level="ERROR"), self.assertRaises(CtapError) as caught:
                self.make()
        self.assertEqual(caught.exception.code, CtapError.ERR.OTHER)
        self.assertEqual(self.h.verifier.messages, [])

    def test_credential_deleted_during_approval_is_not_signed(self):
        self.make()

        def delete_before_approving(*args):
            cred = self.h.credentials()[0]
            self.h.store.remove(self.h.requester.uid, self.h.requester.username, [cred.id])
            return Verdict.APPROVED

        with patch.object(self.h.verifier, "verify", side_effect=delete_before_approving):
            with self.assertRaises(CtapError) as caught:
                self.ctap.get_assertion("example.com", os.urandom(32))
        self.assertEqual(caught.exception.code, CtapError.ERR.NO_CREDENTIALS)

    def test_expired_next_assertion_is_discarded(self):
        self.make(user_id=b"a")
        self.make(user_id=b"b")
        self.ctap.get_assertion("example.com", os.urandom(32))
        state = self.h.connection.transport._channels[self.h.device._channel_id]
        state.pending_assertions.deadline = 0.0
        with self.assertRaises(CtapError) as caught:
            self.ctap.get_next_assertion()
        self.assertEqual(caught.exception.code, CtapError.ERR.NOT_ALLOWED)
        self.assertIsNone(state.pending_assertions)

    def test_declined_request_is_not_shown_again_when_retried(self):
        # Firefox reads OPERATION_DENIED from built-in UV as a misread
        # fingerprint and resends the same request straight away.
        self.make()
        self.h.verifier.verdict = Verdict.DENIED
        prompts = len(self.h.verifier.messages)
        client_data_hash = os.urandom(32)
        for expected in (CtapError.ERR.OPERATION_DENIED, CtapError.ERR.KEEPALIVE_CANCEL):
            with self.assertRaises(CtapError) as caught:
                self.ctap.get_assertion("example.com", client_data_hash, options={"uv": True})
            self.assertEqual(caught.exception.code, expected)
        self.assertEqual(len(self.h.verifier.messages), prompts + 1)
        with self.assertRaises(CtapError) as caught:
            self.ctap.get_assertion("example.com", os.urandom(32), options={"uv": True})
        self.assertEqual(caught.exception.code, CtapError.ERR.OPERATION_DENIED)
        self.assertEqual(len(self.h.verifier.messages), prompts + 2, "a new sign-in asks again")

    def test_reset_is_refused(self):
        self.make()
        with self.assertRaises(CtapError) as caught:
            self.ctap.reset()
        self.assertEqual(caught.exception.code, CtapError.ERR.NOT_ALLOWED)
        self.assertEqual(len(self.h.credentials()), 1)

    def test_unknown_credential_waits_like_an_untouched_key(self):
        # Answering NO_CREDENTIALS would make browsers end the request, even if
        # the credential is on another security key the user could touch.
        unknown = {"type": "public-key", "id": os.urandom(32)}
        cancel = threading.Event()
        threading.Timer(0.5, cancel.set).start()
        with self.assertRaises(CtapError) as caught:
            self.ctap.get_assertion("example.com", os.urandom(32), [unknown], event=cancel)
        self.assertEqual(caught.exception.code, CtapError.ERR.KEEPALIVE_CANCEL)
        self.assertEqual(self.h.verifier.messages, [])
        self.assertIn("No passkey for example.com", self.h.notifier.notes[0][1])
        with self.assertRaises(CtapError) as caught:
            self.ctap.get_assertion("example.com", os.urandom(32), [unknown], options={"up": False})
        self.assertEqual(caught.exception.code, CtapError.ERR.NO_CREDENTIALS)

    def test_touch_request_after_a_miss_waits_without_prompting(self):
        # Chrome: silent probes find nothing -> dummy registration to collect a touch.
        unknown = {"type": "public-key", "id": os.urandom(32)}
        with self.assertRaises(CtapError):
            self.ctap.get_assertion("example.com", os.urandom(32), [unknown], options={"up": False})
        cancel = threading.Event()
        threading.Timer(0.5, cancel.set).start()
        with self.assertRaises(CtapError) as caught:
            self.ctap.make_credential(
                hashlib.sha256(b"").digest(), {"id": ".dummy"}, {"id": b"\x01", "name": "dummy"},
                [{"type": "public-key", "alg": -7}], event=cancel,
            )
        self.assertEqual(caught.exception.code, CtapError.ERR.KEEPALIVE_CANCEL)
        self.assertEqual(self.h.verifier.messages, [])
        self.assertIn("No passkey for example.com", self.h.notifier.notes[0][1])

    def test_touch_request_to_pick_this_authenticator(self):
        # Firefox with several security keys plugged in asks the user to pick one.
        self.make()
        prompts = len(self.h.verifier.messages)
        self.ctap.make_credential(
            b"\0" * 32, {"id": "make.me.blink"}, {"id": b"\0", "name": "make.me.blink"},
            [{"type": "public-key", "alg": -7}],
        )
        self.assertEqual(self.h.verifier.messages[-1], "Test Browser wants to use a passkey stored on this computer.")
        self.ctap.get_assertion("example.com", os.urandom(32))
        self.assertEqual(len(self.h.verifier.messages), prompts + 1, "the pick counts as approval once")
        self.ctap.get_assertion("example.com", os.urandom(32))
        self.assertEqual(len(self.h.verifier.messages), prompts + 2)
        self.assertEqual(len(self.h.credentials()), 1, "touch requests are not stored")

    def test_registration_uses_up_a_touch_approval(self):
        self.make(rp_id="make.me.blink")
        prompts = len(self.h.verifier.messages)
        self.make(rp_id="other.example")
        self.assertEqual(len(self.h.verifier.messages), prompts + 1)
        self.assertIn("wants to save a passkey for", self.h.verifier.messages[-1])
        prompts = len(self.h.verifier.messages)
        self.ctap.get_assertion("other.example", os.urandom(32))
        self.assertEqual(len(self.h.verifier.messages), prompts + 1, "the sign-in asks for itself")

    def test_pin_probe_approval_covers_only_its_own_sign_in(self):
        self.make()
        self.make(rp_id="other.example")
        self.h.pins.set(self.h.requester.uid, self.h.requester.username, b"1234")
        for rp_id, client_data_hash, asks in (("example.com", None, 0), ("other.example", os.urandom(32), 1)):
            with self.subTest(rp_id=rp_id):
                probed = os.urandom(32)
                probe = {1: "example.com", 2: probed, 6: b"", 7: 2}
                self.assertEqual(self.raw(0x02, probe), CtapError.ERR.PIN_INVALID)
                prompts = len(self.h.verifier.messages)
                self.ctap.get_assertion(rp_id, client_data_hash or probed)
                self.assertEqual(len(self.h.verifier.messages), prompts + asks)

    def test_touch_approval_expires(self):
        self.make()
        # Patch the constant, not time.monotonic: a frozen clock would also stall the harness.
        with patch("localpasskey.ctap2.PREVERIFIED_WINDOW", -1.0):
            self.make(rp_id="make.me.blink")
        prompts = len(self.h.verifier.messages)
        self.ctap.get_assertion("example.com", os.urandom(32))
        self.assertEqual(len(self.h.verifier.messages), prompts + 1, "an expired touch approval asks again")

    def test_next_silent_assertion_skips_a_passkey_deleted_meanwhile(self):
        self.make(user_id=b"a")
        self.make(user_id=b"b")
        first = self.ctap.get_assertion("example.com", os.urandom(32), options={"up": False})
        [other] = [c for c in self.h.credentials() if c.id != first.credential["id"]]
        self.h.store.remove(self.h.requester.uid, self.h.requester.username, [other.id])
        with self.assertRaises(CtapError) as caught:
            self.ctap.get_next_assertion()
        self.assertEqual(caught.exception.code, CtapError.ERR.NO_CREDENTIALS)

    def test_failed_assertion_uses_up_a_touch_approval(self):
        self.make()
        self.h.authenticator.prompt_timeout = 0.3
        self.make(rp_id="make.me.blink")
        prompts = len(self.h.verifier.messages)
        with self.assertRaises(CtapError) as caught:
            self.ctap.get_assertion("nothing.example", os.urandom(32))
        self.assertEqual(caught.exception.code, CtapError.ERR.USER_ACTION_TIMEOUT)
        self.assertEqual(len(self.h.verifier.messages), prompts, "the miss waits for a touch")
        self.ctap.get_assertion("example.com", os.urandom(32))
        self.assertEqual(len(self.h.verifier.messages), prompts + 1, "the sign-in asks again")


class KeyLoadingTests(unittest.TestCase):
    def test_oversized_keys_are_refused_before_openssl_checks_them(self):
        big = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        self.assertEqual(cose.private_key_from_bytes(cose.private_key_to_bytes(big)).key_size, 4096)
        with patch("localpasskey.cose.serialization.load_der_private_key") as load:
            with self.assertRaisesRegex(ValueError, "too large"):
                cose.private_key_from_bytes(bytes(cose.MAX_KEY_DER + 1))
        load.assert_not_called()


if __name__ == "__main__":
    unittest.main()
