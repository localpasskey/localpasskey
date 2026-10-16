import io
import json
import os
import struct
import subprocess
import sys
import threading
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from fido2.server import Fido2Server
from fido2.utils import sha256, websafe_decode, websafe_encode
from fido2.webauthn import (
    AttestationObject,
    AuthenticatorData,
    CollectedClientData,
    PublicKeyCredentialParameters,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialType,
    PublicKeyCredentialUserEntity,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from localpasskey import bridge, cose
from localpasskey.config import Config
from localpasskey.ctap2 import Verdict

from .helpers import Harness

ORIGIN = "https://example.com"
NOT_ALLOWED = "NotAllowedError"


def frame(message):
    data = message if isinstance(message, bytes) else json.dumps(message).encode()
    return struct.pack("=I", len(data)) + data


def override(origin=ORIGIN, same=True):
    return {"remoteDesktopClientOverride": {"origin": origin, "sameOriginWithAncestors": same}}


def create_details(challenge, user_id=b"alice-id", algs=(cose.ES256,), exclude=(), extensions=None, **selection):
    """A request shaped like Chromium's requestDetailsJson for create()."""
    return {
        "rp": {"id": "example.com", "name": "Example"},
        "user": {"id": websafe_encode(user_id), "name": "alice", "displayName": "Alice"},
        "challenge": websafe_encode(challenge),
        "pubKeyCredParams": [{"type": "public-key", "alg": alg} for alg in algs],
        "excludeCredentials": [
            {"type": "public-key", "id": websafe_encode(i), "transports": ["usb", "internal"]} for i in exclude
        ],
        "authenticatorSelection": {
            "authenticatorAttachment": "platform",
            "residentKey": "required",
            "userVerification": "preferred",
            **selection,
        },
        "attestation": "none",
        "timeout": 60000,
        "extensions": {**override(), **(extensions or {})},
    }


def get_details(challenge, allow=(), rp_id="example.com", extensions=None):
    return {
        "challenge": websafe_encode(challenge),
        "rpId": rp_id,
        "allowCredentials": [{"type": "public-key", "id": websafe_encode(i)} for i in allow],
        "userVerification": "preferred",
        "timeout": 60000,
        "extensions": {**override(), **(extensions or {})},
    }


class FramingTests(unittest.TestCase):
    def test_round_trip(self):
        out = io.BytesIO()
        bridge.write_message(out, {"type": "status"})
        self.assertEqual(out.getvalue(), frame({"type": "status"}))
        self.assertEqual(bridge.read_message(io.BytesIO(out.getvalue())), {"type": "status"})

    def test_end_of_input_is_no_message(self):
        self.assertIsNone(bridge.read_message(io.BytesIO(b"")))

    def test_rejects_bad_frames(self):
        for data in (
            b"\x05\x00",  # truncated length
            frame(b"{}")[:-1],  # truncated body
            struct.pack("=I", bridge.MAX_MESSAGE + 1) + b"{}",
            frame(b"\xff\xfe"),
            frame(b"not json"),
            frame([1, 2]),
        ):
            with self.subTest(data=data[:12]), self.assertRaises(bridge.ProtocolError):
                bridge.read_message(io.BytesIO(data))

    def test_accepts_a_message_of_exactly_the_limit(self):
        body = json.dumps({"type": "status", "pad": ""}).encode()
        body = body[:-2] + b" " * (bridge.MAX_MESSAGE - len(body)) + body[-2:]
        self.assertEqual(bridge.read_message(io.BytesIO(frame(body)))["type"], "status")

    def test_serve_answers_once(self):
        out = io.BytesIO()
        status = bridge.serve(io.BytesIO(frame({"type": "status"})), out, find_device=lambda: object())
        self.assertEqual(status, 0)
        self.assertEqual(bridge.read_message(io.BytesIO(out.getvalue())), {"available": True})

    def test_process_exits_cleanly_while_the_browser_keeps_stdin_open(self):
        # A reader blocked in the buffered stdin used to abort interpreter shutdown.
        script = "import sys; from localpasskey import bridge; sys.exit(bridge.serve(sys.stdin.buffer, sys.stdout.buffer))"
        read_fd, write_fd = os.pipe()
        os.write(write_fd, frame({"type": "unknown"}))
        try:
            result = subprocess.run([sys.executable, "-c", script], stdin=read_fd, capture_output=True, timeout=30,
                                    cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        finally:
            os.close(read_fd)
            os.close(write_fd)
        self.assertEqual((result.returncode, result.stderr), (0, b""))
        self.assertEqual(bridge.read_message(io.BytesIO(result.stdout))["error"]["name"], NOT_ALLOWED)

    def test_serve_without_input_or_with_garbage_writes_nothing(self):
        for data, code in ((b"", 0), (struct.pack("=I", 1 << 30), 1)):
            out = io.BytesIO()
            self.assertEqual(bridge.serve(io.BytesIO(data), out), code)
            self.assertEqual(out.getvalue(), b"")


class OriginTests(unittest.TestCase):
    def origin(self, extensions):
        return bridge.request_origin({"extensions": extensions})

    def test_takes_the_origin_chromium_verified_and_removes_it(self):
        details = {"extensions": {**override(), "credProps": True}}
        self.assertEqual(bridge.request_origin(details), ORIGIN)
        self.assertEqual(details["extensions"], {"credProps": True})

    def test_local_http_origins_for_testing(self):
        for origin in ("http://localhost:8765", "https://login.example.com:8443"):
            self.assertEqual(self.origin(override(origin)), origin)

    def test_refused(self):
        for extensions in (
            {},
            {"remoteDesktopClientOverride": {"origin": None, "sameOriginWithAncestors": True}},
            {"remoteDesktopClientOverride": {"origin": ORIGIN}},
            override(same=False),
            override("http://example.com"),
            override("http://127.0.0.1:8765"),
            override("http://localhost.example.com"),
            override("chrome-extension://abc"),
            override("https://example.com/path"),
            override("https://user@example.com"),
            override("https://"),
            [],
        ):
            with self.subTest(extensions=extensions), self.assertRaises(bridge.Refused):
                self.origin(extensions)

    def test_refused_request_is_not_allowed(self):
        details = create_details(b"c" * 32)
        details["extensions"] = override(same=False)
        reply = bridge.handle({"type": "create", "requestDetailsJson": json.dumps(details)}, threading.Event(),
                              open_device=self.fail)
        self.assertEqual(reply["error"]["name"], NOT_ALLOWED)


class ConversionTests(unittest.TestCase):
    def test_creation_options(self):
        details = create_details(
            b"c" * 32, exclude=[b"old"],
            extensions={"credProps": True, "appIdExclude": "https://x", "prf": {}, "credentialProtectionPolicy": "userVerificationRequired"},
        )
        bridge.request_origin(details)
        options = bridge.creation_options(details)
        self.assertEqual(options.challenge, b"c" * 32)
        self.assertEqual(options.user.id, b"alice-id")
        self.assertEqual(options.user.display_name, "Alice")
        self.assertIsNone(options.authenticator_selection.authenticator_attachment)
        self.assertEqual(options.authenticator_selection.resident_key, ResidentKeyRequirement.REQUIRED)
        self.assertEqual(options.authenticator_selection.user_verification, UserVerificationRequirement.PREFERRED)
        self.assertEqual(options.exclude_credentials[0].id, b"old")
        self.assertIsNone(options.exclude_credentials[0].transports)
        self.assertEqual(dict(options.extensions), {"credProps": True, "credentialProtectionPolicy": "userVerificationRequired"})
        self.assertEqual(options.timeout, 60000)

    def test_request_options(self):
        details = get_details(b"c" * 32, allow=[b"one"], extensions={"appid": "https://x", "prf": {}})
        bridge.request_origin(details)
        options = bridge.request_options(details)
        self.assertEqual((options.rp_id, options.challenge), ("example.com", b"c" * 32))
        self.assertEqual(options.allow_credentials[0].id, b"one")
        self.assertIsNone(options.extensions)

    def test_malformed_requests_are_not_allowed(self):
        for details in ("[]", "{", json.dumps({"extensions": override()}),
                        json.dumps({**get_details(b"c"), "challenge": 5})):
            reply = bridge.handle({"type": "get", "requestDetailsJson": details}, threading.Event(), open_device=self.fail)
            self.assertEqual(reply["error"]["name"], NOT_ALLOWED)
        for message in ({"type": "sign"}, {}, {"type": "create"}):
            self.assertEqual(bridge.handle(message, threading.Event(), open_device=self.fail)["error"]["name"], NOT_ALLOWED)


class BridgeFlowTests(unittest.TestCase):
    """The bridge in front of the in-process authenticator; Fido2Server plays the site."""

    def setUp(self):
        self.h = Harness()
        self.server = Fido2Server(PublicKeyCredentialRpEntity(id="example.com", name="Example"))
        self.server.allowed_algorithms = [
            PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, alg) for alg in cose.SUPPORTED_ALGORITHMS
        ]

    def tearDown(self):
        self.h.close()

    def run_bridge(self, kind, details, cancel=None):
        reply = bridge.handle(
            {"type": kind, "requestDetailsJson": json.dumps(details)},
            cancel or threading.Event(),
            open_device=lambda: self.h.device,
        )
        return json.loads(reply["responseJson"]) if "responseJson" in reply else reply

    def register(self, alg=cose.ES256, **kwargs):
        options, state = self.server.register_begin(
            PublicKeyCredentialUserEntity(id=b"alice-id", name="alice"),
            user_verification=UserVerificationRequirement.PREFERRED,
        )
        response = self.run_bridge("create", create_details(options["publicKey"]["challenge"], algs=(alg,), **kwargs))
        return state, response

    def test_create_and_get_for_every_algorithm(self):
        for alg in cose.SUPPORTED_ALGORITHMS:
            with self.subTest(alg=alg):
                state, created = self.register(alg, extensions={"credProps": True})
                self.assertEqual(created["type"], "public-key")
                self.assertEqual(created["authenticatorAttachment"], "platform")
                self.assertEqual(created["id"], created["rawId"])
                response = created["response"]
                self.assertEqual(response["transports"], ["internal", "usb"])
                self.assertEqual(response["publicKeyAlgorithm"], alg)
                self.assertEqual(created["clientExtensionResults"], {"credProps": {"rk": True}})
                client_data = CollectedClientData(websafe_decode(response["clientDataJSON"]))
                self.assertEqual((client_data.origin, client_data.cross_origin), (ORIGIN, False))
                attestation = AttestationObject(websafe_decode(response["attestationObject"]))
                self.assertEqual(websafe_decode(response["authenticatorData"]), bytes(attestation.auth_data))
                auth = self.server.register_complete(state, client_data, attestation)
                self.assertTrue(auth.is_user_present() and auth.is_user_verified())
                credential = auth.credential_data
                self.assertEqual(websafe_decode(created["rawId"]), credential.credential_id)
                spki = serialization.load_der_public_key(websafe_decode(response["publicKey"]))
                self.assertEqual(type(credential.public_key).from_cryptography_key(spki), credential.public_key)

                for allow in ([credential.credential_id], []):
                    options, state = self.server.authenticate_begin([credential])
                    got = self.run_bridge("get", get_details(options["publicKey"]["challenge"], allow=allow))
                    self.assertEqual(got["authenticatorAttachment"], "platform")
                    self.assertEqual(got["clientExtensionResults"], {})
                    response = got["response"]
                    self.assertEqual(websafe_decode(response["userHandle"]), b"alice-id")
                    self.server.authenticate_complete(
                        state, [credential], websafe_decode(got["rawId"]),
                        CollectedClientData(websafe_decode(response["clientDataJSON"])),
                        AuthenticatorData(websafe_decode(response["authenticatorData"])),
                        websafe_decode(response["signature"]),
                    )

    def test_no_cred_props_unless_asked_and_no_user_handle_for_non_discoverable(self):
        state, created = self.register(residentKey="discouraged")
        self.assertEqual(created["clientExtensionResults"], {})
        credential = self.server.register_complete(
            state,
            CollectedClientData(websafe_decode(created["response"]["clientDataJSON"])),
            AttestationObject(websafe_decode(created["response"]["attestationObject"])),
        ).credential_data
        options, _ = self.server.authenticate_begin([credential])
        got = self.run_bridge("get", get_details(options["publicKey"]["challenge"], allow=[credential.credential_id]))
        self.assertNotIn("userHandle", got["response"])

    def test_cred_protect_reaches_the_key(self):
        created = self.run_bridge("create", create_details(
            b"c" * 32, extensions={"credentialProtectionPolicy": "userVerificationRequired"}))
        auth = AuthenticatorData(websafe_decode(created["response"]["authenticatorData"]))
        self.assertEqual(auth.extensions, {"credProtect": 3})

    def test_excluded_credential_is_invalid_state(self):
        _, created = self.register()
        reply = self.run_bridge("create", create_details(b"c" * 32, exclude=[websafe_decode(created["rawId"])]))
        self.assertEqual(reply["error"]["name"], "InvalidStateError")

    def test_unsupported_algorithm_is_not_supported(self):
        reply = self.run_bridge("create", create_details(b"c" * 32, algs=(-35,)))
        self.assertEqual(reply["error"]["name"], "NotSupportedError")

    def test_related_origin_chromium_accepted_is_served(self):
        details = create_details(b"c" * 32)
        details["extensions"] = override("https://www.example.co.uk")
        created = self.run_bridge("create", details)
        client_data = CollectedClientData(websafe_decode(created["response"]["clientDataJSON"]))
        self.assertEqual(client_data.origin, "https://www.example.co.uk")
        auth_data = AuthenticatorData(websafe_decode(created["response"]["authenticatorData"]))
        self.assertEqual(auth_data.rp_id_hash, sha256(b"example.com"))

    def test_failures_are_not_allowed_without_request_data(self):
        details = get_details(b"secret-challenge-bytes", allow=[b"nope"])
        reply = self.run_bridge("get", details)
        self.assertEqual(reply, {"error": {"name": NOT_ALLOWED, "message": bridge.NOT_ALLOWED[1]}})
        self.assertNotIn(details["challenge"], json.dumps(reply))

        self.h.verifier.verdict = Verdict.DENIED
        self.assertEqual(self.run_bridge("create", create_details(b"c" * 32))["error"]["name"], NOT_ALLOWED)

        def missing():
            raise bridge.Refused("LocalPasskey device not found")

        reply = bridge.handle({"type": "get", "requestDetailsJson": json.dumps(get_details(b"c"))},
                              threading.Event(), open_device=missing)
        self.assertEqual(reply["error"]["name"], NOT_ALLOWED)

    def test_closing_stdin_cancels_the_ceremony(self):
        self.h.verifier.delay = 30
        read_fd, write_fd = os.pipe()
        stdin, out = os.fdopen(read_fd, "rb"), io.BytesIO()
        os.write(write_fd, frame({"type": "create", "requestDetailsJson": json.dumps(create_details(b"c" * 32))}))
        done = threading.Thread(target=bridge.serve, args=(stdin, out),
                                kwargs={"open_device": lambda: self.h.device})
        done.start()
        self.assertTrue(self.h.verifier.messages or self._wait(lambda: self.h.verifier.messages))
        os.close(write_fd)
        done.join(10)
        stdin.close()
        self.assertFalse(done.is_alive())
        self.assertTrue(self.h.verifier.saw_cancel.is_set())
        reply = bridge.read_message(io.BytesIO(out.getvalue()))
        self.assertEqual(reply["error"]["name"], NOT_ALLOWED)
        self.assertEqual(self.h.credentials(), [])

    @staticmethod
    def _wait(condition, timeout=5.0):
        event = threading.Event()
        for _ in range(int(timeout / 0.02)):
            if condition():
                return True
            event.wait(0.02)
        return False


@patch.object(bridge, "load_config", Config)
class DeviceTests(unittest.TestCase):
    def descriptor(self, vid=0x1209, pid=0x4C50, name="LocalPasskey Virtual FIDO2 Authenticator"):
        from fido2.hid.base import HidDescriptor

        return HidDescriptor("/dev/hidrawX", vid, pid, 64, 64, name, None)

    def test_only_the_localpasskey_key_is_used(self):
        ours = self.descriptor()
        others = [self.descriptor(name="YubiKey"), self.descriptor(pid=0x0001)]
        with patch.object(bridge, "list_descriptors", return_value=others + [ours]):
            self.assertIs(bridge.find_device(), ours)
        with patch.object(bridge, "list_descriptors", return_value=others):
            self.assertIsNone(bridge.find_device())
            self.assertEqual(bridge.handle({"type": "status"}, threading.Event()), {"available": False})
            reply = bridge.handle(
                {"type": "get", "requestDetailsJson": json.dumps(get_details(b"c"))}, threading.Event()
            )
            self.assertEqual(reply["error"]["name"], NOT_ALLOWED)

    def test_status_survives_errors(self):
        with patch.object(bridge, "list_descriptors", side_effect=OSError):
            self.assertEqual(bridge.handle({"type": "status"}, threading.Event()), {"available": False})


if __name__ == "__main__":
    unittest.main()
