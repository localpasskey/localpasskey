import io
import json
import struct
import threading
import unittest
from unittest.mock import patch

from fido2.utils import websafe_encode

from localpasskey import bridge
from localpasskey.config import Config

ORIGIN = "https://example.com"
NOT_ALLOWED = "NotAllowedError"


def frame(message):
    data = message if isinstance(message, bytes) else json.dumps(message).encode()
    return struct.pack("=I", len(data)) + data


def override(origin=ORIGIN, same=True):
    return {"remoteDesktopClientOverride": {"origin": origin, "sameOriginWithAncestors": same}}


def create_details(challenge, user_id=b"alice-id", algs=(-7,), exclude=(), extensions=None, **selection):
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
        for origin in ("http://localhost:8765", "http://127.0.0.1:8765", "https://login.example.com:8443"):
            self.assertEqual(self.origin(override(origin)), origin)

    def test_refused(self):
        for extensions in (
            {},
            {"remoteDesktopClientOverride": {"origin": None, "sameOriginWithAncestors": True}},
            {"remoteDesktopClientOverride": {"origin": ORIGIN}},
            override(same=False),
            override("http://example.com"),
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
