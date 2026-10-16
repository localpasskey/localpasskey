import os
import struct
import threading
import time
import unittest
from unittest.mock import patch

from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2
from fido2.hid import CTAPHID, STATUS

from localpasskey import ctaphid
from localpasskey.ctap2 import Verdict

from .helpers import Harness


def init_packet(cid, cmd, payload, length=None):
    length = len(payload) if length is None else length
    return (struct.pack(">IBH", cid, 0x80 | cmd, length) + payload).ljust(64, b"\0")


class RawTransportTests(unittest.TestCase):
    """Packet-level behaviour that python-fido2 doesn't exercise on its own."""

    def setUp(self):
        self.h = Harness()
        self.transport = self.h.connection.transport
        self.reports = self.h.connection.reports
        self.cid = self.h.device._channel_id
        while not self.reports.empty():
            self.reports.get()

    def tearDown(self):
        self.h.close()

    def read(self, timeout=2):
        return self.reports.get(timeout=timeout)

    def test_init_allocates_distinct_channels(self):
        nonce = os.urandom(8)
        self.transport.handle_report(init_packet(ctaphid.BROADCAST_CID, ctaphid.CMD_INIT, nonce))
        reply = self.read()
        self.assertEqual(reply[:7], struct.pack(">IBH", ctaphid.BROADCAST_CID, 0x86, 17))
        self.assertEqual(reply[7:15], nonce)
        new_cid, version, *_, capabilities = struct.unpack_from(">IBBBBB", reply, 15)
        self.assertNotIn(new_cid, (0, ctaphid.BROADCAST_CID, self.cid))
        self.assertEqual(version, 2)
        self.assertEqual(capabilities, ctaphid.CAPABILITY_CBOR | ctaphid.CAPABILITY_NMSG)

    def test_channel_allocation_preserves_an_incomplete_request(self):
        request = b"\x04" + b"\0" * ctaphid.INIT_PAYLOAD
        self.transport.handle_report(init_packet(
            self.cid, ctaphid.CMD_CBOR, request[:ctaphid.INIT_PAYLOAD], length=len(request)
        ))
        for _ in range(ctaphid.MAX_CHANNELS):
            self.transport.handle_report(init_packet(ctaphid.BROADCAST_CID, ctaphid.CMD_INIT, os.urandom(8)))
            self.read()
        self.assertEqual(len(self.transport._channels), ctaphid.MAX_CHANNELS)
        self.assertIn(self.cid, self.transport._channels)
        self.transport.handle_report((struct.pack(">IB", self.cid, 0) + request[ctaphid.INIT_PAYLOAD:]).ljust(64, b"\0"))
        self.assertEqual(self.read()[4], 0x80 | ctaphid.CMD_CBOR)

    def test_unknown_channel_is_rejected(self):
        self.transport.handle_report(init_packet(0x12345678, ctaphid.CMD_PING, b"hi"))
        self.assertEqual(self.read()[4:8], bytes([0xBF, 0, 1, ctaphid.ERR_INVALID_CHANNEL]))

    def test_init_cannot_allocate_a_host_chosen_channel(self):
        cid = next(c for c in range(1, 100) if c not in self.transport._channels)
        self.transport.handle_report(init_packet(cid, ctaphid.CMD_INIT, os.urandom(8)))
        self.assertEqual(self.read()[4:8], bytes([0xBF, 0, 1, ctaphid.ERR_INVALID_CHANNEL]))
        self.assertNotIn(cid, self.transport._channels)

    def test_wrong_sequence_number(self):
        self.transport.handle_report(init_packet(self.cid, ctaphid.CMD_PING, b"x" * 57, length=100))
        self.transport.handle_report(struct.pack(">IB", self.cid, 1).ljust(64, b"\0"))
        self.assertEqual(self.read()[4:8], bytes([0xBF, 0, 1, ctaphid.ERR_INVALID_SEQ]))

    def test_continuation_from_another_channel_is_ignored(self):
        other = self.h.open_device()._channel_id
        while not self.reports.empty():
            self.reports.get()
        payload = os.urandom(100)
        self.transport.handle_report(init_packet(self.cid, ctaphid.CMD_PING, payload[:57], length=100))
        self.transport.handle_report(struct.pack(">IB", other, 0).ljust(64, b"X"))
        self.transport.handle_report((struct.pack(">IB", self.cid, 0) + payload[57:]).ljust(64, b"\0"))
        reply = self.read() + self.read()
        self.assertEqual(reply[:7], struct.pack(">IBH", self.cid, 0x80 | ctaphid.CMD_PING, 100))
        self.assertEqual(reply[7:64] + reply[69:112], payload)

    def test_incomplete_message_times_out(self):
        self.transport.handle_report(init_packet(self.cid, ctaphid.CMD_PING, b"x" * 57, length=100))
        reply = self.read(timeout=ctaphid.MESSAGE_TIMEOUT + 2)
        self.assertEqual(reply[4:8], bytes([0xBF, 0, 1, ctaphid.ERR_MSG_TIMEOUT]))

    def test_u2f_messages_are_not_supported(self):
        self.transport.handle_report(init_packet(self.cid, ctaphid.CMD_MSG, b"\x00\x03\x00\x00"))
        self.assertEqual(self.read()[4:8], bytes([0xBF, 0, 1, ctaphid.ERR_INVALID_CMD]))

    def test_invalid_lengths_are_rejected(self):
        for command, payload, length in (
            (ctaphid.CMD_INIT, b"x" * 7, 7),
            (ctaphid.CMD_CBOR, b"", 0),
            (ctaphid.CMD_PING, b"x" * 57, ctaphid.MAX_MESSAGE + 1),
        ):
            with self.subTest(command=command, length=length):
                self.transport.handle_report(init_packet(self.cid, command, payload, length=length))
                self.assertEqual(self.read()[4:8], bytes([0xBF, 0, 1, ctaphid.ERR_INVALID_LEN]))

    def test_init_resynchronizes_an_incomplete_request(self):
        self.transport.handle_report(init_packet(self.cid, ctaphid.CMD_PING, b"x" * 57, length=100))
        self.assertIsNotNone(self.transport.poll_timeout())
        self.transport.handle_report(init_packet(self.cid, ctaphid.CMD_INIT, os.urandom(8)))
        self.assertEqual(self.read()[4], 0x80 | ctaphid.CMD_INIT)
        self.assertIsNone(self.transport.poll_timeout())
        self.transport.handle_report(struct.pack(">IB", self.cid, 0).ljust(64, b"\0"))
        self.assertTrue(self.reports.empty(), "a stale continuation is ignored")
        self.assertEqual(self.h.device.call(CTAPHID.PING, b"new request"), b"new request")

    def test_handler_failure_returns_error_and_releases_channel(self):
        with patch.object(self.h.authenticator, "process", side_effect=RuntimeError("test failure")):
            with self.assertLogs("localpasskey.ctaphid", level="ERROR"):
                self.assertEqual(self.h.device.call(CTAPHID.CBOR, b"\x04"), b"\x7f")
        self.assertEqual(self.h.device.call(CTAPHID.PING, b"still alive"), b"still alive")

    def test_send_stops_after_a_report_error(self):
        with patch.object(self.transport, "_send_report", side_effect=[None, OSError("device closed")]) as send:
            self.transport._send(self.cid, ctaphid.CMD_PING, b"x" * 200)
        self.assertEqual(send.call_count, 2)
        self.assertTrue(all(len(call.args[0]) == ctaphid.REPORT_SIZE for call in send.call_args_list))

    def test_other_channels_get_busy_while_a_request_waits_for_the_user(self):
        self.h.verifier.delay = 1.0
        other = self.h.open_device()
        while not self.reports.empty():
            self.reports.get()
        request = bytes([0x02]) + bytes.fromhex("a2016b6578616d706c652e636f6d025820") + b"\0" * 32
        self.h.store.add(self.h.requester.uid, self.h.requester.username, _resident_credential(self.h))
        self.transport.handle_report(init_packet(self.cid, ctaphid.CMD_CBOR, request))
        time.sleep(0.05)
        self.transport.handle_report(init_packet(other._channel_id, ctaphid.CMD_PING, b"hi"))
        replies = [self.read() for _ in range(3)]
        busy = [r for r in replies if r[:4] == struct.pack(">I", other._channel_id)]
        self.assertEqual(busy[0][4:8], bytes([0xBF, 0, 1, ctaphid.ERR_CHANNEL_BUSY]))
        keepalives = [r for r in replies if r[:5] == struct.pack(">IB", self.cid, 0xBB)]
        self.assertTrue(keepalives)
        self.assertEqual(keepalives[0][7], STATUS.UPNEEDED)


def _resident_credential(h):
    from localpasskey import cose
    from localpasskey.store import Credential

    key = cose.generate_private_key(cose.ES256)
    cred_id = os.urandom(32)
    return Credential(
        id=cred_id, rp_id="example.com", user_id=b"u", alg=cose.ES256,
        sealed_key=h.store.seal(h.requester.uid, cred_id, cose.private_key_to_bytes(key)),
        user_name="alice", created=time.time(),
    )


class HostTests(unittest.TestCase):
    """The transport as seen through python-fido2's CTAPHID implementation."""

    def setUp(self):
        self.h = Harness()

    def tearDown(self):
        self.h.close()

    def test_ping_round_trips_multi_packet_payloads(self):
        payload = os.urandom(ctaphid.MAX_MESSAGE)
        self.assertEqual(self.h.device.call(CTAPHID.PING, payload), payload)

    def test_keepalive_reports_that_user_presence_is_needed(self):
        self.h.verifier.delay = 0.5
        self.h.verifier.verdict = Verdict.APPROVED
        self.h.store.add(self.h.requester.uid, self.h.requester.username, _resident_credential(self.h))
        statuses = []
        Ctap2(self.h.device).get_assertion("example.com", b"\0" * 32, on_keepalive=statuses.append)
        self.assertIn(STATUS.UPNEEDED, statuses)

    def test_cancel_aborts_a_pending_prompt(self):
        self.h.verifier.delay = 10
        self.h.store.add(self.h.requester.uid, self.h.requester.username, _resident_credential(self.h))
        event = threading.Event()
        threading.Timer(0.3, event.set).start()
        started = time.monotonic()
        with self.assertRaises(CtapError) as caught:
            Ctap2(self.h.device).get_assertion("example.com", b"\0" * 32, event=event)
        self.assertEqual(caught.exception.code, CtapError.ERR.KEEPALIVE_CANCEL)
        self.assertLess(time.monotonic() - started, 3)

    def test_closing_the_device_cancels_the_prompt(self):
        self.h.verifier.delay = 10
        self.h.store.add(self.h.requester.uid, self.h.requester.username, _resident_credential(self.h))

        def sign_in():
            try:
                Ctap2(self.h.device).get_assertion("example.com", b"\0" * 32)
            except Exception:
                pass  # the reply is dropped once the device is reset

        threading.Thread(target=sign_in, daemon=True).start()
        time.sleep(0.3)
        self.assertTrue(self.h.verifier.messages)
        self.h.connection.transport.reset()
        self.assertTrue(self.h.verifier.saw_cancel.wait(2))


if __name__ == "__main__":
    unittest.main()
