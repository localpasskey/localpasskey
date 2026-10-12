"""CTAPHID: the FIDO USB HID framing layer (CTAP 2.1, section 11.2).

Messages are split into 64-byte reports: an initialisation packet carrying the
channel ID, command and length, followed by sequence-numbered continuation
packets. Only one transaction runs at a time; CBOR requests are processed on a
worker thread so the transport can keep answering INIT/CANCEL and send
KEEPALIVE packets while the user is looking at the confirmation dialog.
"""

from __future__ import annotations

import logging
import secrets
import struct
import threading
import time
from collections import OrderedDict
from typing import Callable, Optional

log = logging.getLogger(__name__)

REPORT_SIZE = 64
INIT_PAYLOAD = REPORT_SIZE - 7
CONT_PAYLOAD = REPORT_SIZE - 5
MAX_MESSAGE = INIT_PAYLOAD + 128 * CONT_PAYLOAD
BROADCAST_CID = 0xFFFFFFFF

CMD_PING = 0x01
CMD_MSG = 0x03
CMD_INIT = 0x06
CMD_CBOR = 0x10
CMD_CANCEL = 0x11
CMD_KEEPALIVE = 0x3B
CMD_ERROR = 0x3F

ERR_INVALID_CMD = 0x01
ERR_INVALID_LEN = 0x03
ERR_INVALID_SEQ = 0x04
ERR_MSG_TIMEOUT = 0x05
ERR_CHANNEL_BUSY = 0x06
ERR_INVALID_CHANNEL = 0x0B

CAPABILITY_CBOR = 0x04
CAPABILITY_NMSG = 0x08  # no CTAP1/U2F CTAPHID_MSG support

PROTOCOL_VERSION = 2
MESSAGE_TIMEOUT = 2.0
KEEPALIVE_INTERVAL = 0.1
MAX_CHANNELS = 64

STATUS_PROCESSING = 1


class _Assembly:
    def __init__(self, cid, cmd, length, data):
        self.cid = cid
        self.cmd = cmd
        self.length = length
        self.data = bytearray(data)
        self.next_seq = 0
        self.deadline = time.monotonic() + MESSAGE_TIMEOUT


class _Transaction:
    """One running CBOR request; also the ``ctx`` its handler sees."""

    def __init__(self, cid, channel):
        self.cid = cid
        self.channel = channel
        self.cancelled = threading.Event()
        self.status = STATUS_PROCESSING
        self.last_keepalive = time.monotonic()

    def set_status(self, status):
        self.status = status


class CtapHidTransport:
    def __init__(self, send_report: Callable[[bytes], None], authenticator, version):
        """``send_report`` writes one 64-byte input report to the host;
        ``authenticator`` provides ``process(request, ctx)`` and
        ``new_channel_state()``."""
        self._send_report = send_report
        self._authenticator = authenticator
        self._version = version
        self._lock = threading.RLock()
        self._channels: "OrderedDict[int, object]" = OrderedDict()
        self._assembly: Optional[_Assembly] = None
        self._busy: Optional[_Transaction] = None

    def handle_report(self, report: bytes) -> None:
        report = bytes(report[:REPORT_SIZE]).ljust(REPORT_SIZE, b"\0")
        cid = struct.unpack_from(">I", report)[0]
        with self._lock:
            if report[4] & 0x80:
                self._on_init_packet(cid, report[4] & 0x7F, report)
            else:
                self._on_continuation_packet(cid, report[4], report)

    def reset(self) -> None:
        """Forget all channels and abort the running transaction (the host
        closed the device)."""
        with self._lock:
            self._assembly = None
            self._abort_busy()
            self._channels.clear()

    def poll_timeout(self) -> Optional[float]:
        """Seconds until ``tick()`` has work to do, or None when idle."""
        with self._lock:
            deadlines = []
            if self._assembly is not None:
                deadlines.append(self._assembly.deadline)
            if self._busy is not None:
                deadlines.append(self._busy.last_keepalive + KEEPALIVE_INTERVAL)
            if not deadlines:
                return None
            return max(0.0, min(deadlines) - time.monotonic())

    def tick(self) -> None:
        now = time.monotonic()
        with self._lock:
            assembly = self._assembly
            if assembly is not None and now >= assembly.deadline:
                self._assembly = None
                self._send_error(assembly.cid, ERR_MSG_TIMEOUT)
            busy = self._busy
            if busy is not None and now - busy.last_keepalive >= KEEPALIVE_INTERVAL:
                busy.last_keepalive = now
                self._send(busy.cid, CMD_KEEPALIVE, bytes([busy.status]))

    def _on_init_packet(self, cid, cmd, report):
        length = struct.unpack_from(">H", report, 5)[0]
        data = report[7 : 7 + min(length, INIT_PAYLOAD)]
        if cid == 0:
            self._send_error(cid, ERR_INVALID_CHANNEL)
            return
        if cmd == CMD_INIT:
            if length != 8:
                self._send_error(cid, ERR_INVALID_LEN)
            else:
                self._handle_init(cid, data)
            return
        if cid == BROADCAST_CID or cid not in self._channels:
            self._send_error(cid, ERR_INVALID_CHANNEL)
            return
        self._channels.move_to_end(cid)
        if cmd == CMD_CANCEL:
            if self._busy is not None and self._busy.cid == cid:
                log.debug("Channel %08x cancelled its request", cid)
                self._busy.cancelled.set()
            return
        if self._busy is not None or (self._assembly is not None and self._assembly.cid != cid):
            self._send_error(cid, ERR_CHANNEL_BUSY)
            return
        if length > MAX_MESSAGE:
            self._assembly = None
            self._send_error(cid, ERR_INVALID_LEN)
            return
        if length <= INIT_PAYLOAD:
            self._assembly = None
            self._dispatch(cid, cmd, data)
        else:
            self._assembly = _Assembly(cid, cmd, length, data)

    def _on_continuation_packet(self, cid, seq, report):
        assembly = self._assembly
        if assembly is None or assembly.cid != cid:
            return  # stray continuation packet: ignore it, as the spec says
        if seq != assembly.next_seq:
            self._assembly = None
            self._send_error(cid, ERR_INVALID_SEQ)
            return
        needed = assembly.length - len(assembly.data)
        assembly.data += report[5 : 5 + min(needed, CONT_PAYLOAD)]
        assembly.next_seq += 1
        if len(assembly.data) >= assembly.length:
            self._assembly = None
            self._dispatch(cid, assembly.cmd, bytes(assembly.data))

    def _handle_init(self, cid, nonce):
        if cid == BROADCAST_CID:
            response_cid = self._allocate_channel()
        elif cid not in self._channels:
            self._send_error(cid, ERR_INVALID_CHANNEL)
            return
        else:
            # INIT on an existing channel re-synchronises it.
            if self._assembly is not None and self._assembly.cid == cid:
                self._assembly = None
            if self._busy is not None and self._busy.cid == cid:
                self._abort_busy()
            self._channels[cid] = self._authenticator.new_channel_state()
            self._channels.move_to_end(cid)
            response_cid = cid
        payload = nonce + struct.pack(
            ">IBBBBB",
            response_cid,
            PROTOCOL_VERSION,
            *self._version,
            CAPABILITY_CBOR | CAPABILITY_NMSG,
        )
        self._send(cid, CMD_INIT, payload)

    def _allocate_channel(self):
        while True:
            cid = secrets.randbits(32)
            if cid not in (0, BROADCAST_CID) and cid not in self._channels:
                break
        active_cids = {t.cid for t in (self._busy, self._assembly) if t is not None}
        while len(self._channels) >= MAX_CHANNELS:
            oldest = next(c for c in self._channels if c not in active_cids)
            del self._channels[oldest]
        self._channels[cid] = self._authenticator.new_channel_state()
        return cid

    def _dispatch(self, cid, cmd, data):
        if cmd == CMD_PING:
            self._send(cid, CMD_PING, data)
        elif cmd == CMD_CBOR and data:
            transaction = _Transaction(cid, self._channels[cid])
            self._busy = transaction
            threading.Thread(
                target=self._run, args=(transaction, data), name=f"ctap-{cid:08x}", daemon=True
            ).start()
        elif cmd == CMD_CBOR:
            self._send_error(cid, ERR_INVALID_LEN)
        else:
            self._send_error(cid, ERR_INVALID_CMD)

    def _run(self, transaction, request):
        try:
            response = self._authenticator.process(request, transaction)
        except Exception:
            log.exception("CTAP request handler crashed")
            response = b"\x7f"
        with self._lock:
            if self._busy is transaction:
                self._busy = None
                self._send(transaction.cid, CMD_CBOR, response)

    def _abort_busy(self):
        if self._busy is not None:
            self._busy.cancelled.set()
            self._busy = None

    def _send_error(self, cid, code):
        self._send(cid, CMD_ERROR, bytes([code]))

    def _send(self, cid, cmd, payload):
        try:
            packet = struct.pack(">IBH", cid, 0x80 | cmd, len(payload)) + payload[:INIT_PAYLOAD]
            self._send_report(packet.ljust(REPORT_SIZE, b"\0"))
            for seq, offset in enumerate(range(INIT_PAYLOAD, len(payload), CONT_PAYLOAD)):
                packet = struct.pack(">IB", cid, seq) + payload[offset : offset + CONT_PAYLOAD]
                self._send_report(packet.ljust(REPORT_SIZE, b"\0"))
        except OSError as e:
            log.debug("Could not send a HID report: %s", e)
