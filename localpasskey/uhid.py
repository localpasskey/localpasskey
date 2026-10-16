"""A virtual USB HID FIDO device created through the Linux uhid driver.

Writing UHID_CREATE2 to /dev/uhid makes the kernel register a HID device and a
/dev/hidrawN node for it. Browsers find it like any USB security key; systemd's
``fido_id`` udev helper recognises the FIDO report descriptor and tags the node
``uaccess``, which grants the user of the active session access to it.
"""

from __future__ import annotations

import errno
import os
import struct
import threading
from pathlib import Path
from typing import Optional, Tuple

UHID_DESTROY = 1
UHID_START = 2
UHID_STOP = 3
UHID_OPEN = 4
UHID_CLOSE = 5
UHID_OUTPUT = 6
UHID_GET_REPORT = 9
UHID_GET_REPORT_REPLY = 10
UHID_CREATE2 = 11
UHID_INPUT2 = 12
UHID_SET_REPORT = 13
UHID_SET_REPORT_REPLY = 14

UHID_OUTPUT_REPORT = 1
BUS_USB = 0x03
UHID_DATA_MAX = 4096
HID_MAX_DESCRIPTOR_SIZE = 4096
EVENT_SIZE = 4 + 128 + 64 + 64 + 2 + 2 + 4 * 4 + HID_MAX_DESCRIPTOR_SIZE  # sizeof(struct uhid_event)

# One application collection on the FIDO usage page (0xF1D0) with 64-byte
# input and output reports and no report IDs (CTAP 2.1, section 11.2.8.1).
FIDO_REPORT_DESCRIPTOR = bytes([
    0x06, 0xD0, 0xF1,  # Usage Page (FIDO Alliance)
    0x09, 0x01,        # Usage (CTAPHID)
    0xA1, 0x01,        # Collection (Application)
    0x09, 0x20,        #   Usage (Input Report Data)
    0x15, 0x00,        #   Logical Minimum (0)
    0x26, 0xFF, 0x00,  #   Logical Maximum (255)
    0x75, 0x08,        #   Report Size (8)
    0x95, 0x40,        #   Report Count (64)
    0x81, 0x02,        #   Input (Data, Variable, Absolute)
    0x09, 0x21,        #   Usage (Output Report Data)
    0x15, 0x00,        #   Logical Minimum (0)
    0x26, 0xFF, 0x00,  #   Logical Maximum (255)
    0x75, 0x08,        #   Report Size (8)
    0x95, 0x40,        #   Report Count (64)
    0x91, 0x02,        #   Output (Data, Variable, Absolute)
    0xC0,              # End Collection
])


class UhidDevice:
    def __init__(self, name, uniq, vendor_id, product_id, version=0):
        self.uniq = uniq
        self._write_lock = threading.Lock()
        self._hidraw: Optional[str] = None
        create = struct.pack(
            "=I128s64s64sHHIIII",
            UHID_CREATE2,
            name.encode()[:127],
            b"localpasskey",
            uniq.encode()[:63],
            len(FIDO_REPORT_DESCRIPTOR),
            BUS_USB,
            vendor_id,
            product_id,
            version,
            0,
        ) + FIDO_REPORT_DESCRIPTOR.ljust(HID_MAX_DESCRIPTOR_SIZE, b"\0")
        self.fd = os.open("/dev/uhid", os.O_RDWR | os.O_CLOEXEC)
        try:
            self._write(create)
        except OSError:
            os.close(self.fd)
            raise

    def _write(self, data):
        with self._write_lock:
            if os.write(self.fd, data) != len(data):
                raise OSError(errno.EIO, "short write to /dev/uhid")

    def send_input(self, report: bytes) -> None:
        self._write(struct.pack("=IH", UHID_INPUT2, len(report)) + report)

    def read_event(self) -> Tuple[int, bytes]:
        data = os.read(self.fd, EVENT_SIZE)
        if len(data) < 4:
            raise OSError(errno.EIO, "short read from /dev/uhid")
        return struct.unpack_from("=I", data)[0], data[4:]

    @staticmethod
    def output_report(payload: bytes) -> Optional[bytes]:
        """Extract the report from a UHID_OUTPUT event, without the report ID."""
        size = struct.unpack_from("=H", payload, UHID_DATA_MAX)[0]
        rtype = payload[UHID_DATA_MAX + 2]
        if rtype != UHID_OUTPUT_REPORT or size == 0:
            return None
        data = payload[:min(size, UHID_DATA_MAX)]
        # hidraw writes start with the report number, which is 0 for devices
        # without numbered reports.
        return data[1:] if len(data) == 65 else data

    def reject_report_request(self, event_type: int, payload: bytes) -> None:
        """Answer GET_REPORT/SET_REPORT requests (FIDO doesn't use them)."""
        request_id = struct.unpack_from("=I", payload)[0]
        if event_type == UHID_GET_REPORT:
            self._write(struct.pack("=IIHH", UHID_GET_REPORT_REPLY, request_id, errno.EIO, 0))
        else:
            self._write(struct.pack("=IIH", UHID_SET_REPORT_REPLY, request_id, errno.EIO))

    def hidraw_path(self) -> Optional[str]:
        """The /dev/hidrawN node the kernel created for this device."""
        if self._hidraw and os.path.exists(self._hidraw):
            return self._hidraw
        self._hidraw = None
        marker = f"HID_UNIQ={self.uniq}"
        try:
            entries = list(Path("/sys/class/hidraw").iterdir())
        except OSError:
            return None
        for entry in entries:
            try:
                uevent = (entry / "device" / "uevent").read_text()
            except OSError:
                continue
            if marker in uevent.splitlines():
                self._hidraw = f"/dev/{entry.name}"
                break
        return self._hidraw

    def close(self) -> None:
        try:
            self._write(struct.pack("=I", UHID_DESTROY))
        except OSError:
            pass
        os.close(self.fd)
