import errno
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from localpasskey import uhid


class UhidTests(unittest.TestCase):
    def device(self):
        written = patch("localpasskey.uhid.os.write", side_effect=lambda _fd, data: len(data))
        self.addCleanup(written.stop)
        self.write = written.start()
        with patch("localpasskey.uhid.os.open", return_value=93):
            return uhid.UhidDevice("Test Key", "unique-id", 0x1209, 0x4c50, version=0x0102)

    def test_create_input_and_destroy_wire_layout(self):
        device = self.device()
        create = self.write.call_args.args[1]
        header = struct.unpack_from("=I128s64s64sHHIIII", create)
        self.assertEqual(len(create), uhid.EVENT_SIZE)
        self.assertEqual(header[0], 11)
        self.assertEqual(header[1].rstrip(b"\0"), b"Test Key")
        self.assertEqual(header[3].rstrip(b"\0"), b"unique-id")
        self.assertEqual(header[4:9], (len(uhid.FIDO_REPORT_DESCRIPTOR), 3, 0x1209, 0x4c50, 0x0102))
        self.assertEqual(create[280:280 + header[4]], uhid.FIDO_REPORT_DESCRIPTOR)
        report = bytes(range(64))
        device.send_input(report)
        self.assertEqual(self.write.call_args.args, (93, b"\x0c\x00\x00\x00\x40\x00" + report))
        with patch("localpasskey.uhid.os.close") as close:
            device.close()
        self.assertEqual(self.write.call_args.args, (93, b"\x01\x00\x00\x00"))
        close.assert_called_once_with(93)

    def test_short_create_write_closes_descriptor(self):
        with (
            patch("localpasskey.uhid.os.open", return_value=93),
            patch("localpasskey.uhid.os.write", return_value=1),
            patch("localpasskey.uhid.os.close") as close,
            self.assertRaises(OSError) as error,
        ):
            uhid.UhidDevice("test", "id", 1, 2)
        self.assertEqual(error.exception.errno, errno.EIO)
        close.assert_called_once_with(93)

    def test_invalid_create_arguments_do_not_leak_a_descriptor(self):
        with patch("localpasskey.uhid.os.open", return_value=93) as opened, self.assertRaises(struct.error):
            uhid.UhidDevice("test", "id", -1, 2)
        opened.assert_not_called()

    def test_read_event_rejects_truncation(self):
        device = self.device()
        with patch("localpasskey.uhid.os.read", return_value=b"\x06\0\0\0payload"):
            self.assertEqual(device.read_event(), (6, b"payload"))
        for data in (b"", b"\x01\x02\x03"):
            with self.subTest(data=data), patch("localpasskey.uhid.os.read", return_value=data), self.assertRaises(OSError):
                device.read_event()

    def test_output_report_number_and_report_type(self):
        report = bytes(range(64))
        for data, report_type, expected in (
            (report, uhid.UHID_OUTPUT_REPORT, report),
            (b"\0" + report, uhid.UHID_OUTPUT_REPORT, report),
            (b"", uhid.UHID_OUTPUT_REPORT, None),
            (report, 2, None),
        ):
            with self.subTest(length=len(data), report_type=report_type):
                payload = data.ljust(uhid.UHID_DATA_MAX, b"\0") + struct.pack("=HB", len(data), report_type)
                self.assertEqual(uhid.UhidDevice.output_report(payload), expected)

    def test_feature_requests_get_matching_error_replies(self):
        device = self.device()
        device.reject_report_request(uhid.UHID_GET_REPORT, struct.pack("=I", 17))
        self.assertEqual(self.write.call_args.args[1], struct.pack("=IIHH", 10, 17, errno.EIO, 0))
        device.reject_report_request(uhid.UHID_SET_REPORT, struct.pack("=I", 18))
        self.assertEqual(self.write.call_args.args[1], struct.pack("=IIH", 14, 18, errno.EIO))

    def test_hidraw_discovery_matches_entire_unique_id(self):
        device = self.device()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, value in (("hidraw10", "unique-id-suffix"), ("hidraw11", "unique-id")):
                (root / name / "device").mkdir(parents=True)
                (root / name / "device/uevent").write_text(f"HID_UNIQ={value}\n")
            with patch("localpasskey.uhid.Path", return_value=root), patch("localpasskey.uhid.os.path.exists", return_value=False):
                self.assertEqual(device.hidraw_path(), "/dev/hidraw11")


if __name__ == "__main__":
    unittest.main()
