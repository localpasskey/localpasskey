import configparser
import tempfile
import unittest
from pathlib import Path

from localpasskey.config import Config, load_config


class ConfigTests(unittest.TestCase):
    def load(self, text):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "localpasskeyd.conf"
            path.write_text(text)
            return load_config(str(path))

    def test_missing_configuration_uses_defaults(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(load_config(str(Path(directory) / "missing")), Config())

    def test_overrides_parse_boolean_numeric_and_normalized_values(self):
        config = self.load("""[daemon]
prompt_timeout = 5
notifications = no
activity_notifications = off
log_level = WARNING
[device]
name = Test Authenticator
vendor_id = 0xffff
product_id = 42
""")
        self.assertEqual(config, Config(
            prompt_timeout=5.0, notifications=False, activity_notifications=False, log_level="warning",
            device_name="Test Authenticator", vendor_id=65535, product_id=42,
        ))

    def test_invalid_configuration_is_rejected(self):
        for section, key, values in (
            ("daemon", "prompt_timeout", ("4.9", "601", "nan", "inf", "invalid")),
            ("daemon", "notifications", ("perhaps",)),
            ("daemon", "activity_notifications", ("sometimes",)),
            ("daemon", "log_level", ("verbose",)),
            ("device", "vendor_id", ("-1", "65536", "0x100000000")),
            ("device", "product_id", ("-1", "65536")),
            ("device", "name", ("", "   ", "A" * 128, "\u00e9" * 64)),
        ):
            for value in values:
                with self.subTest(key=key, value=value), self.assertRaises((ValueError, configparser.Error)):
                    self.load(f"[{section}]\n{key} = {value}\n")


if __name__ == "__main__":
    unittest.main()
