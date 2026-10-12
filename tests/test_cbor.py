import random
import unittest

from fido2 import cbor as reference

from localpasskey import cbor


class EncodeTests(unittest.TestCase):
    def test_simple_values(self):
        self.assertEqual(cbor.encode([False, True, None]), bytes.fromhex("83f4f5f6"))

    def test_shortest_form_integers(self):
        cases = {0: "00", 23: "17", 24: "1818", 255: "18ff", 256: "190100", 65536: "1a00010000",
                 2**32: "1b0000000100000000", -1: "20", -24: "37", -25: "3818", -257: "390100"}
        for value, encoded in cases.items():
            self.assertEqual(cbor.encode(value).hex(), encoded, value)

    def test_map_keys_are_ctap2_canonical(self):
        cose_key = cbor.encode({-3: b"y", -2: b"x", -1: 1, 3: -7, 1: 2})
        self.assertEqual(list(cbor.decode(cose_key)), [1, 3, -1, -2, -3])
        options = cbor.encode({"plat": False, "uv": True, "up": True, "rk": True})
        self.assertEqual(list(cbor.decode(options)), ["rk", "up", "uv", "plat"])

    def test_matches_python_fido2(self):
        samples = [
            {1: ["FIDO_2_0"], 3: b"\x00" * 16, 4: {"rk": True, "up": True, "uv": True, "plat": False}},
            {"id": b"\x01\x02", "type": "public-key", "displayName": "Ünïcødé"},
            [0, -1, 1000000, -1000000, b"", "", [], {}, True, False],
            {10: 1, 2: 2, 100: 3, -5: 4, -500: 5},
        ]
        for sample in samples:
            self.assertEqual(cbor.encode(sample), reference.encode(sample))
            self.assertEqual(reference.decode(cbor.encode(sample)), sample)

    def test_integer_limits_and_unsupported_values(self):
        for value in (-(2**64), 2**64 - 1):
            self.assertEqual(cbor.decode(cbor.encode(value)), value)
        for value in (-(2**64) - 1, 2**64):
            with self.assertRaises(ValueError):
                cbor.encode(value)
        with self.assertRaises(TypeError):
            cbor.encode(1.0)


class DecodeTests(unittest.TestCase):
    def test_round_trip(self):
        value = {1: b"abc", 2: {"id": "example.com"}, 3: [{"alg": -7, "type": "public-key"}],
                 7: {"rk": True, "uv": False}, 8: None}
        self.assertEqual(cbor.decode(cbor.encode(value)), value)

    def test_rejects_malformed_input(self):
        bad = {
            "trailing bytes": "0000",
            "truncated": "5801",
            "empty input": "",
            "missing array item": "81",
            "indefinite array": "9fff",
            "tag": "c000",
            "float": "f93c00",
            "duplicate key": "a201000100",
            "invalid utf-8": "61ff",
            "map key is a map": "a1a00000",
        }
        for name, hex_data in bad.items():
            with self.subTest(name), self.assertRaises(cbor.CBORDecodeError):
                cbor.decode(bytes.fromhex(hex_data))

    def test_rejects_deep_nesting(self):
        with self.assertRaises(cbor.CBORDecodeError):
            cbor.decode(b"\x81" * 40 + b"\x00")

    def test_deterministic_malformed_inputs_fail_cleanly(self):
        rng = random.Random(0)
        for length in range(64):
            for _ in range(20):
                data = rng.randbytes(length)
                try:
                    decoded = cbor.decode(data)
                except cbor.CBORDecodeError:
                    continue
                self.assertEqual(reference.decode(cbor.encode(decoded)), decoded)


if __name__ == "__main__":
    unittest.main()
