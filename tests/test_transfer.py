import json
import os
import unittest
from unittest.mock import patch

from localpasskey import cose, transfer
from localpasskey.store import b64decode, b64encode
from localpasskey.transfer import TransferError, WrongPassphrase

PASSPHRASE = "correct horse"


def make_record(alg=cose.ES256, rp_id="example.com", user_id=b"u1", **overrides):
    key = cose.generate_private_key(alg)
    record = {
        "id": b64encode(os.urandom(32)), "rp_id": rp_id, "rp_name": "Example",
        "user_id": b64encode(user_id), "user_name": "alice", "user_display_name": "Alice",
        "alg": alg, "private_key": b64encode(cose.private_key_to_bytes(key)),
        "discoverable": True, "cred_protect": 2, "created": 1760486400.0,
    }
    record.update(overrides)
    return record


# Fast KDF for the tests; the real parameters are tested once.
fast_kdf = patch.multiple(transfer, SCRYPT_N=2**10, SCRYPT_R=8, SCRYPT_P=1)


@fast_kdf
class BackupTests(unittest.TestCase):
    def roundtrip(self, records, passphrase=PASSPHRASE):
        data = transfer.export_backup(records, PASSPHRASE)
        return transfer.load(data, lambda: passphrase)

    def test_round_trip_every_algorithm(self):
        records = [make_record(alg) for alg in cose.SUPPORTED_ALGORITHMS]
        loaded = self.roundtrip(records)
        self.assertEqual(loaded, records)
        self.assertEqual(loaded.skipped, [])
        self.assertEqual(loaded.format, "localpasskey")
        self.assertEqual(transfer.detect_format(transfer.export_backup(records, PASSPHRASE)), "localpasskey")

    def test_keys_are_not_in_the_file_in_clear(self):
        record = make_record()
        data = transfer.export_backup([record], PASSPHRASE)
        self.assertNotIn(record["private_key"].encode(), data)
        self.assertNotIn(b"example.com", data)

    def test_wrong_passphrase(self):
        with self.assertRaises(WrongPassphrase):
            self.roundtrip([make_record()], passphrase="wrong horse")

    def test_passphrase_is_unicode_normalized(self):
        data = transfer.export_backup([make_record()], "café au lait")
        self.assertEqual(len(transfer.load(data, lambda: "café au lait")), 1)

    def test_passphrase_callback_only_for_backups_and_empty_refused(self):
        data = transfer.export_backup([make_record()], PASSPHRASE)
        with self.assertRaises(TransferError):
            transfer.load(data, lambda: "")

    def test_weak_passphrase_refused_on_export(self):
        with self.assertRaises(TransferError):
            transfer.export_backup([make_record()], "short")

    def tamper(self, change):
        doc = json.loads(transfer.export_backup([make_record()], PASSPHRASE))
        change(doc)
        return json.dumps(doc).encode()

    def test_tampered_ciphertext(self):
        def flip(doc):
            raw = bytearray(b64decode(doc["ciphertext"]))
            raw[5] ^= 1
            doc["ciphertext"] = b64encode(bytes(raw))
        with self.assertRaises(WrongPassphrase):
            transfer.load(self.tamper(flip), lambda: PASSPHRASE)

    def test_tampered_header(self):
        def change(doc):
            doc["kdf"]["n"] //= 2  # still a valid, cheaper parameter
        with self.assertRaises(WrongPassphrase):
            transfer.load(self.tamper(change), lambda: PASSPHRASE)

        def extra(doc):
            doc["kdf"]["note"] = "x"
        with self.assertRaises(WrongPassphrase):
            transfer.load(self.tamper(extra), lambda: PASSPHRASE)

    def test_hostile_kdf_params_refused_before_the_passphrase(self):
        hostile = [
            {"n": 2**21}, {"n": 2**20 + 1}, {"n": 3}, {"n": "1024"}, {"n": True},
            {"r": 9}, {"r": 0}, {"p": 5}, {"p": 0}, {"name": "pbkdf2"},
            {"salt": b64encode(b"short")}, {"salt": "not base64!"},
        ]
        for change in hostile:
            with self.subTest(change=change):
                data = self.tamper(lambda doc: doc["kdf"].update(change))
                asked = []
                with self.assertRaises(TransferError) as caught:
                    transfer.load(data, lambda: asked.append(1) or PASSPHRASE)
                self.assertNotIsInstance(caught.exception, WrongPassphrase)
                self.assertEqual(asked, [])

    def test_other_damage(self):
        for change in (
            lambda doc: doc.update(version=2),
            lambda doc: doc.update(cipher="ChaCha20"),
            lambda doc: doc.update(nonce=b64encode(b"123")),
            lambda doc: doc.pop("ciphertext"),
        ):
            with self.assertRaises(TransferError):
                transfer.load(self.tamper(change), lambda: PASSPHRASE)
        for data in (b"", b"\xff", b"[]", b'{"hello": 1}'):
            with self.assertRaises(TransferError):
                transfer.load(data, lambda: PASSPHRASE)

    def test_bad_records_are_skipped_with_a_reason(self):
        good = make_record()
        mismatch = dict(make_record(cose.EDDSA), alg=cose.ES256)
        long_id = make_record(id=b64encode(bytes(513)))
        unknown = dict(make_record(), alg=-35)
        loaded = self.roundtrip([good, mismatch, long_id, unknown, "junk"])
        self.assertEqual(loaded, [good])
        reasons = [s["reason"] for s in loaded.skipped]
        self.assertEqual(len(reasons), 4)
        self.assertIn("does not match", reasons[0])
        self.assertIn("1 to 512 bytes", reasons[1])
        self.assertIn("unsupported algorithm", reasons[2])
        self.assertEqual(loaded.skipped[0]["credential"]["site"], "example.com")

    def test_labels_shortened_and_bad_created_dropped(self):
        record = make_record(user_name="x" * 400, created=float("nan"), cred_protect=7)
        loaded = self.roundtrip([record])[0]
        self.assertEqual(len(loaded["user_name"]), 255)
        self.assertEqual(loaded["created"], 0.0)
        self.assertEqual(loaded["cred_protect"], 1)


class RealKdfTests(unittest.TestCase):
    def test_default_parameters(self):
        doc = json.loads(transfer.export_backup([make_record()], PASSPHRASE))
        self.assertEqual(doc["kdf"]["n"], 2**17)
        self.assertEqual(len(b64decode(doc["kdf"]["salt"])), 16)
        self.assertEqual(len(transfer.load(json.dumps(doc).encode(), lambda: PASSPHRASE)), 1)


class PassphraseProblemTests(unittest.TestCase):
    def test_cases(self):
        cases = [
            ("", None, "Enter a passphrase"),
            ("1234567", None, "At least 8 characters"),
            ("12345678", None, None),
            ("12345678", "", None),
            ("12345678", "1234", "The passphrases do not match"),
            ("12345678", "12345678", None),
        ]
        for passphrase, repeat, expected in cases:
            with self.subTest(passphrase=passphrase, repeat=repeat):
                self.assertEqual(transfer.passphrase_problem(passphrase, repeat), expected)


if __name__ == "__main__":
    unittest.main()
