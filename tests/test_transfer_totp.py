import json
import os
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from localpasskey import cose, totp, transfer
from localpasskey.store import b64decode, b64encode
from localpasskey.totp import OtpError
from localpasskey.transfer import TransferError, WrongPassphrase

PASSPHRASE = "correct horse"

# Fast KDF for the tests; the real parameters are tested once.
fast_kdf = patch.multiple(transfer, SCRYPT_N=2**10, SCRYPT_R=8, SCRYPT_P=1)


def make_passkey(**overrides):
    key = cose.generate_private_key(cose.ES256)
    record = {
        "id": b64encode(os.urandom(32)), "rp_id": "example.com", "rp_name": "Example",
        "user_id": b64encode(b"u1"), "user_name": "alice", "user_display_name": "Alice",
        "alg": cose.ES256, "private_key": b64encode(cose.private_key_to_bytes(key)),
        "discoverable": True, "cred_protect": 2, "created": 1760486400.0,
    }
    record.update(overrides)
    return record


def make_code(**overrides):
    record = {
        "id": b64encode(os.urandom(16)), "site": "github.com", "issuer": "GitHub",
        "account": "alice@example.com", "secret": "JBSWY3DPEHPK3PXP",
        "algorithm": "SHA1", "digits": 6, "period": 30, "created": 1760486400.0,
    }
    record.update(overrides)
    return record


@fast_kdf
class CodesBackupTests(unittest.TestCase):
    def header(self, data):
        return json.loads(data)

    def test_round_trip_with_codes(self):
        passkey = make_passkey()
        codes = [make_code(), make_code(site="", issuer="ACME", algorithm="SHA256",
                                       digits=8, period=60, secret="jbsw y3dp ehpk 3pxp")]
        loaded = transfer.load(transfer.export_backup([passkey], PASSPHRASE, codes), lambda: PASSPHRASE)
        self.assertEqual(loaded, [passkey])
        self.assertEqual(loaded.skipped, [])
        self.assertEqual(loaded.skipped_codes, [])
        self.assertEqual(loaded.codes[0], codes[0])
        # The setup key is written canonically, without spaces.
        self.assertEqual(loaded.codes[1], dict(codes[1], secret="JBSWY3DPEHPK3PXP"))
        self.assertEqual(transfer.describe_code(loaded.codes[1])["id"], b64decode(codes[1]["id"]).hex())

    def test_version_1_without_codes(self):
        self.assertEqual(self.header(transfer.export_backup([make_passkey()], PASSPHRASE))["version"], 1)
        self.assertEqual(self.header(transfer.export_backup([], PASSPHRASE))["version"], 1)
        self.assertEqual(self.header(transfer.export_backup([make_passkey()], PASSPHRASE, []))["version"], 1)

    def test_version_2_with_codes(self):
        data = transfer.export_backup([], PASSPHRASE, [make_code()])
        self.assertEqual(self.header(data)["version"], transfer.CODES_BACKUP_VERSION)
        self.assertEqual(transfer.CODES_BACKUP_VERSION, 2)
        self.assertEqual(transfer.detect_format(data), "localpasskey")
        self.assertNotIn(b"github.com", data)
        self.assertNotIn(make_code()["secret"].encode(), data)

    def test_old_reader_refuses_version_2(self):
        def reader(data):  # what 0.3.1 does: only version 1 is known
            doc = json.loads(data)
            if doc.get("version") != transfer.BACKUP_VERSION:
                raise TransferError("newer LocalPasskey")
            return doc

        reader(transfer.export_backup([make_passkey()], PASSPHRASE))
        with self.assertRaises(TransferError):
            reader(transfer.export_backup([make_passkey()], PASSPHRASE, [make_code()]))

    def test_tampered_version_refused(self):
        doc = json.loads(transfer.export_backup([], PASSPHRASE, [make_code()]))
        doc["version"] = 1  # the header is the associated data
        with self.assertRaises(WrongPassphrase):
            transfer.load(json.dumps(doc).encode(), lambda: PASSPHRASE)
        doc["version"] = 3
        with self.assertRaises(TransferError):
            transfer.load(json.dumps(doc).encode(), lambda: PASSPHRASE)

    def test_bad_codes_skipped_with_reasons(self):
        good = make_code()
        bad = [
            ("junk", "not an authenticator code"),
            (make_code(id=b64encode(b"123")), "16 bytes"),
            (make_code(secret=None), "setup key is missing"),
            (make_code(secret="ABC"), "not a valid setup key"),
            (make_code(secret="JBSWY3DP"), "too short"),
            (make_code(site="not a site"), "invalid site"),
            (make_code(algorithm="MD5"), "algorithm"),
            (make_code(digits=7), "6 or 8"),
            (make_code(digits=True), "6 or 8"),
            (make_code(period=0), "period"),
            (make_code(period=301), "period"),
        ]
        loaded = transfer.load(transfer.export_backup([], PASSPHRASE, [good] + [b[0] for b in bad]),
                               lambda: PASSPHRASE)
        self.assertEqual(loaded.codes, [good])
        reasons = [s["reason"] for s in loaded.skipped_codes]
        self.assertEqual(len(reasons), len(bad))
        for reason, (_, expected) in zip(reasons, bad):
            self.assertIn(expected, reason)
        self.assertEqual(loaded.skipped_codes[1]["code"]["id"], b64decode(bad[1][0]["id"]).hex())

    def test_code_defaults_and_bad_created(self):
        code = make_code(created=float("nan"), site="")
        for key in ("algorithm", "digits", "period"):
            code.pop(key)
        loaded = transfer.load(transfer.export_backup([], PASSPHRASE, [code]), lambda: PASSPHRASE)
        self.assertEqual(loaded.codes[0]["algorithm"], totp.DEFAULT_ALGORITHM)
        self.assertEqual(loaded.codes[0]["digits"], totp.DEFAULT_DIGITS)
        self.assertEqual(loaded.codes[0]["period"], totp.DEFAULT_PERIOD)
        self.assertEqual(loaded.codes[0]["created"], 0.0)
        self.assertEqual(loaded.codes[0]["site"], "")

    def with_plaintext(self, plaintext, version=transfer.BACKUP_VERSION):
        doc = json.loads(transfer.export_backup([], PASSPHRASE))
        doc["version"] = version
        header = {key: doc[key] for key in ("format", "version", "kdf", "cipher")}
        key = transfer._passphrase_key(PASSPHRASE, header["kdf"])
        nonce = b64decode(doc["nonce"])
        doc["ciphertext"] = b64encode(AESGCM(key).encrypt(nonce, plaintext, transfer._header_aad(header)))
        return json.dumps(doc).encode()

    def test_version_2_payload_must_hold_codes(self):
        plaintext = json.dumps({"credentials": []}).encode()
        with self.assertRaises(TransferError):
            transfer.load(self.with_plaintext(plaintext, transfer.CODES_BACKUP_VERSION), lambda: PASSPHRASE)

    def test_hostile_code_payload_does_not_crash(self):
        nested = b'{"credentials": [], "codes": ' + b"[" * 100000 + b"]" * 100000 + b"}"
        with self.assertRaises(TransferError):
            transfer.load(self.with_plaintext(nested, transfer.CODES_BACKUP_VERSION), lambda: PASSPHRASE)

    def test_cxf_and_bitwarden_carry_no_codes(self):
        loaded = transfer.load(transfer.export_cxf([make_passkey()]), lambda: PASSPHRASE)
        self.assertEqual(loaded.codes, [])
        self.assertEqual(loaded.skipped_codes, [])
        bitwarden = json.dumps({"items": []}).encode()
        self.assertEqual(transfer.load(bitwarden, lambda: PASSPHRASE).codes, [])
