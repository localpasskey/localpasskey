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


class CxfTests(unittest.TestCase):
    def test_round_trip_every_algorithm(self):
        records = [make_record(alg, cred_protect=1) for alg in cose.SUPPORTED_ALGORITHMS]
        data = transfer.export_cxf(records, now=1760486400)
        self.assertEqual(transfer.detect_format(data), "cxf")
        doc = json.loads(data)
        self.assertEqual(doc["version"], {"major": 1, "minor": 0})
        self.assertEqual(doc["accounts"][0]["collections"], [])
        cred = doc["accounts"][0]["items"][0]["credentials"][0]
        self.assertEqual(cred["type"], "passkey")
        self.assertEqual(cred["key"], records[0]["private_key"])
        loaded = transfer.load(data, self.fail)
        self.assertEqual(loaded.format, "cxf")
        self.assertEqual(loaded, records)

    def test_spec_example_with_other_items_and_skips(self):
        good = make_record()
        doc = {
            "version": {"major": 1, "minor": 0}, "exporterRpId": "exporter.example",
            "exporterDisplayName": "Exporter", "timestamp": 1760486400,
            "accounts": [{
                "id": "DZSXp7iBQY-Fg-OofakQtQ", "username": "", "email": "", "collections": [],
                "items": [
                    {"id": "AA", "title": "Example", "creationAt": 1760486400, "unknownField": 1,
                     "credentials": [
                         {"type": "basic-auth", "username": {"fieldType": "string", "value": "x"}},
                         {"type": "passkey", "credentialId": good["id"], "rpId": "example.com",
                          "username": "alice", "userDisplayName": "Alice",
                          "userHandle": good["user_id"] + "==", "key": good["private_key"],
                          "fido2Extensions": {"payments": False}},
                     ]},
                    {"id": "AB", "title": "Broken", "credentials": [
                        {"type": "passkey", "credentialId": "AQ", "rpId": "broken.example",
                         "username": "bob", "userDisplayName": "", "userHandle": "",
                         "key": b64encode(b"not a key")},
                    ]},
                ],
            }],
        }
        loaded = transfer.load(json.dumps(doc).encode(), self.fail)
        self.assertEqual(loaded, [dict(good, rp_name="Example", cred_protect=1)])
        self.assertEqual(loaded.skipped, [{
            "credential": transfer.describe({"rp_id": "broken.example", "rp_name": "Broken", "user_name": "bob"}),
            "reason": "the private key cannot be read",
        }])

    def test_unsupported_version(self):
        doc = json.loads(transfer.export_cxf([make_record()]))
        doc["version"]["major"] = 2
        with self.assertRaises(TransferError):
            transfer.load(json.dumps(doc).encode(), self.fail)


def bitwarden_credential(record, **overrides):
    cred = {
        "credentialId": "b64." + record["id"], "keyType": "public-key", "keyAlgorithm": "ECDSA",
        "keyCurve": "P-256", "keyValue": record["private_key"], "rpId": record["rp_id"],
        "userHandle": record["user_id"], "userName": record["user_name"], "counter": "0",
        "rpName": record["rp_name"], "userDisplayName": record["user_display_name"],
        "discoverable": "true", "creationDate": "2025-10-15T00:00:00.000Z",
    }
    cred.update(overrides)
    return cred


def bitwarden_export(*creds, **top):
    item = {
        "id": "6a1b4b8e-1c2d-4e5f-8a9b-0c1d2e3f4a5b", "organizationId": None, "folderId": None,
        "type": 1, "reprompt": 0, "name": "Example item", "notes": None, "favorite": False,
        "login": {"uris": [{"match": None, "uri": "https://example.com"}], "username": "login-user",
                  "password": None, "totp": None, "fido2Credentials": list(creds)},
        "collectionIds": None, "revisionDate": "2025-10-15T00:00:00.000Z",
        "creationDate": "2025-10-15T00:00:00.000Z", "deletedDate": None,
    }
    note = {"id": "x", "type": 2, "name": "A note", "secureNote": {"type": 0}}
    doc = {"encrypted": False, "folders": [], "items": [item, note]}
    doc.update(top)
    return json.dumps(doc).encode()


class BitwardenTests(unittest.TestCase):
    def test_import(self):
        guid_record = make_record(id=b64encode(bytes(range(16))), cred_protect=1, created=1760486400.0)
        b64_record = make_record(cred_protect=1, created=1760486400.0)
        data = bitwarden_export(
            bitwarden_credential(guid_record, credentialId="00010203-0405-0607-0809-0a0b0c0d0e0f",
                                 creationDate="2025-10-15T00:00:00.000Z"),
            bitwarden_credential(b64_record, discoverable="false", creationDate="2025-10-15T00:00:00+00:00",
                                 userName=None, rpName=None, userHandle=None),
        )
        self.assertEqual(transfer.detect_format(data), "bitwarden")
        loaded = transfer.load(data, self.fail)
        self.assertEqual(loaded.format, "bitwarden")
        self.assertEqual(loaded.skipped, [])
        self.assertEqual(loaded[0], dict(guid_record))
        self.assertEqual(loaded[1], dict(
            b64_record, discoverable=False, user_id="", user_name="login-user", rp_name="Example item",
        ))

    def test_bad_passkeys_skipped(self):
        record = make_record()
        data = bitwarden_export(
            bitwarden_credential(record, credentialId="not-a-guid"),
            bitwarden_credential(record, keyValue="!!"),
            bitwarden_credential(record, rpId=""),
            bitwarden_credential(record, creationDate="yesterday"),
        )
        loaded = transfer.load(data, self.fail)
        self.assertEqual([s["reason"] for s in loaded.skipped], [
            "the credential ID is neither a UUID nor b64.-prefixed",
            "the private key is not base64url",
            "invalid site",
        ])
        self.assertEqual(loaded[0]["created"], 0.0)

    def test_encrypted_exports_refused(self):
        protected = json.dumps({
            "encrypted": True, "passwordProtected": True, "salt": "AAAA", "kdfType": 0,
            "kdfIterations": 600000, "encKeyValidation_DO_NOT_EDIT": "2.x", "data": "2.y",
        }).encode()
        account = json.dumps({"encrypted": True, "encKeyValidation_DO_NOT_EDIT": "2.x", "items": []}).encode()
        for data, words in ((protected, "password protected"), (account, "Bitwarden account")):
            with self.assertRaises(TransferError) as caught:
                transfer.load(data, self.fail)
            self.assertIn(words, str(caught.exception))
            self.assertIn("unencrypted JSON", str(caught.exception))


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
