import json
import os
import stat
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from localpasskey import cose
from localpasskey import store as store_module
from localpasskey.store import (
    Credential,
    CredentialStore,
    StoreError,
    StoreFull,
    TotpEntry,
)

UID, USER = 1000, "alice"


class TotpStoreTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.store = CredentialStore(self.dir)
        self.path = self.dir / "users" / str(UID) / "totp.json"
        self.creds_path = self.dir / "users" / str(UID) / "credentials.json"

    def tearDown(self):
        self._tmp.cleanup()

    def entry(self, secret=b"0123456789", site="example.com", account="me", uid=UID, entry_id=None):
        entry_id = entry_id or os.urandom(16)
        return TotpEntry(
            id=entry_id, sealed_secret=self.store.seal(uid, b"totp\0" + entry_id, secret),
            site=site, issuer="Example", account=account, created=time.time(),
        )

    def credential(self):
        cred_id = os.urandom(32)
        key = cose.private_key_to_bytes(cose.generate_private_key(cose.ES256))
        return Credential(
            id=cred_id, rp_id="example.com", user_id=b"u1", alg=cose.ES256,
            sealed_key=self.store.seal(UID, cred_id, key), created=time.time(),
        )

    def write_doc(self, **changes):
        doc = {"format": 1, "uid": UID, "user": USER, "require_auth": True, "entries": []}
        doc.update(changes)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(doc))

    def test_round_trip(self):
        entry = self.entry()
        entry.algorithm, entry.digits, entry.period = "SHA256", 8, 60
        self.store.totp_add(UID, USER, entry)
        [got] = self.store.totp_entries(UID, USER)
        self.assertEqual(got, entry)
        self.assertEqual(self.store.totp_unseal(UID, got), b"0123456789")
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.path.parent.stat().st_mode), 0o700)
        doc = json.loads(self.path.read_text())
        self.assertEqual((doc["format"], doc["uid"], doc["user"], doc["require_auth"]), (1, UID, USER, True))
        self.assertEqual(set(doc["entries"][0]), {
            "id", "site", "issuer", "account", "secret", "algorithm", "digits", "period", "created", "deleted",
        })
        self.assertNotIn("0123456789", self.path.read_text())

    def test_missing_file(self):
        self.assertEqual(self.store.totp_entries(UID, USER), [])
        self.assertEqual(self.store.totp_trash(UID, USER), [])
        self.assertTrue(self.store.totp_require_auth(UID, USER))
        self.assertFalse(self.path.exists())

    def test_trash_restore_purge(self):
        a, b = self.entry(), self.entry(secret=b"9876543210")
        self.store.totp_add(UID, USER, a)
        self.store.totp_add(UID, USER, b)
        moved = self.store.totp_remove(UID, USER, [a.id])
        self.assertEqual([e.id for e in moved], [a.id])
        self.assertIsNotNone(moved[0].deleted)
        self.assertEqual([e.id for e in self.store.totp_entries(UID, USER)], [b.id])
        self.assertEqual([e.id for e in self.store.totp_trash(UID, USER)], [a.id])
        self.assertEqual(self.store.totp_remove(UID, USER, [a.id]), [])  # already trashed
        self.assertEqual(self.store.totp_purge(UID, USER, [b.id]), [])  # live: not purged
        self.assertEqual([e.id for e in self.store.totp_restore(UID, USER, [a.id])], [a.id])
        self.assertEqual(len(self.store.totp_entries(UID, USER)), 2)
        self.store.totp_remove(UID, USER, [a.id])
        self.assertEqual([e.id for e in self.store.totp_purge(UID, USER, [a.id])], [a.id])
        self.assertEqual(self.store.totp_trash(UID, USER), [])
        self.assertEqual([e.id for e in self.store.totp_entries(UID, USER)], [b.id])

    def test_update(self):
        entry = self.entry()
        self.store.totp_add(UID, USER, entry)
        got = self.store.totp_update(UID, USER, entry.id, account="you")
        self.assertEqual((got.site, got.issuer, got.account), ("example.com", "Example", "you"))
        self.store.totp_update(UID, USER, entry.id, site="", issuer="New")
        [got] = self.store.totp_entries(UID, USER)
        self.assertEqual((got.site, got.issuer, got.account), ("", "New", "you"))
        with self.assertRaises(KeyError):
            self.store.totp_update(UID, USER, os.urandom(16), site="x.com")
        self.store.totp_remove(UID, USER, [entry.id])
        with self.assertRaises(KeyError):
            self.store.totp_update(UID, USER, entry.id, site="x.com")

    def test_require_auth(self):
        self.store.set_totp_require_auth(UID, USER, False, True)
        self.assertFalse(self.store.totp_require_auth(UID, USER))
        entry = self.entry()
        self.store.totp_add(UID, USER, entry)
        self.assertFalse(self.store.totp_require_auth(UID, USER))  # kept by other writes
        with self.assertRaisesRegex(StoreError, "changed meanwhile"):
            self.store.set_totp_require_auth(UID, USER, True, True)
        self.assertFalse(self.store.totp_require_auth(UID, USER))
        self.store.set_totp_require_auth(UID, USER, True, False)
        self.assertTrue(self.store.totp_require_auth(UID, USER))
        self.assertEqual(len(self.store.totp_entries(UID, USER)), 1)

    def test_require_auth_defaults_on_and_fails_closed(self):
        self.write_doc()
        doc = json.loads(self.path.read_text())
        del doc["require_auth"]
        self.path.write_text(json.dumps(doc))
        self.assertTrue(self.store.totp_require_auth(UID, USER))
        for bad in (0, "false", None, [], 1):
            self.write_doc(require_auth=bad)
            with self.assertRaises(StoreError, msg=bad):
                self.store.totp_require_auth(UID, USER)
            with self.assertRaises(StoreError):
                self.store.totp_entries(UID, USER)

    def test_format_uid_user_checks(self):
        for changes in ({"format": 2}, {"format": None}, {"uid": 1001}, {"entries": None}):
            self.write_doc(**changes)
            with self.assertRaises(StoreError, msg=changes):
                self.store.totp_entries(UID, USER)
        self.write_doc(user="bob")
        with self.assertRaisesRegex(StoreError, "belongs to user"):
            self.store.totp_entries(UID, USER)
        self.path.write_text("[")
        with self.assertRaisesRegex(StoreError, "not valid JSON"):
            self.store.totp_entries(UID, USER)
        self.path.write_text("[]")
        with self.assertRaises(StoreError):
            self.store.totp_entries(UID, USER)

    def test_malformed_entries_fail_closed(self):
        good = self.entry().to_json()
        for bad in ({**good, "deleted": "yesterday"}, {**good, "deleted": True}, {"id": good["id"]},
                    {**good, "digits": "x"}, {**good, "period": 0}, {**good, "period": 301},
                    {**good, "algorithm": "MD5"}, {**good, "digits": True}, {**good, "digits": 7},
                    {**good, "digits": "6"}, {**good, "period": 30.5}, {**good, "site": None},
                    {**good, "issuer": 1}, {**good, "account": None}, "not an object"):
            self.write_doc(entries=[bad])
            with self.assertRaisesRegex(StoreError, "malformed authenticator code", msg=bad):
                self.store.totp_entries(UID, USER)
        self.write_doc(entries=[{k: v for k, v in good.items() if k not in ("algorithm", "digits", "period")}])
        [entry] = self.store.totp_entries(UID, USER)
        self.assertEqual((entry.algorithm, entry.digits, entry.period), ("SHA1", 6, 30))

    def test_cap_counts_the_trash(self):
        with patch.object(store_module, "MAX_TOTP_PER_USER", 2):
            a, b = self.entry(), self.entry()
            self.store.totp_add(UID, USER, a)
            self.store.totp_add(UID, USER, b)
            self.store.totp_remove(UID, USER, [a.id])
            with self.assertRaises(StoreFull):
                self.store.totp_add(UID, USER, self.entry())
            self.store.totp_purge(UID, USER, [a.id])
            self.store.totp_add(UID, USER, self.entry())

    def test_import_reasons(self):
        live, trashed = self.entry(secret=b"live-secret"), self.entry(secret=b"trash-secret")
        self.store.totp_add(UID, USER, live)
        self.store.totp_add(UID, USER, trashed)
        self.store.totp_remove(UID, USER, [trashed.id])
        fresh = self.entry(secret=b"new-secret")
        same_secret = self.entry(secret=b"live-secret")  # same secret, site and account as live
        other_account = self.entry(secret=b"live-secret", account="someone else")
        live_copy = self.entry(secret=b"changed", entry_id=live.id)
        trash_copy = self.entry(secret=b"changed", entry_id=trashed.id)
        repeat = self.entry(secret=b"another", entry_id=fresh.id)
        with patch.object(store_module, "MAX_TOTP_PER_USER", 4):
            overflow = self.entry(secret=b"overflow")
            batch = [fresh, repeat, same_secret, live_copy, trash_copy, other_account, overflow]
            imported, skipped = self.store.totp_import(UID, USER, batch, dry_run=True)
            self.assertEqual([e.id for e in imported], [fresh.id, other_account.id])
            self.assertEqual([(e.id, r) for e, r in skipped], [
                (fresh.id, "duplicate in the file"),
                (same_secret.id, "already on this computer"),
                (live.id, "already on this computer"),
                (trashed.id, "in the trash on this computer"),
                (overflow.id, "store full"),
            ])
            self.assertEqual(len(self.store.totp_entries(UID, USER)), 1)  # dry run wrote nothing
            with patch.object(store_module, "_write_file", wraps=store_module._write_file) as write:
                self.store.totp_import(UID, USER, batch)
            self.assertEqual(write.call_count, 1)
        self.assertEqual({e.id for e in self.store.totp_entries(UID, USER)}, {live.id, fresh.id, other_account.id})
        self.assertEqual(self.store.totp_unseal(UID, self.store.totp_entries(UID, USER)[0]), b"live-secret")

    def test_wrong_uid_or_label_cannot_unseal(self):
        other = self.entry(uid=1001)
        with self.assertRaisesRegex(StoreError, other.id.hex()[:12]):
            self.store.totp_unseal(UID, other)
        entry_id = os.urandom(16)
        raw = TotpEntry(id=entry_id, sealed_secret=self.store.seal(UID, entry_id, b"0123456789"))
        with self.assertRaisesRegex(StoreError, "cannot be decrypted"):
            self.store.totp_unseal(UID, raw)

    def test_credentials_file_untouched_by_totp_operations(self):
        self.store.add(UID, USER, self.credential())
        original = self.creds_path.read_bytes()
        a, b = self.entry(), self.entry(secret=b"9876543210")
        steps = [
            lambda: self.store.totp_add(UID, USER, a),
            lambda: self.store.totp_import(UID, USER, [b]),
            lambda: self.store.totp_update(UID, USER, a.id, site="x.example"),
            lambda: self.store.totp_remove(UID, USER, [a.id]),
            lambda: self.store.totp_restore(UID, USER, [a.id]),
            lambda: self.store.totp_remove(UID, USER, [b.id]),
            lambda: self.store.totp_purge(UID, USER, [b.id]),
            lambda: self.store.set_totp_require_auth(UID, USER, False, True),
            lambda: self.store.totp_entries(UID, USER),
            lambda: self.store.totp_trash(UID, USER),
            lambda: self.store.totp_require_auth(UID, USER),
        ]
        for step in steps:
            step()
            self.assertEqual(self.creds_path.read_bytes(), original)

    def test_passkey_operations_leave_totp_file_alone(self):
        self.store.totp_add(UID, USER, self.entry())
        original = self.path.read_bytes()
        cred = self.credential()
        self.store.add(UID, USER, cred)
        self.store.record_use(UID, USER, cred.id)
        self.store.update_user(UID, USER, cred.id, "new", "New")
        self.store.remove(UID, USER, [cred.id])
        self.store.restore(UID, USER, [cred.id])
        self.store.remove(UID, USER, [cred.id])
        self.store.purge(UID, USER, [cred.id])
        self.store.import_credentials(UID, USER, [self.credential()])
        self.assertEqual(self.path.read_bytes(), original)
        self.assertEqual(len(self.store.credentials(UID, USER)), 1)


if __name__ == "__main__":
    unittest.main()
