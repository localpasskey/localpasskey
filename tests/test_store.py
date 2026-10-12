import json
import os
import stat
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from localpasskey import cose
from localpasskey.store import Credential, CredentialStore, StoreError, StoreFull


class StoreTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = self._tmp.name
        self.store = CredentialStore(self.dir)

    def tearDown(self):
        self._tmp.cleanup()

    def credential(self, uid, rp_id="example.com", user_id=b"u1", discoverable=True):
        key = cose.generate_private_key(cose.ES256)
        cred_id = os.urandom(32)
        return Credential(
            id=cred_id, rp_id=rp_id, user_id=user_id, alg=cose.ES256,
            sealed_key=self.store.seal(uid, cred_id, cose.private_key_to_bytes(key)),
            discoverable=discoverable, created=time.time(),
        )

    def mode(self, *parts):
        return stat.S_IMODE(os.stat(os.path.join(self.dir, *parts)).st_mode)

    def test_files_are_private(self):
        self.store.add(1000, "alice", self.credential(1000))
        self.assertEqual(self.mode("master.key"), 0o600)
        self.assertEqual(self.mode("users"), 0o700)
        self.assertEqual(self.mode("users", "1000"), 0o700)
        self.assertEqual(self.mode("users", "1000", "credentials.json"), 0o600)

    def test_users_have_separate_stores(self):
        self.store.add(1000, "alice", self.credential(1000))
        self.store.add(1001, "bob", self.credential(1001))
        self.store.add(1001, "bob", self.credential(1001, user_id=b"u2"))
        self.assertEqual(len(self.store.credentials(1000, "alice")), 1)
        self.assertEqual(len(self.store.credentials(1001, "bob")), 2)

    def test_master_key_and_credentials_survive_a_restart(self):
        cred = self.credential(1000)
        self.store.add(1000, "alice", cred)
        reopened = CredentialStore(self.dir)
        [loaded] = reopened.credentials(1000, "alice")
        self.assertEqual(loaded, cred)
        cose.private_key_from_bytes(reopened.unseal(1000, loaded))

    def test_sealed_keys_are_bound_to_their_owner(self):
        cred = self.credential(1000)
        with self.assertRaises(StoreError):
            self.store.unseal(1001, cred)

    def test_sealed_keys_reject_id_changes_and_corruption(self):
        cred = self.credential(1000)
        for altered in (
            replace(cred, id=os.urandom(32)),
            replace(cred, sealed_key=cred.sealed_key[:-1] + bytes([cred.sealed_key[-1] ^ 1])),
            replace(cred, sealed_key=b""),
            replace(cred, sealed_key=cred.sealed_key[:8]),
        ):
            with self.subTest(length=len(altered.sealed_key)), self.assertRaises(StoreError):
                self.store.unseal(1000, altered)

    def test_corrupt_documents_are_rejected_without_overwriting(self):
        cred = self.credential(1000)
        self.store.add(1000, "alice", cred)
        path = Path(self.dir) / "users" / "1000" / "credentials.json"
        valid = json.loads(path.read_text())
        for doc in (None, [], "bad", valid | {"credentials": {}}, valid | {"credentials": ""}):
            with self.subTest(document=doc):
                data = json.dumps(doc).encode()
                path.write_bytes(data)
                with self.assertRaises(StoreError):
                    self.store.add(1000, "alice", self.credential(1000, user_id=b"other"))
                self.assertEqual(path.read_bytes(), data)

    def test_capacity_allows_replacement_but_preserves_other_credentials(self):
        first = self.credential(1000)
        other = self.credential(1000, user_id=b"u2")
        replacement = self.credential(1000)
        with patch("localpasskey.store.MAX_CREDENTIALS_PER_USER", 2):
            self.store.add(1000, "alice", first)
            self.store.add(1000, "alice", other)
            with self.assertRaises(StoreFull):
                self.store.add(1000, "alice", self.credential(1000, user_id=b"u3"))
            self.assertEqual(self.store.credentials(1000, "alice"), [first, other])
            self.store.add(1000, "alice", replacement)
            self.assertEqual(self.store.credentials(1000, "alice"), [other, replacement])

    def test_all_key_algorithms_survive_storage(self):
        for alg in cose.SUPPORTED_ALGORITHMS:
            with self.subTest(alg=alg):
                key = cose.generate_private_key(alg)
                serialized = cose.private_key_to_bytes(key)
                cred = self.credential(1000, user_id=str(alg).encode())
                cred = replace(cred, alg=alg, sealed_key=self.store.seal(1000, cred.id, serialized))
                self.store.add(1000, "alice", cred)
                loaded = CredentialStore(self.dir).credentials(1000, "alice")[-1]
                restored = cose.private_key_from_bytes(self.store.unseal(1000, loaded))
                self.assertEqual(cose.public_key(restored, alg), cose.public_key(key, alg))

    def test_reused_uid_does_not_inherit_passkeys(self):
        self.store.add(1000, "alice", self.credential(1000))
        with self.assertRaises(StoreError):
            self.store.credentials(1000, "mallory")
        with self.assertRaises(StoreError):
            self.store.add(1000, "mallory", self.credential(1000))

    def test_record_use_and_delete(self):
        cred = self.credential(1000)
        self.store.add(1000, "alice", cred)
        self.store.record_use(1000, "alice", cred.id)
        [loaded] = self.store.credentials(1000, "alice")
        self.assertIsNotNone(loaded.last_used)
        self.assertEqual(len(self.store.remove(1000, "alice", [cred.id])), 1)
        self.assertEqual(self.store.credentials(1000, "alice"), [])
        with self.assertRaises(KeyError):
            self.store.record_use(1000, "alice", cred.id)

    def test_record_use_skips_rewrite_within_resolution(self):
        cred = self.credential(1000)
        self.store.add(1000, "alice", cred)
        with patch("localpasskey.store.time.time", return_value=1000.0):
            self.store.record_use(1000, "alice", cred.id)
        with patch("localpasskey.store.time.time", return_value=1030.0):
            self.store.record_use(1000, "alice", cred.id)
        self.assertEqual(self.store.credentials(1000, "alice")[0].last_used, 1000.0)
        with patch("localpasskey.store.time.time", return_value=1060.0):
            self.store.record_use(1000, "alice", cred.id)
        self.assertEqual(self.store.credentials(1000, "alice")[0].last_used, 1060.0)
        with patch("localpasskey.store.time.time", return_value=500.0):
            self.store.record_use(1000, "alice", cred.id)  # clock stepped back
        self.assertEqual(self.store.credentials(1000, "alice")[0].last_used, 500.0)

    def test_failed_sync_keeps_previous_credentials(self):
        cred = self.credential(1000)
        self.store.add(1000, "alice", cred)
        with patch("localpasskey.store.os.fsync", side_effect=OSError("disk error")):
            with self.assertRaises(OSError):
                self.store.add(1000, "alice", self.credential(1000, user_id=b"u2"))
        self.assertEqual(CredentialStore(self.dir).credentials(1000, "alice"), [cred])


if __name__ == "__main__":
    unittest.main()
