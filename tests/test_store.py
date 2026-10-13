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
from localpasskey.store import (
    Credential,
    CredentialStore,
    PinState,
    StoreError,
    StoreFull,
    b64encode,
)


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

    def test_remove_trashes_and_restore_brings_back(self):
        cred = self.credential(1000)
        self.store.add(1000, "alice", cred)
        [moved] = self.store.remove(1000, "alice", [cred.id])
        self.assertEqual(moved.id, cred.id)
        self.assertIsNotNone(moved.deleted)
        self.assertEqual(self.store.credentials(1000, "alice"), [])
        self.assertEqual([c.id for c in self.store.trash(1000, "alice")], [cred.id])
        # Already trashed: a second remove is a no-op.
        self.assertEqual(self.store.remove(1000, "alice", [cred.id]), [])
        [restored] = self.store.restore(1000, "alice", [cred.id])
        self.assertIsNone(restored.deleted)
        self.assertEqual(self.store.trash(1000, "alice"), [])
        self.assertEqual([c.id for c in self.store.credentials(1000, "alice")], [cred.id])
        self.assertEqual(self.store.restore(1000, "alice", [cred.id]), [])
        self.assertEqual(self.store.purge(1000, "alice", [cred.id]), [])

    def test_trash_survives_rewrites_and_reopen(self):
        cred, other = self.credential(1000), self.credential(1000, user_id=b"u2")
        self.store.add(1000, "alice", cred)
        self.store.add(1000, "alice", other)
        self.store.remove(1000, "alice", [cred.id])
        self.store.record_use(1000, "alice", other.id)
        reopened = CredentialStore(self.dir)
        self.assertIsNone(reopened.credentials(1000, "alice")[0].deleted)
        [trashed] = reopened.trash(1000, "alice")
        self.assertEqual(trashed.id, cred.id)
        self.assertGreater(trashed.deleted, 0.0)

    def test_record_use_refuses_a_trashed_credential(self):
        cred = self.credential(1000)
        self.store.add(1000, "alice", cred)
        self.store.record_use(1000, "alice", cred.id)
        self.store.remove(1000, "alice", [cred.id])
        with self.assertRaises(KeyError):
            self.store.record_use(1000, "alice", cred.id)

    def test_add_keeps_a_trashed_credential_with_the_same_account(self):
        old, new = self.credential(1000), self.credential(1000)
        self.store.add(1000, "alice", old)
        self.store.remove(1000, "alice", [old.id])
        self.store.add(1000, "alice", new)
        self.assertEqual([c.id for c in self.store.credentials(1000, "alice")], [new.id])
        self.assertEqual([c.id for c in self.store.trash(1000, "alice")], [old.id])

    def test_capacity_counts_trashed_records_until_purged(self):
        first = self.credential(1000)
        with patch("localpasskey.store.MAX_CREDENTIALS_PER_USER", 2):
            self.store.add(1000, "alice", first)
            self.store.remove(1000, "alice", [first.id])
            self.store.add(1000, "alice", self.credential(1000, user_id=b"u2"))
            with self.assertRaises(StoreFull):
                self.store.add(1000, "alice", self.credential(1000, user_id=b"u3"))
            self.assertEqual([c.id for c in self.store.purge(1000, "alice", [first.id])], [first.id])
            self.store.add(1000, "alice", self.credential(1000, user_id=b"u3"))
            self.assertEqual(len(self.store.credentials(1000, "alice")), 2)

    def test_restore_refuses_when_a_live_passkey_was_made_since(self):
        old = self.credential(1000, rp_id="github.com")
        other = self.credential(1000, rp_id="other.org", user_id=b"u2")
        self.store.add(1000, "alice", old)
        self.store.remove(1000, "alice", [old.id])
        self.store.add(1000, "alice", self.credential(1000, rp_id="github.com"))
        path = Path(self.dir) / "users" / "1000" / "credentials.json"
        before = path.read_bytes()
        with self.assertRaises(StoreError) as caught:
            self.store.restore(1000, "alice", [old.id])
        self.assertIn("github.com", str(caught.exception))
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(len(self.store.trash(1000, "alice")), 1)
        # All-or-nothing: a second, unrelated record is not restored either.
        self.store.add(1000, "alice", other)
        self.store.remove(1000, "alice", [other.id])
        self.store.add(1000, "alice", self.credential(1000, rp_id="other.org", user_id=b"u2"))
        with self.assertRaises(StoreError):
            self.store.restore(1000, "alice", [other.id, old.id])
        self.assertEqual(len(self.store.trash(1000, "alice")), 2, "nothing was written")

    def test_restore_refuses_two_records_for_the_same_account(self):
        first = self.credential(1000, rp_id="github.com")
        self.store.add(1000, "alice", first)
        self.store.remove(1000, "alice", [first.id])
        second = self.credential(1000, rp_id="github.com")
        self.store.add(1000, "alice", second)
        self.store.remove(1000, "alice", [second.id])
        path = Path(self.dir) / "users" / "1000" / "credentials.json"
        before = path.read_bytes()
        with self.assertRaises(StoreError) as caught:
            self.store.restore(1000, "alice", [first.id, second.id])
        self.assertIn("github.com", str(caught.exception))
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(len(self.store.trash(1000, "alice")), 2, "nothing was written")
        [restored] = self.store.restore(1000, "alice", [first.id])
        self.assertEqual(restored.id, first.id)

    def test_nondiscoverable_records_restore_unconditionally(self):
        old = self.credential(1000, rp_id="github.com", discoverable=False)
        self.store.add(1000, "alice", old)
        self.store.remove(1000, "alice", [old.id])
        self.store.add(1000, "alice", self.credential(1000, rp_id="github.com"))
        [restored] = self.store.restore(1000, "alice", [old.id])
        self.assertIsNone(restored.deleted)
        self.assertEqual(len(self.store.credentials(1000, "alice")), 2)

    def test_purge_ignores_live_ids(self):
        live, trashed = self.credential(1000), self.credential(1000, user_id=b"u2")
        self.store.add(1000, "alice", live)
        self.store.add(1000, "alice", trashed)
        self.store.remove(1000, "alice", [trashed.id])
        self.assertEqual([c.id for c in self.store.purge(1000, "alice", [live.id, trashed.id])],
                         [trashed.id])
        self.assertEqual([c.id for c in self.store.credentials(1000, "alice")], [live.id])
        self.assertEqual(self.store.trash(1000, "alice"), [])

    def test_corrupt_deleted_timestamp_is_rejected(self):
        cred = self.credential(1000)
        self.store.add(1000, "alice", cred)
        path = Path(self.dir) / "users" / "1000" / "credentials.json"
        doc = json.loads(path.read_text())
        for bad in ("", "yesterday", True, False, [], {}, 10 ** 400):
            with self.subTest(deleted=bad):
                doc["credentials"][0]["deleted"] = bad
                data = json.dumps(doc).encode()
                path.write_bytes(data)
                with self.assertRaises(StoreError):
                    self.store.credentials(1000, "alice")
                self.assertEqual(path.read_bytes(), data)

    def test_the_file_is_written_as_format_2(self):
        self.store.add(1000, "alice", self.credential(1000))
        path = Path(self.dir) / "users" / "1000" / "credentials.json"
        self.assertEqual(json.loads(path.read_text())["format"], 2)

    def test_a_file_of_an_unknown_format_is_refused(self):
        cred = self.credential(1000)
        self.store.add(1000, "alice", cred)
        path = Path(self.dir) / "users" / "1000" / "credentials.json"
        doc = json.loads(path.read_text())
        for bad in (0, 3, "2", None):
            with self.subTest(format=bad):
                path.write_text(json.dumps(doc | {"format": bad}))
                with self.assertRaises(StoreError):
                    self.store.credentials(1000, "alice")

    def test_a_format_1_file_without_deleted_loads_live(self):
        cred = self.credential(1000)
        self.store.add(1000, "alice", cred)
        path = Path(self.dir) / "users" / "1000" / "credentials.json"
        doc = json.loads(path.read_text())
        del doc["credentials"][0]["deleted"]
        path.write_bytes(json.dumps(doc | {"format": 1}).encode())
        [loaded] = self.store.credentials(1000, "alice")
        self.assertIsNone(loaded.deleted)
        self.assertEqual(loaded.id, cred.id)
        # Writing it back upgrades the file rather than keeping format 1, so a
        # 0.1.1 daemon cannot load trashed passkeys as live afterwards.
        self.store.remove(1000, "alice", [cred.id])
        self.assertEqual(json.loads(path.read_text())["format"], 2)

    def test_update_user_renames_a_live_credential_only(self):
        cred = self.credential(1000)
        self.store.add(1000, "alice", cred)
        self.store.update_user(1000, "alice", cred.id, "New Name", "New Display")
        [loaded] = self.store.credentials(1000, "alice")
        self.assertEqual((loaded.user_name, loaded.user_display_name), ("New Name", "New Display"))
        with self.assertRaises(KeyError):
            self.store.update_user(1000, "alice", os.urandom(32), "x", "x")
        self.store.remove(1000, "alice", [cred.id])
        with self.assertRaises(KeyError):
            self.store.update_user(1000, "alice", cred.id, "x", "x")

    def test_pin_round_trip_and_delete(self):
        state = PinState(hash=bytes(range(16)), retries=5)
        self.assertIsNone(self.store.pin(1000, "alice"))
        self.store.set_pin(1000, "alice", state)
        self.assertEqual(self.store.pin(1000, "alice"), state)
        self.assertEqual(self.mode("users", "1000", "pin.json"), 0o600)
        self.store.set_pin(1000, "alice", PinState(hash=b"\x00" * 16, retries=8))
        self.assertEqual(self.store.pin(1000, "alice").retries, 8)
        self.store.set_pin(1000, "alice", None)
        self.assertIsNone(self.store.pin(1000, "alice"))
        self.store.set_pin(1000, "alice", None)  # a missing file is fine

    def test_pin_file_is_bound_to_its_user_and_master_key(self):
        self.store.set_pin(1000, "alice", PinState(hash=b"h" * 16, retries=8))
        path = Path(self.dir) / "users" / "1000" / "pin.json"
        with self.assertRaises(StoreError):
            self.store.pin(1000, "mallory")
        self.assertIsNone(self.store.pin(1001, "alice"), "another user has no PIN file")
        doc = json.loads(path.read_text())
        self.assertEqual(doc["format"], 1)
        self.assertEqual((doc["uid"], doc["user"]), (1000, "alice"))
        for bad in (doc | {"pin": "AAAA"}, doc | {"retries": "many"}, {"format": 1, "uid": 1000}, None):
            with self.subTest(document=bad), self.assertRaises((StoreError, TypeError)):
                path.write_bytes(json.dumps(bad).encode())
                self.store.pin(1000, "alice")
        # A blob sealed for another uid must not open either.
        path.write_bytes(json.dumps(
            doc | {"pin": b64encode(self.store.seal(1001, b"clientPin", b"h" * 16))}
        ).encode())
        with self.assertRaises(StoreError):
            self.store.pin(1000, "alice")


if __name__ == "__main__":
    unittest.main()
