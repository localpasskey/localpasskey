import errno
import json
import os
import pwd
import socket
import tempfile
import threading
import time
import unittest

from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import rsa

from localpasskey import client, cose
from localpasskey.clientpin import MAX_PIN_RETRIES
from localpasskey.control import MAX_REQUEST, ControlError, ControlServer, record
from localpasskey.ctap2 import Verdict
from localpasskey.polkit import ACTION_EXPORT, ACTION_MANAGE
from localpasskey.store import Credential, CredentialStore, StoreError, b64encode
from localpasskey.store import b64decode as store_b64decode


class FakePolkit:
    def __init__(self, verdict):
        self.verdict = verdict
        self.checks = []

    def check(self, subject, action_id, message, cancelled=None, timeout=120.0):
        self.checks.append((subject[0], action_id, message))
        return self.verdict


class FakeNotifier:
    def __init__(self, fail=False):
        self.fail = fail
        self.notes = []
        self.uids = []

    def notify(self, requester, summary, body, kind):
        if self.fail:
            raise OSError("no session bus")
        self.uids.append(requester.uid)
        self.notes.append((summary, body, kind))


class ControlTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.store = CredentialStore(self._tmp.name)
        self.uid = os.getuid()
        self.name = pwd.getpwuid(self.uid).pw_name
        self.polkit = FakePolkit(Verdict.APPROVED)
        self.server = ControlServer(
            os.path.join(self._tmp.name, "control.sock"), self.store, self.polkit, lambda: {"version": "test"}
        )
        self.creds = [self.add("example.com", b"a"), self.add("example.com", b"b"), self.add("other.org", b"c")]

    def tearDown(self):
        self.server.stop()
        self._tmp.cleanup()

    def add(self, rp_id, user_id):
        key = cose.generate_private_key(cose.ES256)
        cred_id = os.urandom(32)
        cred = Credential(
            id=cred_id, rp_id=rp_id, user_id=user_id, alg=cose.ES256,
            sealed_key=self.store.seal(self.uid, cred_id, cose.private_key_to_bytes(key)),
            user_name=user_id.decode(), created=time.time(),
        )
        self.store.add(self.uid, self.name, cred)
        return cred

    def handle(self, request):
        return self.server.handle(request, os.getpid(), self.uid)

    def normalized(self, alg=cose.ES256, **overrides):
        """A normalized record for the import command, as export would send it."""
        key = cose.generate_private_key(alg if alg in cose.SUPPORTED_ALGORITHMS else cose.ES256)
        cred_id = overrides.pop("id", os.urandom(32))
        data = {
            "id": b64encode(cred_id) if isinstance(cred_id, bytes) else cred_id,
            "rp_id": "imported.example",
            "rp_name": "Imported",
            "user_id": b64encode(os.urandom(16)),
            "user_name": "u",
            "user_display_name": "U",
            "alg": alg,
            "private_key": b64encode(cose.private_key_to_bytes(key)),
            "discoverable": True,
            "cred_protect": 1,
            "created": 1700000000.0,
        }
        data.update(overrides)
        return data

    def test_list(self):
        listing = self.handle({"command": "list"})
        self.assertEqual(listing["user"], self.name)
        self.assertEqual({c["site"] for c in listing["credentials"]}, {"example.com", "other.org"})

    def test_only_root_may_look_at_other_users(self):
        if self.uid == 0:
            self.skipTest("running as root")
        with self.assertRaises(ControlError):
            self.handle({"command": "list", "user": "root"})

    def test_delete_requires_authentication(self):
        prefix = self.creds[0].id.hex()[:8]
        preview = self.handle({"command": "delete", "ids": [prefix], "dry_run": True})
        self.assertEqual(len(preview["deleted"]), 1)
        self.assertEqual(self.polkit.checks, [])

        self.polkit.verdict = Verdict.DENIED
        with self.assertRaises(ControlError):
            self.handle({"command": "delete", "ids": [prefix]})
        self.assertEqual(len(self.store.credentials(self.uid, self.name)), 3)

        self.polkit.verdict = Verdict.APPROVED
        self.handle({"command": "delete", "ids": [prefix]})
        self.assertEqual(self.polkit.checks[-1][:2], ("unix-process", ACTION_MANAGE))
        self.assertEqual(len(self.store.credentials(self.uid, self.name)), 2)

    def test_deletion_is_reported_to_the_owner(self):
        notifier = FakeNotifier()
        self.server.notifier = notifier
        self.polkit.verdict = Verdict.DENIED
        with self.assertRaises(ControlError):
            self.handle({"command": "delete", "site": "example.com"})
        self.handle({"command": "delete", "ids": [self.creds[2].id.hex()], "dry_run": True})
        self.assertEqual(notifier.notes, [], "nothing deleted, nothing to report")

        self.polkit.verdict = Verdict.APPROVED
        self.handle({"command": "delete", "ids": [self.creds[2].id.hex()]})
        self.assertEqual(
            notifier.notes[-1],
            ("Passkey moved to the trash",
             "The passkey for other.org was moved to the trash from this computer.", "activity"),
        )
        self.handle({"command": "delete", "site": "example.com"})
        self.assertEqual(
            notifier.notes[-1],
            ("Passkeys moved to the trash",
             "2 passkeys for example.com were moved to the trash from this computer.", "activity"),
        )
        self.assertEqual(notifier.uids, [self.uid, self.uid])

    def test_deletion_notice_names_the_administrator_and_shortens_long_lists(self):
        notifier = FakeNotifier()
        self.server.notifier = notifier
        many = self.creds + [self.add(f"site{n}.example", b"x") for n in range(2)]
        self.server._notify_change(self.uid, many, caller_uid=self.uid + 1, what="moved to the trash")
        self.assertEqual(notifier.notes, [(
            "Passkeys moved to the trash",
            "5 passkeys for example.com, other.org, site0.example, … were moved to the trash from this "
            "computer by the administrator.",
            "activity",
        )])

    def test_deletion_notice_lists_only_what_was_still_there(self):
        notifier = FakeNotifier()
        self.server.notifier = notifier

        def deleting_meanwhile(cred):
            def check(subject, action_id, message, cancelled=None, timeout=120.0):
                self.store.remove(self.uid, self.name, [cred.id])  # e.g. from the GUI
                return Verdict.APPROVED
            return check

        self.polkit.check = deleting_meanwhile(self.creds[0])
        deleted = self.handle({"command": "delete", "site": "example.com"})["deleted"]
        self.assertEqual([d["id"] for d in deleted], [self.creds[1].id.hex()])
        self.assertEqual(notifier.notes[-1][0], "Passkey moved to the trash")

        self.polkit.check = deleting_meanwhile(self.creds[2])
        self.assertEqual(self.handle({"command": "delete", "ids": [self.creds[2].id.hex()]})["deleted"], [])
        self.assertEqual(len(notifier.notes), 1, "nothing was deleted by this request")

    def test_notifier_failure_does_not_undo_deletion(self):
        self.server.notifier = FakeNotifier(fail=True)
        self.assertEqual(len(self.handle({"command": "delete", "all": True})["deleted"]), 3)

    def test_delete_by_site(self):
        deleted = self.handle({"command": "delete", "site": "example.com"})["deleted"]
        self.assertEqual(len(deleted), 2)
        self.assertIn("Move 2 passkeys", self.polkit.checks[-1][2])
        self.assertIn("to the trash", self.polkit.checks[-1][2])
        [left] = self.store.credentials(self.uid, self.name)
        self.assertEqual(left.rp_id, "other.org")

    def test_delete_moves_to_the_trash(self):
        before = time.time()
        [deleted] = self.handle({"command": "delete", "ids": [self.creds[0].id.hex()]})["deleted"]
        self.assertEqual(deleted["site"], "example.com")
        self.assertGreaterEqual(deleted["deleted"], before)
        self.assertEqual([c.id for c in self.store.trash(self.uid, self.name)], [self.creds[0].id])
        self.assertEqual(len(self.store.credentials(self.uid, self.name)), 2)

    def test_list_of_the_trash_reports_what_was_deleted(self):
        self.handle({"command": "delete", "ids": [self.creds[1].id.hex()]})
        listing = self.handle({"command": "list", "trash": True})
        self.assertEqual(listing["user"], self.name)
        [trashed] = listing["credentials"]
        self.assertEqual(trashed["id"], self.creds[1].id.hex())
        self.assertIsNotNone(trashed["deleted"])
        self.assertIsNone(self.handle({"command": "list"})["credentials"][0]["deleted"])
        for bad in ("true", 1, [], "no"):
            with self.subTest(trash=bad), self.assertRaises(ControlError):
                self.handle({"command": "list", "trash": bad})

    def test_restore_brings_a_trashed_passkey_back(self):
        self.handle({"command": "delete", "ids": [self.creds[0].id.hex()]})
        preview = self.handle({"command": "restore", "ids": [self.creds[0].id.hex()], "dry_run": True})
        self.assertEqual([c["id"] for c in preview["deleted"]], [self.creds[0].id.hex()])
        self.polkit.checks.clear()
        restored = self.handle({"command": "restore", "all": True})["restored"]
        self.assertEqual(len(restored), 1)
        self.assertIsNone(restored[0]["deleted"])
        self.assertEqual(len(self.store.credentials(self.uid, self.name)), 3)
        self.assertEqual(self.store.trash(self.uid, self.name), [])
        self.assertEqual(self.polkit.checks[-1][2], "Restore 1 passkey from the trash?")

    def test_restore_conflict_becomes_an_error_reply(self):
        self.server.start()
        self.handle({"command": "delete", "ids": [self.creds[0].id.hex()]})
        self.add("example.com", b"a")  # a newer passkey for the same site and account
        with self.assertRaisesRegex(client.ServiceError, "newer passkey for this account on example.com"):
            client.request({"command": "restore", "all": True}, self.server.path)
        self.assertEqual(len(self.store.credentials(self.uid, self.name)), 3)
        self.assertEqual(len(self.store.trash(self.uid, self.name)), 1)

    def test_restore_from_an_empty_trash_is_refused(self):
        with self.assertRaises(ControlError):
            self.handle({"command": "restore", "all": True})
        self.assertEqual(self.polkit.checks, [])

    def test_purge_deletes_one_trashed_passkey_for_good(self):
        self.handle({"command": "delete", "ids": [self.creds[0].id.hex()]})
        prefix = self.creds[0].id.hex()[:8]
        preview = self.handle({"command": "purge", "ids": [prefix], "dry_run": True})
        self.assertEqual([c["id"] for c in preview["deleted"]], [self.creds[0].id.hex()])
        purged = self.handle({"command": "purge", "ids": [prefix]})["purged"]
        self.assertEqual([c["id"] for c in purged], [self.creds[0].id.hex()])
        self.assertEqual(self.store.trash(self.uid, self.name), [])
        self.assertEqual(len(self.store.credentials(self.uid, self.name)), 2)
        self.assertEqual(self.polkit.checks[-1][2],
                         "Permanently delete the passkey for example.com? This cannot be undone.")

    def test_purge_refuses_anything_but_one_id(self):
        self.handle({"command": "delete", "all": True})
        self.polkit.checks.clear()
        both = [self.creds[0].id.hex(), self.creds[1].id.hex()]
        for request in ({"ids": both}, {"all": True}, {"site": "example.com"}, {}):
            with self.subTest(request=request), self.assertRaises(ControlError):
                self.handle({"command": "purge", **request})
        with self.assertRaisesRegex(ControlError, "one passkey at a time"):
            self.handle({"command": "purge", "ids": both})
        self.assertEqual(self.polkit.checks, [])
        self.assertEqual(len(self.store.trash(self.uid, self.name)), 3)

    def test_purge_never_touches_a_live_passkey(self):
        self.handle({"command": "delete", "ids": [self.creds[0].id.hex()]})
        with self.assertRaises(ControlError):
            self.handle({"command": "purge", "ids": [self.creds[1].id.hex()]})
        self.assertEqual(len(self.store.credentials(self.uid, self.name)), 2)
        self.assertEqual(len(self.store.trash(self.uid, self.name)), 1)

    def test_purge_is_reported_to_the_owner(self):
        notifier = FakeNotifier()
        self.server.notifier = notifier
        self.handle({"command": "delete", "ids": [self.creds[2].id.hex()]})
        self.handle({"command": "purge", "ids": [self.creds[2].id.hex()]})
        self.assertEqual(
            notifier.notes[-1],
            ("Passkey permanently deleted",
             "The passkey for other.org was permanently deleted from this computer.", "activity"),
        )

    def test_pin_status_set_and_remove(self):
        status = self.handle({"command": "pin", "action": "status"})
        self.assertEqual(status, {"ok": True, "user": self.name, "set": False, "retries": MAX_PIN_RETRIES})
        self.assertEqual(self.polkit.checks, [], "reading the PIN state needs no approval")

        self.polkit.verdict = Verdict.DENIED
        with self.assertRaises(ControlError):
            self.handle({"command": "pin", "action": "set", "pin": "1234"})
        self.assertEqual(self.handle({"command": "pin", "action": "status"})["set"], False)

        self.polkit.verdict = Verdict.APPROVED
        self.assertEqual(self.handle({"command": "pin", "action": "set", "pin": "1234"}), {"ok": True})
        self.assertEqual(self.polkit.checks[-1][2],
                         "Set a new PIN for the passkeys stored on this computer?")
        status = self.handle({"command": "pin", "action": "status"})
        self.assertEqual((status["set"], status["retries"]), (True, MAX_PIN_RETRIES))

        self.handle({"command": "pin", "action": "remove"})
        self.assertEqual(self.polkit.checks[-1][2],
                         "Remove the PIN for the passkeys stored on this computer?")
        self.assertEqual(self.handle({"command": "pin", "action": "status"})["set"], False)

    def test_pin_policy_and_action_errors(self):
        for pin in ("123", "x" * 64, "12\0" + "x" * 10, 1234, None):
            with self.subTest(pin=pin), self.assertRaises(ControlError):
                self.handle({"command": "pin", "action": "set", "pin": pin})
        with self.assertRaisesRegex(ControlError, "PIN must be at least 4 characters"):
            self.handle({"command": "pin", "action": "set", "pin": "123"})
        for action in ("get", "", None):
            with self.subTest(action=action), self.assertRaises(ControlError):
                self.handle({"command": "pin", "action": action})
        self.assertFalse(self.server.pins.is_set(self.uid, self.name))

    def test_export_needs_authentication_and_reports_what_it_exported(self):
        notifier = FakeNotifier()
        self.server.notifier = notifier
        prefix = self.creds[0].id.hex()[:8]
        preview = self.handle({"command": "export", "ids": [prefix], "dry_run": True})
        self.assertEqual([c["id"] for c in preview["exported"]], [self.creds[0].id.hex()])
        self.assertEqual(self.polkit.checks, [], "a dry run shows no keys and asks nothing")

        self.polkit.verdict = Verdict.DENIED
        with self.assertRaisesRegex(ControlError, "not exported"):
            self.handle({"command": "export", "ids": [prefix]})
        self.assertEqual(notifier.notes, [])

        self.polkit.verdict = Verdict.APPROVED
        reply = self.handle({"command": "export", "ids": [prefix]})
        self.assertEqual(self.polkit.checks[-1][:2], ("unix-process", ACTION_EXPORT))
        self.assertEqual(
            self.polkit.checks[-1][2],
            "Export 1 passkey stored on this computer? Whoever gets the exported file and its "
            "passphrase can sign in as you.",
        )
        [record_] = reply["credentials"]
        self.assertEqual(record_["id"], b64encode(self.creds[0].id))
        self.assertEqual(record_["rp_id"], "example.com")
        self.assertEqual(record_["alg"], cose.ES256)
        self.assertEqual(record_["private_key"],
                         b64encode(cose.private_key_to_bytes(
                             cose.private_key_from_bytes(
                                 self.store.unseal(self.uid, self.creds[0])))))
        self.assertEqual(notifier.notes[-1],
                         ("Passkey exported",
                          "The passkey for example.com was exported from this computer.", "activity"))

    def test_export_never_includes_trashed_passkeys(self):
        self.store.remove(self.uid, self.name, [self.creds[0].id])
        reply = self.handle({"command": "export", "all": True, "dry_run": True})
        self.assertEqual({c["site"] for c in reply["exported"]}, {"example.com", "other.org"})
        with self.assertRaises(ControlError):
            self.handle({"command": "export", "ids": [self.creds[0].id.hex()], "dry_run": True})

    def test_import_dry_run_plans_without_asking_or_storing(self):
        records = [self.normalized(), self.normalized()]
        plan = self.handle({"command": "import", "credentials": records, "dry_run": True})
        self.assertEqual([c["site"] for c in plan["imported"]], ["imported.example"] * 2)
        self.assertEqual(plan["skipped"], [])
        self.assertEqual(self.polkit.checks, [])
        self.assertEqual(len(self.store.credentials(self.uid, self.name)), 3)

    def test_import_asks_once_and_stores_the_passkeys(self):
        notifier = FakeNotifier()
        self.server.notifier = notifier
        records = [self.normalized(), self.normalized()]
        self.polkit.verdict = Verdict.DENIED
        with self.assertRaisesRegex(ControlError, "not imported"):
            self.handle({"command": "import", "credentials": records})
        self.assertEqual(len(self.store.credentials(self.uid, self.name)), 3)
        self.assertEqual(notifier.notes, [])

        self.polkit.verdict = Verdict.APPROVED
        reply = self.handle({"command": "import", "credentials": records})
        self.assertEqual(self.polkit.checks[-1][:2], ("unix-process", ACTION_MANAGE))
        self.assertEqual(self.polkit.checks[-1][2], "Import 2 passkeys into this computer?")
        self.assertEqual(len(reply["imported"]), 2)
        self.assertEqual(reply["skipped"], [])
        stored = self.store.credentials(self.uid, self.name)[-2:]
        self.assertEqual([c.rp_id for c in stored], ["imported.example"] * 2)
        self.assertEqual([c.created for c in stored], [1700000000.0] * 2)
        self.assertEqual(notifier.notes[-1],
                         ("Passkeys imported",
                          "2 passkeys for imported.example were imported into this computer.", "activity"))

    def test_import_of_nothing_new_never_asks(self):
        records = [self.normalized(rp_id="example.com", user_id=b64encode(b"a"), created=0)]
        reply = self.handle({"command": "import", "credentials": records})
        self.assertEqual(self.polkit.checks, [], "nothing to import, nothing to ask")
        self.assertEqual(reply["imported"], [])
        [skipped] = reply["skipped"]
        self.assertEqual(skipped["reason"], "a passkey for this account already exists")
        self.assertEqual(skipped["credential"]["site"], "example.com")

    def test_import_reports_every_skip_reason(self):
        trashed = self.add("gone.example", b"t")
        self.store.remove(self.uid, self.name, [trashed.id])
        live_id = self.creds[0].id
        fresh = self.normalized(rp_id="fresh.example", user_id=b64encode(b"f"))
        fresh_id = fresh["id"]
        records = [
            self.normalized(id=live_id, rp_id="elsewhere.example"),
            self.normalized(id=trashed.id, rp_id="elsewhere.example"),
            self.normalized(rp_id="example.com", user_id=b64encode(b"a")),
            fresh,
            self.normalized(id=fresh_id, rp_id="dup.example"),
            self.normalized(rp_id="fresh.example", user_id=b64encode(b"f")),
        ]
        plan = self.handle({"command": "import", "credentials": records, "dry_run": True})
        reply = self.handle({"command": "import", "credentials": records})
        self.assertEqual(plan, reply)
        self.assertEqual([c["id"] for c in reply["imported"]], [store_b64decode(fresh_id).hex()])
        self.assertEqual([(s["credential"]["site"], s["reason"]) for s in reply["skipped"]], [
            ("elsewhere.example", "already on this computer"),
            ("elsewhere.example", "in the trash on this computer"),
            ("example.com", "a passkey for this account already exists"),
            ("dup.example", "duplicate in the file"),
            ("fresh.example", "another passkey in the file is for the same account"),
        ])
        self.assertEqual(self.polkit.checks[-1][2], "Import 1 passkey into this computer?")

    def test_import_skips_records_the_capacity_cannot_hold(self):
        records = [self.normalized(rp_id=f"site{n}.example", id=b"id%d" % n) for n in range(3)]
        with patch("localpasskey.store.MAX_CREDENTIALS_PER_USER", 4):
            reply = self.handle({"command": "import", "credentials": records})
        self.assertEqual(len(reply["imported"]), 1)
        self.assertEqual([s["reason"] for s in reply["skipped"]], ["store full"] * 2)

    def test_import_re_seals_keys_for_the_target_uid(self):
        [stored] = self.handle({"command": "import", "credentials": [self.normalized()]})["imported"]
        cred = self.store.credentials(self.uid, self.name)[-1]
        self.assertEqual(cred.id.hex(), stored["id"])
        self.assertEqual(cose.private_key_from_bytes(self.store.unseal(self.uid, cred)).key_size, 256)
        with self.assertRaises(StoreError):
            self.store.unseal(self.uid + 1, cred)

    def test_import_validates_records_strictly(self):
        for overrides in [
            {"id": "not base64!!"},
            {"id": ""},
            {"id": b64encode(b"x" * 513)},
            {"user_id": b64encode(b"x" * 65)},
            {"user_id": 5},
            {"rp_id": ""},
            {"rp_id": "a" * 254},
            {"rp_id": "exa mple.com"},
            {"rp_id": "exa\nmple.com"},
            {"rp_name": "x" * 256},
            {"alg": -35},
            {"alg": "ES256"},
            {"alg": True},
            {"private_key": "AAAA"},
            {"private_key": 3},
            {"discoverable": "yes"},
            {"cred_protect": 0},
            {"cred_protect": 4},
            {"created": "yesterday"},
        ]:
            # The error names the offending record, here the second.
            records = [self.normalized(), self.normalized(**overrides)]
            with self.subTest(overrides=overrides), self.assertRaisesRegex(ControlError, "^passkey 2: "):
                self.handle({"command": "import", "credentials": records})
        for request in ({"command": "import"}, {"command": "import", "credentials": {}},
                        {"command": "import", "credentials": ["x"]},
                        {"command": "import", "credentials": [], "dry_run": "yes"}):
            with self.subTest(request=request), self.assertRaises(ControlError):
                self.handle(request)
        self.assertEqual(self.store.credentials(self.uid, self.name), self.creds)
        self.assertEqual(self.polkit.checks, [], "bad records are refused before any prompt")

    def test_import_refuses_a_key_that_does_not_match_its_algorithm(self):
        for alg, other in ((cose.ES256, cose.EDDSA), (cose.EDDSA, cose.RS256), (cose.RS256, cose.ES256)):
            with self.subTest(alg=alg):
                key = cose.generate_private_key(other)
                record_ = self.normalized(alg=alg, private_key=b64encode(cose.private_key_to_bytes(key)))
                with self.assertRaisesRegex(ControlError, "not a valid"):
                    self.handle({"command": "import", "credentials": [record_]})
        small = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        with self.assertRaisesRegex(ControlError, "not a valid RS256 key"):
            self.handle({"command": "import", "credentials": [
                self.normalized(alg=cose.RS256, private_key=b64encode(cose.private_key_to_bytes(small)))]})

    def test_import_refuses_oversized_rsa_keys_and_too_many_records(self):
        big = rsa.generate_private_key(public_exponent=65537, key_size=4160)
        with self.assertRaisesRegex(ControlError, "not a valid RS256 key"):
            self.handle({"command": "import", "dry_run": True, "credentials": [
                self.normalized(alg=cose.RS256, private_key=b64encode(cose.private_key_to_bytes(big)))]})
        records = [self.normalized(rp_id=f"site{n}.example", id=b"id%d" % n) for n in range(3)]
        with patch("localpasskey.control.MAX_CREDENTIALS_PER_USER", 2), \
                patch("localpasskey.control._parse_record") as parse:
            with self.assertRaisesRegex(ControlError, "at most 2 passkeys"):
                self.handle({"command": "import", "dry_run": True, "credentials": records})
        parse.assert_not_called()

    def test_import_accepts_every_algorithm(self):
        for alg in cose.SUPPORTED_ALGORITHMS:
            with self.subTest(alg=alg):
                reply = self.handle({"command": "import", "credentials": [self.normalized(alg=alg)]})
                self.assertEqual(len(reply["imported"]), 1)
                self.assertEqual(reply["imported"][0]["algorithm"], cose.ALGORITHM_NAMES[alg])

    def test_import_keeps_a_sane_creation_time_and_replaces_an_insane_one(self):
        now = time.time()
        reply = self.handle({"command": "import", "credentials": [
            self.normalized(rp_id="old.example", id=b"old", created=100.0),
            self.normalized(rp_id="future.example", id=b"new", created=now + 86400 * 365),
        ]})
        created = {c["site"]: c["created"] for c in reply["imported"]}
        self.assertEqual(created["old.example"], 100.0)
        self.assertAlmostEqual(created["future.example"], now, delta=30)

    def test_an_import_of_a_full_store_of_rsa_passkeys_fits_in_one_request(self):
        rsa_record = self.normalized(alg=cose.RS256, user_id=b64encode(b"u" * 64),
                                     rp_id="x" * 253, rp_name="n" * 255, user_name="n" * 255,
                                     user_display_name="n" * 255)
        request = {"command": "import", "credentials": [rsa_record] * 4096}
        self.assertLess(len(json.dumps(request)) + 1, MAX_REQUEST)

    def test_bad_selectors(self):
        for request in ({"ids": ["ab"]}, {"ids": ["ffffffffffff"]}, {"site": "nowhere.test"}, {}):
            with self.subTest(request), self.assertRaises(ControlError):
                self.handle({"command": "delete", **request})

    def test_malformed_or_conflicting_delete_selectors_never_delete(self):
        for selector in (
            {"all": "false"}, {"all": 1}, {"all": True, "site": "example.com"},
            {"all": True, "ids": [self.creds[0].id.hex()]}, {"ids": self.creds[0].id.hex()},
            {"ids": [12345]}, {"site": ["example.com"]}, {"all": True, "dry_run": "false"},
        ):
            with self.subTest(selector=selector), self.assertRaises(ControlError):
                self.handle({"command": "delete", **selector})
        self.assertEqual(len(self.store.credentials(self.uid, self.name)), 3)
        self.assertEqual(self.polkit.checks, [])

    def test_invalid_json_and_non_object_requests_return_errors(self):
        self.server.start()
        for data in (b"not json\n", b"[]\n", b"null\n", b"1\n", b"\xff\n"):
            with self.subTest(data=data), socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(2)
                sock.connect(self.server.path)
                sock.sendall(data)
                with sock.makefile("rb") as stream:
                    response = json.loads(stream.readline())
                self.assertFalse(response["ok"])
        self.assertEqual(len(client.request({"command": "list"}, self.server.path)["credentials"]), 3)

    def test_client_handles_malformed_service_replies(self):
        reply = [b"not json\n"]

        def invalid_reply(conn):
            with conn, conn.makefile("rb") as stream:
                stream.readline()
                conn.sendall(reply[0])

        self.server._serve = invalid_reply
        self.server.start()
        for data in (b"not json\n", b"[]\n", b"null\n", b"\xff\n", b'{"ok": true}'):
            reply[0] = data
            with self.subTest(data=data), self.assertRaises(client.ServiceError):
                client.request({"command": "status"}, self.server.path)

    def test_socket_round_trip(self):
        self.server.start()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.05)
            sock.connect(self.server.path)
            sock.sendall(b'{"command": ')
            with self.assertRaises(socket.timeout):
                sock.recv(1)
            sock.settimeout(2)
            sock.sendall(b'"list"}\n')
            with sock.makefile("rb") as stream:
                reply = json.loads(stream.readline())
        self.assertTrue(reply["ok"])
        self.assertEqual(len(reply["credentials"]), 3)

    def test_stop_wakes_the_accept_thread(self):
        before = set(threading.enumerate())
        self.server.start()
        threads = [t for t in threading.enumerate() if t not in before and t.name == "control"]
        self.assertEqual(len(threads), 1)
        self.server.stop()
        threads[0].join(timeout=1)
        self.assertFalse(threads[0].is_alive(), "stop left the listening thread blocked in accept")

    def test_accept_survives_fd_exhaustion(self):
        served = []
        errors = [OSError(errno.EMFILE, "Too many open files"), OSError(errno.EINVAL, "Invalid argument")]

        class FakeSock:
            def accept(self):
                if not served:
                    served.append(None)
                    raise errors[0]
                raise errors[1]

        with self.assertLogs("localpasskey.control", "WARNING"):
            self.server._accept_loop(FakeSock())  # returns only on EINVAL, after retrying EMFILE
        self.assertEqual(served, [None])

    def test_socket_request_boundaries(self):
        self.server.start()
        request = b'{"command": "status"}'
        for data, accepted in (
            (request.ljust(MAX_REQUEST - 1) + b"\n", True),
            (request.ljust(MAX_REQUEST) + b"\n", False),
            (request, False),
        ):
            with self.subTest(size=len(data), accepted=accepted):
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                    sock.settimeout(2)
                    sock.connect(self.server.path)
                    sock.sendall(data)
                    sock.shutdown(socket.SHUT_WR)
                    with sock.makefile("rb") as stream:
                        reply = stream.readline()
                if accepted:
                    self.assertEqual(json.loads(reply), {"ok": True, "version": "test"})
                else:
                    self.assertEqual(reply, b"")

    def test_a_caller_has_a_bounded_number_of_requests_being_read(self):
        self.server.start()
        readers = self.server._slot(os.getuid()).readers
        for _ in range(2):
            readers.acquire()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.3)
            sock.connect(self.server.path)
            sock.sendall(b'{"command": "status"}\n')
            with self.assertRaises(socket.timeout):
                sock.recv(1)
            readers.release()
            sock.settimeout(2)
            with sock.makefile("rb") as stream:
                self.assertEqual(json.loads(stream.readline()), {"ok": True, "version": "test"})
        readers.release()

    def test_a_caller_has_a_bounded_number_of_open_connections(self):
        self.server.start()
        connections = self.server._slot(os.getuid()).connections
        for _ in range(8):
            connections.acquire()
        try:
            with self.assertRaisesRegex(client.ServiceError, "too many requests"):
                client.request({"command": "status"}, self.server.path)
            connections.release()
            self.assertEqual(client.request({"command": "status"}, self.server.path), {"ok": True, "version": "test"})
        finally:
            for _ in range(7):
                connections.release()

    def test_a_request_waiting_for_authentication_keeps_its_reader_slot(self):
        self.server.start()
        asking, answer = threading.Event(), threading.Event()

        def slow_dialog(subject, action_id, message, cancelled=None, timeout=120.0):
            asking.set()
            answer.wait(5)
            return Verdict.APPROVED

        self.polkit.check = slow_dialog
        readers = self.server._slot(os.getuid()).readers
        readers.acquire()
        export = threading.Thread(target=client.request, args=({"command": "export", "all": True}, self.server.path))
        export.start()
        try:
            self.assertTrue(asking.wait(5))
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.3)
                sock.connect(self.server.path)
                sock.sendall(b'{"command": "status"}\n')
                with self.assertRaises(socket.timeout):
                    sock.recv(1)
                answer.set()
                sock.settimeout(5)
                with sock.makefile("rb") as stream:
                    self.assertEqual(json.loads(stream.readline()), {"ok": True, "version": "test"})
        finally:
            answer.set()
            readers.release()
            export.join(5)

    def test_client_round_trip_and_errors(self):
        self.server.start()
        reply = client.request({"command": "list"}, self.server.path)
        self.assertEqual(len(reply["credentials"]), 3)
        with self.assertRaisesRegex(client.ServiceError, "unknown command"):
            client.request({"command": "unknown"}, self.server.path)

        def close_without_reply(conn):
            with conn, conn.makefile("rb") as stream:
                stream.readline()

        self.server._serve = close_without_reply
        with self.assertRaisesRegex(client.ServiceUnavailable, "no reply"):
            client.request({"command": "status"}, self.server.path)

    def test_client_reads_a_large_fragmented_reply(self):
        expected = {"ok": True, "payload": "x" * 131072}
        data = json.dumps(expected).encode() + b"\n"

        def reply_in_chunks(conn):
            with conn, conn.makefile("rb") as stream:
                stream.readline()
                for start in range(0, len(data), 4093):
                    conn.sendall(data[start:start + 4093])

        self.server._serve = reply_in_chunks
        self.server.start()
        self.assertEqual(client.request({"command": "status"}, self.server.path), expected)


if __name__ == "__main__":
    unittest.main()
