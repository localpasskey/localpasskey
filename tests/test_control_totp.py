import base64
import json
import os
import pwd
import tempfile
import threading
import time
import unittest
import xml.etree.ElementTree as ET

from pathlib import Path
from unittest.mock import patch

from localpasskey import cose, totp
from localpasskey.control import UNLOCK_IDLE, ControlError, ControlServer
from localpasskey.ctap2 import Verdict
from localpasskey.polkit import ACTION_AUTHENTICATE, ACTION_EXPORT, ACTION_MANAGE, ACTION_TOTP
from localpasskey.store import Credential, CredentialStore, StoreError, TotpEntry, b64encode
from tests.test_control import FakeNotifier, FakePolkit

SECRET = bytes(range(1, 21))  # RFC 6238's SHA1 test key would also be its own oracle
POLICY = Path(__file__).resolve().parent.parent / "data" / "org.localpasskey.policy"


class TotpControlTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.store = CredentialStore(self._tmp.name)
        self.uid = os.getuid()
        if self.uid == 0:
            self.skipTest("root is always unlocked")
        self.name = pwd.getpwuid(self.uid).pw_name
        self.polkit = FakePolkit(Verdict.APPROVED)
        self.notifier = FakeNotifier()
        self.server = ControlServer(
            os.path.join(self._tmp.name, "control.sock"), self.store, self.polkit, lambda: {"version": "test"},
            self.notifier,
        )
        self.replies = []

    def tearDown(self):
        self.server.stop()
        self._tmp.cleanup()
        # The hard rule: no reply but export ever carries a seed.
        for reply, export in self.replies:
            if not export:
                self.assertNotIn(totp.encode_secret(SECRET), reply)
                self.assertNotIn(base64.b32encode(SECRET).decode(), reply)
                self.assertNotIn(SECRET.hex(), reply)
                self.assertNotIn(b64encode(SECRET), reply)
                self.assertNotIn(base64.b64encode(SECRET).decode(), reply)

    def handle(self, request, pid=None):
        try:
            reply = self.server.handle({"command": "totp", **request}, pid or os.getpid(), self.uid)
        except ControlError as e:
            self.replies.append((str(e), False))
            raise
        self.replies.append((json.dumps(reply), request.get("command") == "export"))
        return reply

    def raw(self, request):
        """A non-totp command; an export reply may carry the seed."""
        reply = self.server.handle(request, os.getpid(), self.uid)
        self.replies.append((json.dumps(reply), request.get("command") == "export"))
        return reply

    def entry(self, **overrides):
        data = {"secret": totp.encode_secret(SECRET), "site": "github.com", "issuer": "GitHub",
                "account": "octocat", "algorithm": "SHA1", "digits": 6, "period": 30}
        data.update(overrides)
        return data

    def add(self, **overrides):
        self.server._unlocks[self.server._unlock_key(os.getpid(), self.uid)] = time.monotonic() + 60
        try:
            return self.handle({"action": "add", "entry": self.entry(**overrides)})["added"]
        finally:
            self.server._unlocks.clear()

    def unlock(self):
        self.handle({"action": "unlock"})

    def code_record(self, **overrides):
        data = {"id": b64encode(os.urandom(16)), "site": "imported.example", "issuer": "Imp", "account": "a",
                "secret": totp.encode_secret(os.urandom(20)), "algorithm": "SHA1", "digits": 6, "period": 30,
                "created": 1700000000.0}
        data.update(overrides)
        return data

    def add_passkey(self, rp_id="example.com"):
        key = cose.generate_private_key(cose.ES256)
        cred_id = os.urandom(32)
        cred = Credential(id=cred_id, rp_id=rp_id, user_id=b"u", alg=cose.ES256,
                          sealed_key=self.store.seal(self.uid, cred_id, cose.private_key_to_bytes(key)),
                          created=time.time())
        self.store.add(self.uid, self.name, cred)
        return cred

    # -- policy -----------------------------------------------------------

    def test_the_policy_file_declares_every_action_at_auth_self(self):
        actions = {a.get("id"): a for a in ET.parse(POLICY).getroot().iter("action")}
        self.assertEqual(set(actions), {ACTION_AUTHENTICATE, ACTION_MANAGE, ACTION_EXPORT, ACTION_TOTP})
        defaults = actions[ACTION_TOTP].find("defaults")
        self.assertEqual([defaults.find(k).text for k in ("allow_any", "allow_inactive", "allow_active")],
                         ["auth_self"] * 3)

    # -- status, list, settings -------------------------------------------

    def test_status_and_list_never_ask(self):
        self.assertEqual(self.handle({"action": "status"}),
                         {"ok": True, "user": self.name, "require_auth": True, "unlocked": False,
                          "count": 0, "trash_count": 0})
        added = self.add()
        self.assertEqual(set(added), {"id", "site", "issuer", "account", "algorithm", "digits", "period",
                                      "created", "deleted"})
        self.polkit.checks.clear()
        listing = self.handle({"action": "list"})
        self.assertEqual(listing["user"], self.name)
        self.assertEqual([c["id"] for c in listing["codes"]], [added["id"]])
        self.assertEqual(self.handle({"action": "list", "trash": True})["codes"], [])
        self.assertEqual(self.handle({"action": "status"})["count"], 1)
        self.assertEqual(self.polkit.checks, [])
        with self.assertRaisesRegex(ControlError, "invalid trash selector"):
            self.handle({"action": "list", "trash": "yes"})

    def test_unknown_action(self):
        for action in (None, "show", 1):
            with self.subTest(action=action), self.assertRaisesRegex(
                    ControlError, "unknown authenticator code action"):
                self.handle({"action": action})

    def test_settings_off_always_asks_and_on_never_asks(self):
        self.unlock()
        self.polkit.checks.clear()
        self.polkit.verdict = Verdict.DENIED
        with self.assertRaisesRegex(ControlError, "not changed"):
            self.handle({"action": "settings", "require_auth": False})
        self.assertTrue(self.store.totp_require_auth(self.uid, self.name))
        self.assertEqual(self.polkit.checks, [
            ("unix-process", ACTION_MANAGE, "Show authenticator codes without asking for your password?")])

        self.polkit.verdict = Verdict.APPROVED
        self.assertEqual(self.handle({"action": "settings", "require_auth": False}),
                         {"ok": True, "require_auth": False})
        self.assertFalse(self.store.totp_require_auth(self.uid, self.name))
        self.polkit.checks.clear()
        self.handle({"action": "settings", "require_auth": False})
        self.handle({"action": "settings", "require_auth": True})
        self.handle({"action": "settings", "require_auth": True})
        self.assertEqual(self.polkit.checks, [], "turning it on or leaving it never asks")
        self.assertTrue(self.store.totp_require_auth(self.uid, self.name))
        for value in (None, 0, "no"):
            with self.subTest(value=value), self.assertRaises(ControlError):
                self.handle({"action": "settings", "require_auth": value})

    def test_settings_off_cannot_race_a_concurrent_switch_on(self):
        self.store.set_totp_require_auth(self.uid, self.name, False, True)
        read = self.store.totp_require_auth

        def read_then_switch_on(uid, username):
            value = read(uid, username)  # this request decides with the old value...
            self.store.set_totp_require_auth(uid, username, True, False)  # ...then the user turns it on
            return value

        self.polkit.checks.clear()
        with patch.object(self.store, "totp_require_auth", read_then_switch_on):
            with self.assertRaisesRegex(StoreError, "changed meanwhile"):
                self.handle({"action": "settings", "require_auth": False})
        self.assertTrue(self.store.totp_require_auth(self.uid, self.name))
        self.assertEqual(self.polkit.checks, [])

    # -- unlock, lock, code -----------------------------------------------

    def test_code_without_an_unlock_is_refused(self):
        added = self.add()
        with self.assertRaisesRegex(ControlError, "authenticator codes are locked"):
            self.handle({"action": "code", "ids": [added["id"]]})
        self.assertEqual(self.polkit.checks, [])

    def test_unlock_asks_once_then_codes_flow(self):
        added = self.add()
        self.polkit.verdict = Verdict.DENIED
        with self.assertRaisesRegex(ControlError, "not unlocked"):
            self.unlock()
        with self.assertRaisesRegex(ControlError, "locked"):
            self.handle({"action": "code", "all": True})
        self.polkit.verdict = Verdict.APPROVED
        self.polkit.checks.clear()
        self.assertEqual(self.handle({"action": "unlock"}), {"ok": True, "unlocked": True})
        self.assertEqual(self.polkit.checks, [
            ("unix-process", ACTION_TOTP, "Show the authenticator codes stored on this computer?")])
        self.assertTrue(self.handle({"action": "status"})["unlocked"])
        now = time.time()
        reply = self.handle({"action": "code", "all": True, "now": 0})
        [code] = reply["codes"]
        self.assertEqual(set(code), {"id", "code", "remaining", "period"})
        self.assertEqual(code["id"], added["id"])
        self.assertEqual(code["period"], 30)
        self.assertIn(code["code"], {totp.code(SECRET, now=now + d)[0] for d in (0, 2)},
                      "computed with the daemon's clock, not the client's")
        self.assertIsInstance(code["remaining"], float)
        self.assertTrue(0 <= code["remaining"] <= 30)
        self.handle({"action": "code", "ids": [added["id"]]})
        self.assertEqual(len(self.polkit.checks), 1, "an unlocked process is not asked again")

    def test_code_with_ask_prompts_once_and_records_no_unlock(self):
        added = self.add(site="", issuer="Bank & Co")
        reply = self.handle({"action": "code", "ids": [added["id"]], "ask": True})
        self.assertEqual(len(reply["codes"]), 1)
        self.assertEqual(self.polkit.checks, [
            ("unix-process", ACTION_TOTP, "Show the authenticator code for Bank & Co?")])
        self.assertEqual(self.server._unlocks, {})
        with self.assertRaisesRegex(ControlError, "locked"):
            self.handle({"action": "code", "ids": [added["id"]]})
        self.polkit.verdict = Verdict.CANCELLED
        with self.assertRaisesRegex(ControlError, "not shown"):
            self.handle({"action": "code", "ids": [added["id"]], "ask": True})

    def test_dialogs_and_notifications_never_name_the_account(self):
        self.server._unlocks[self.server._unlock_key(os.getpid(), self.uid)] = time.monotonic() + 60
        added = self.handle({"action": "add", "entry": self.entry(site="", issuer="", account="octocat")})["added"]
        self.server._unlocks.clear()
        self.handle({"action": "code", "ids": [added["id"]], "ask": True})
        self.assertEqual(self.polkit.checks[-1][2], "Show the authenticator code for an account?")
        self.assertEqual(self.notifier.notes[-1][1],
                         "The authenticator code for an account was added to this computer.")
        self.assertNotIn("octocat", repr(self.polkit.checks + self.notifier.notes))

    def test_code_ignores_the_trash_and_validates_its_request(self):
        added = self.add()
        self.unlock()
        self.handle({"action": "delete", "all": True})
        with self.assertRaisesRegex(ControlError, "no authenticator code with ID"):
            self.handle({"action": "code", "ids": [added["id"]]})
        for request in ({"all": True, "ask": 1}, {"site": "github.com"}, {}, {"ids": [1]}):
            with self.subTest(request=request), self.assertRaises(ControlError):
                self.handle({"action": "code", **request})

    def test_codes_follow_the_algorithm_digits_and_period(self):
        self.handle({"action": "settings", "require_auth": True})
        self.add(algorithm="sha512", digits=8, period=60)
        self.unlock()
        [code] = self.handle({"action": "code", "all": True})["codes"]
        self.assertEqual(len(code["code"]), 8)
        self.assertEqual(code["period"], 60)
        self.assertEqual(self.handle({"action": "list"})["codes"][0]["algorithm"], "SHA512")

    def test_require_auth_off_shows_codes_without_an_unlock(self):
        self.add()
        self.handle({"action": "settings", "require_auth": False})
        self.polkit.checks.clear()
        self.assertTrue(self.handle({"action": "status"})["unlocked"])
        self.assertEqual(self.handle({"action": "unlock"}), {"ok": True, "unlocked": True})
        self.assertEqual(len(self.handle({"action": "code", "all": True})["codes"]), 1)
        self.assertEqual(self.polkit.checks, [])
        self.assertEqual(self.server._unlocks, {}, "nothing is recorded when the setting is off")

    def test_an_unlock_belongs_to_one_process(self):
        self.add()
        self.unlock()
        with self.assertRaisesRegex(ControlError, "locked"):
            self.handle({"action": "code", "all": True}, pid=os.getppid())
        with patch("localpasskey.control.process_start_time", return_value=1), \
                self.assertRaisesRegex(ControlError, "locked"):
            self.handle({"action": "code", "all": True})  # a recycled pid
        self.handle({"action": "code", "all": True})

    def test_an_unlock_expires_when_idle_and_code_requests_extend_it(self):
        self.add()
        start = time.monotonic()
        with patch("localpasskey.control.time.monotonic", return_value=start):
            self.unlock()
        with patch("localpasskey.control.time.monotonic", return_value=start + UNLOCK_IDLE - 1):
            self.handle({"action": "code", "all": True})
        with patch("localpasskey.control.time.monotonic", return_value=start + UNLOCK_IDLE + 10):
            self.handle({"action": "code", "all": True})  # extended by the previous request
        with patch("localpasskey.control.time.monotonic", return_value=start + 3 * UNLOCK_IDLE):
            with self.assertRaisesRegex(ControlError, "locked"):
                self.handle({"action": "code", "all": True})
            self.assertFalse(self.handle({"action": "status"})["unlocked"])
        self.assertEqual(self.server._unlocks, {}, "expired unlocks are dropped")

    def test_recording_an_unlock_drops_the_expired_ones(self):
        now = time.monotonic()
        for pid in range(1000):  # windows that quit without sending lock
            self.server._unlocks[(self.uid, pid, 1)] = now - 1
        live = (self.uid, 1, 2)
        self.server._unlocks[live] = now + 60
        self.unlock()
        self.assertEqual(set(self.server._unlocks), {live, self.server._unlock_key(os.getpid(), self.uid)})

    def test_a_lock_during_a_code_request_stays_locked(self):
        self.add()
        self.unlock()
        real_code = totp.code

        def lock_meanwhile(*args):
            self.handle({"action": "lock"})  # another request while this one computes
            return real_code(*args)

        with patch("localpasskey.control.totp.code", side_effect=lock_meanwhile):
            self.handle({"action": "code", "all": True})
        self.assertEqual(self.server._unlocks, {}, "the code request must not re-create the unlock")
        with self.assertRaisesRegex(ControlError, "locked"):
            self.handle({"action": "code", "all": True})

    def test_keep_unlocked_never_inserts_or_revives(self):
        key = self.server._unlock_key(os.getpid(), self.uid)
        self.server._keep_unlocked(key)
        self.server._keep_unlocked(None)
        self.assertEqual(self.server._unlocks, {})
        self.server._unlocks[key] = time.monotonic() - 1
        self.server._keep_unlocked(key)
        self.assertLess(self.server._unlocks[key], time.monotonic(), "an expired unlock is not extended")

    def test_lock_drops_the_unlock_and_is_idempotent(self):
        self.add()
        self.unlock()
        self.assertEqual(self.handle({"action": "lock"}), {"ok": True})
        self.assertEqual(self.handle({"action": "lock"}), {"ok": True})
        with self.assertRaisesRegex(ControlError, "locked"):
            self.handle({"action": "code", "all": True})

    # -- add, update ------------------------------------------------------

    def test_add_asks_unless_unlocked(self):
        reply = self.handle({"action": "add", "entry": self.entry(), "dry_run": True})
        self.assertEqual(reply["added"]["id"], "")
        self.assertEqual(self.polkit.checks, [])
        self.assertEqual(self.store.totp_entries(self.uid, self.name), [])

        self.polkit.verdict = Verdict.DENIED
        with self.assertRaisesRegex(ControlError, "not added"):
            self.handle({"action": "add", "entry": self.entry()})
        self.assertEqual(self.store.totp_entries(self.uid, self.name), [])
        self.assertEqual(self.polkit.checks[-1], (
            "unix-process", ACTION_MANAGE, "Save an authenticator code for github.com on this computer?"))

        self.polkit.verdict = Verdict.APPROVED
        added = self.handle({"action": "add", "entry": self.entry()})["added"]
        [stored] = self.store.totp_entries(self.uid, self.name)
        self.assertEqual(added["id"], stored.id.hex())
        self.assertEqual(self.store.totp_unseal(self.uid, stored), SECRET)
        self.assertEqual((stored.site, stored.issuer, stored.account), ("github.com", "GitHub", "octocat"))
        self.assertEqual(self.notifier.notes[-1], (
            "Authenticator code added", "The authenticator code for github.com was added to this computer.",
            "activity"))

        self.unlock()
        self.polkit.checks.clear()
        self.handle({"action": "add", "entry": self.entry(account="other")})
        self.assertEqual(self.polkit.checks, [], "an unlocked caller adds without a prompt")

    def test_add_validates_the_entry_strictly(self):
        self.unlock()
        cases = {
            "not a JSON object": None,
            "secret is missing": self.entry(secret=None),
            "not a valid setup key": self.entry(secret="0189"),
            "too short": self.entry(secret=totp.encode_secret(b"short")),
            "invalid site": self.entry(site="not a site"),
            "site is missing or not a str": self.entry(site=1),
            "issuer is missing or not a str": self.entry(issuer=None),
            "account is missing or not a str": self.entry(account=None),
            "issuer is longer": self.entry(issuer="x" * 256),
            "account is not valid text": self.entry(account="\ud800"),
            "algorithm must be": self.entry(algorithm="MD5"),
            "digits must be": self.entry(digits=7),
            "digits is missing or not": self.entry(digits=True),
            "period must be": self.entry(period=0),
            "period is missing or not": self.entry(period="30"),
        }
        for problem, entry in cases.items():
            with self.subTest(problem=problem), self.assertRaisesRegex(ControlError, problem):
                self.handle({"action": "add", "entry": entry})
        self.assertEqual(self.store.totp_entries(self.uid, self.name), [])
        added = self.handle({"action": "add", "entry": {"secret": totp.encode_secret(SECRET).lower()}})["added"]
        self.assertEqual((added["site"], added["algorithm"], added["digits"], added["period"]),
                         ("", "SHA1", 6, 30))

    def test_labels_lose_surrounding_whitespace(self):
        self.unlock()
        added = self.handle({"action": "add", "entry": self.entry(site=" github.com\t", issuer="  GitHub ",
                                                                   account="\noctocat ")})["added"]
        self.assertEqual((added["site"], added["issuer"], added["account"]), ("github.com", "GitHub", "octocat"))
        updated = self.handle({"action": "update", "id": added["id"], "site": "  ", "issuer": " Hub ",
                               "account": None})["updated"]  # null: unchanged
        self.assertEqual((updated["site"], updated["issuer"], updated["account"]), ("", "Hub", "octocat"))
        reply = self.raw({"command": "import", "credentials": [],
                          "codes": [self.code_record(site=" imported.example ", issuer=" Imp ", account=" a ")]})
        self.assertEqual([(c["site"], c["issuer"], c["account"]) for c in reply["imported_codes"]],
                         [("imported.example", "Imp", "a")])
        self.assertEqual(sorted((e.site, e.issuer, e.account) for e in self.store.totp_entries(self.uid, self.name)),
                         [("", "Hub", "octocat"), ("imported.example", "Imp", "a")])

    def test_update_changes_labels(self):
        added = self.add()
        self.polkit.verdict = Verdict.DENIED
        with self.assertRaisesRegex(ControlError, "not changed"):
            self.handle({"action": "update", "id": added["id"][:6], "account": "new"})
        self.assertEqual(self.polkit.checks[-1], (
            "unix-process", ACTION_MANAGE, "Change the details of the authenticator code for github.com?"))
        self.polkit.verdict = Verdict.APPROVED
        updated = self.handle({"action": "update", "id": added["id"][:6], "account": "new", "site": ""})["updated"]
        self.assertEqual((updated["site"], updated["issuer"], updated["account"]), ("", "GitHub", "new"))
        self.unlock()
        self.polkit.checks.clear()
        self.handle({"action": "update", "id": added["id"], "issuer": "Hub"})
        self.assertEqual(self.polkit.checks, [])
        for request, problem in (({"id": added["id"]}, "nothing to change"),
                                 ({"id": "abc", "site": "a.b"}, "too short"),
                                 ({"id": 5, "site": "a.b"}, "must be a string"),
                                 ({"id": "ffffffff", "site": "a.b"}, "no authenticator code with ID"),
                                 ({"id": added["id"], "site": "bad site"}, "invalid site")):
            with self.subTest(request=request), self.assertRaisesRegex(ControlError, problem):
                self.handle({"action": "update", **request})

    def test_the_service_keeps_and_matches_the_host_of_a_typed_website(self):
        added = self.add(site="GitHub.com/login")
        self.assertEqual(added["site"], "github.com")
        updated = self.handle({"action": "update", "id": added["id"], "site": "https://WWW.github.com:443/"})
        self.assertEqual(updated["updated"]["site"], "www.github.com")
        reply = self.raw({"command": "import", "credentials": [], "dry_run": True,
                          "codes": [self.code_record(site="me@imported.example:8443")]})
        self.assertEqual(reply["imported_codes"][0]["site"], "imported.example")
        for action in ("delete", "restore", "purge"):
            if action == "restore":
                self.handle({"action": "delete", "all": True})
            with self.subTest(action=action):
                preview = self.handle({"action": action, "site": "www.GitHub.com/x", "dry_run": True})
                self.assertEqual([c["id"] for c in preview["deleted"]], [added["id"]])
        self.handle({"action": "restore", "all": True})
        plan = self.raw({"command": "export", "site": "https://www.github.com", "codes": True, "dry_run": True})
        self.assertEqual([c["id"] for c in plan["exported_codes"]], [added["id"]])

    # -- delete, restore, purge -------------------------------------------

    def test_delete_restore_and_purge(self):
        first = self.add()
        self.add(site="other.org", account="b")
        preview = self.handle({"action": "delete", "site": "github.com", "dry_run": True})
        self.assertEqual([c["id"] for c in preview["deleted"]], [first["id"]])
        self.assertEqual(self.polkit.checks, [])

        moved = self.handle({"action": "delete", "site": "github.com"})["deleted"]
        self.assertEqual(self.polkit.checks[-1], ("unix-process", ACTION_MANAGE,
                                                  "Move 1 authenticator code to the trash?"))
        self.assertEqual([c["id"] for c in moved], [first["id"]])
        self.assertIsNotNone(moved[0]["deleted"])
        self.assertEqual(self.notifier.notes[-1][0], "Authenticator code moved to the trash")
        self.assertEqual(self.handle({"action": "status"})["trash_count"], 1)

        preview = self.handle({"action": "restore", "all": True, "dry_run": True})
        self.assertEqual([c["id"] for c in preview["deleted"]], [first["id"]])
        restored = self.handle({"action": "restore", "all": True})["restored"]
        self.assertEqual(self.polkit.checks[-1][2], "Restore 1 authenticator code from the trash?")
        self.assertIsNone(restored[0]["deleted"])

        self.handle({"action": "delete", "all": True})
        self.assertEqual(self.polkit.checks[-1][2], "Move 2 authenticator codes to the trash?")
        with self.assertRaisesRegex(ControlError, "one authenticator code at a time"):
            self.handle({"action": "purge", "all": True})
        self.polkit.verdict = Verdict.DENIED
        with self.assertRaisesRegex(ControlError, "not purged"):
            self.handle({"action": "purge", "ids": [first["id"]]})
        self.polkit.verdict = Verdict.APPROVED
        preview = self.handle({"action": "purge", "ids": [first["id"]], "dry_run": True})
        self.assertEqual(len(preview["deleted"]), 1)
        purged = self.handle({"action": "purge", "ids": [first["id"]]})["purged"]
        self.assertEqual(self.polkit.checks[-1], (
            "unix-process", ACTION_MANAGE, "Permanently delete the authenticator code for github.com? "
            "You may lose access to that account. This cannot be undone."))
        self.assertEqual([c["id"] for c in purged], [first["id"]])
        self.assertEqual(self.notifier.notes[-1], (
            "Authenticator code permanently deleted",
            "The authenticator code for github.com was permanently deleted from this computer.", "activity"))
        self.assertEqual(len(self.store.totp_trash(self.uid, self.name)), 1)

    def test_an_unlock_covers_delete_and_restore_but_never_purge(self):
        added = self.add()
        self.unlock()
        self.polkit.checks.clear()
        self.handle({"action": "delete", "ids": [added["id"]]})
        self.handle({"action": "restore", "ids": [added["id"]]})
        self.assertEqual(self.polkit.checks, [])
        self.handle({"action": "delete", "ids": [added["id"]]})
        self.handle({"action": "purge", "ids": [added["id"]]})
        self.assertEqual([c[1] for c in self.polkit.checks], [ACTION_MANAGE])

    def test_selectors_speak_of_codes(self):
        self.add()
        for request, problem in (({"all": True, "site": "x.y"}, "choose one selector"),
                                 ({"site": "nowhere.example"}, "no matching authenticator codes"),
                                 ({"ids": ["ab"]}, "authenticator code ID 'ab' is too short"),
                                 ({"ids": [7]}, "authenticator code IDs must be strings"),
                                 ({"all": True, "dry_run": "yes"}, "invalid dry_run")):
            with self.subTest(request=request), self.assertRaisesRegex(ControlError, problem):
                self.handle({"action": "delete", **request})
        with self.assertRaisesRegex(ControlError, "no matching authenticator codes"):
            self.handle({"action": "restore", "all": True})
        self.assertEqual(self.polkit.checks, [])
        self.assertEqual(len(self.store.totp_entries(self.uid, self.name)), 1)

    def test_codes_are_kept_apart_from_passkeys(self):
        self.add_passkey()
        self.add()
        self.unlock()
        self.handle({"action": "delete", "all": True})
        self.assertEqual(len(self.raw({"command": "list"})["credentials"]), 1)
        self.assertEqual(self.raw({"command": "list", "trash": True})["credentials"], [])

    # -- export and import ------------------------------------------------

    def test_export_includes_codes_on_request_with_one_prompt(self):
        cred = self.add_passkey("github.com")
        added = self.add()
        self.add(site="other.org", account="b")
        plan = self.raw({"command": "export", "site": "github.com", "codes": True, "dry_run": True})
        self.assertEqual([c["id"] for c in plan["exported"]], [cred.id.hex()])
        self.assertEqual([c["id"] for c in plan["exported_codes"]], [added["id"]])
        self.assertNotIn("codes", plan, "a dry run carries no secret")
        self.assertEqual(self.polkit.checks, [])

        self.polkit.verdict = Verdict.DENIED
        with self.assertRaisesRegex(ControlError, "not exported"):
            self.raw({"command": "export", "ids": [cred.id.hex()], "code_ids": [added["id"]]})
        self.polkit.verdict = Verdict.APPROVED
        self.notifier.notes.clear()
        reply = self.raw({"command": "export", "ids": [cred.id.hex()], "code_ids": [added["id"]]})
        self.assertEqual(self.polkit.checks[-1], (
            "unix-process", ACTION_EXPORT, "Export 1 passkey and 1 authenticator code stored on this computer? "
            "Whoever can open the exported file can sign in as you."))
        self.assertEqual(len(reply["credentials"]), 1)
        [code] = reply["codes"]
        self.assertEqual(code, {"id": b64encode(bytes.fromhex(added["id"])), "site": "github.com",
                                "issuer": "GitHub", "account": "octocat", "secret": totp.encode_secret(SECRET),
                                "algorithm": "SHA1", "digits": 6, "period": 30, "created": added["created"]})
        self.assertEqual([c["id"] for c in reply["exported_codes"]], [added["id"]])
        self.assertEqual([n[0] for n in self.notifier.notes], ["Passkey exported", "Authenticator code exported"])

    def test_export_of_codes_only_and_of_nothing(self):
        self.add()
        self.add(account="b")
        plan = self.raw({"command": "export", "all": True, "codes": True, "dry_run": True})
        self.assertEqual((len(plan["exported"]), len(plan["exported_codes"])), (0, 2))
        ids = [c["id"] for c in plan["exported_codes"]]
        reply = self.raw({"command": "export", "code_ids": ids})
        self.assertEqual(self.polkit.checks[-1][2], "Export 2 authenticator codes stored on this computer? "
                         "Whoever can open the exported file can sign in as you.")
        self.assertEqual((reply["credentials"], len(reply["codes"])), ([], 2))
        with self.assertRaisesRegex(ControlError, "nothing to export"):
            self.raw({"command": "export", "site": "nowhere.example", "codes": True, "dry_run": True})
        with self.assertRaisesRegex(ControlError, "no matching passkeys"):
            self.raw({"command": "export", "all": True, "dry_run": True})
        with self.assertRaisesRegex(ControlError, "invalid codes selector"):
            self.raw({"command": "export", "all": True, "codes": "yes"})

    def test_export_without_codes_behaves_as_before(self):
        cred = self.add_passkey()
        self.add(site="example.com")
        plan = self.raw({"command": "export", "all": True, "dry_run": True})
        self.assertEqual(plan["exported_codes"], [])
        reply = self.raw({"command": "export", "ids": [cred.id.hex()]})
        self.assertEqual(self.polkit.checks[-1][2], "Export 1 passkey stored on this computer? "
                         "Whoever can open the exported file can sign in as you.")
        self.assertEqual(reply["codes"], [])
        self.replies[-1] = (self.replies[-1][0], False)  # so it is scanned for the seed too
        # ids select passkeys only, even with codes asked for.
        self.assertEqual(self.raw({"command": "export", "ids": [cred.id.hex()], "codes": True,
                                   "dry_run": True})["exported_codes"], [])

    def test_a_code_that_cannot_be_decrypted_fails_the_export_before_any_prompt(self):
        added = self.add()
        path = self.store._totp_path(self.uid)
        doc = json.loads(path.read_text())
        sealed = bytearray(base64.urlsafe_b64decode(doc["entries"][0]["secret"] + "=="))
        sealed[-1] ^= 1
        doc["entries"][0]["secret"] = b64encode(bytes(sealed))
        path.write_text(json.dumps(doc))
        self.polkit.checks.clear()
        for request in ({"all": True, "codes": True, "dry_run": True}, {"code_ids": [added["id"]]}):
            with self.subTest(request=request), self.assertRaisesRegex(StoreError, "cannot be decrypted"):
                self.raw({"command": "export", **request})
        self.assertEqual(self.polkit.checks, [])

    def test_export_leaves_out_codes_trashed_during_the_dialog(self):
        added = self.add()
        self.add(account="b")

        def trash_one(subject, action_id, message, cancelled=None, timeout=120.0):
            self.store.totp_remove(self.uid, self.name, [bytes.fromhex(added["id"])])
            return Verdict.APPROVED

        self.polkit.check = trash_one
        reply = self.raw({"command": "export", "all": True, "codes": True})
        self.assertEqual(len(reply["codes"]), 1)
        self.assertNotEqual(reply["exported_codes"][0]["id"], added["id"])

    def test_import_of_codes(self):
        records = [self.code_record(), self.code_record()]
        plan = self.raw({"command": "import", "credentials": [], "codes": records, "dry_run": True})
        self.assertEqual([c["site"] for c in plan["imported_codes"]], ["imported.example"] * 2)
        self.assertEqual((plan["imported"], plan["skipped"], plan["skipped_codes"]), ([], [], []))
        self.assertEqual(self.polkit.checks, [])
        self.assertEqual(self.store.totp_entries(self.uid, self.name), [])

        reply = self.raw({"command": "import", "credentials": [], "codes": records})
        self.assertEqual(self.polkit.checks, [
            ("unix-process", ACTION_MANAGE, "Import 2 authenticator codes into this computer?")])
        self.assertEqual(len(reply["imported_codes"]), 2)
        stored = {e.id: e for e in self.store.totp_entries(self.uid, self.name)}
        for data in records:
            entry = stored[base64.urlsafe_b64decode(data["id"] + "==")]
            self.assertEqual(totp.encode_secret(self.store.totp_unseal(self.uid, entry)), data["secret"])
            self.assertEqual(entry.created, 1700000000.0)
        self.assertEqual(self.notifier.notes[-1][0], "Authenticator codes imported")

        again = self.raw({"command": "import", "credentials": [], "codes": records + [records[0]]})
        self.assertEqual(len(self.polkit.checks), 1, "nothing new, nothing asked")
        self.assertEqual([s["reason"] for s in again["skipped_codes"]],
                         ["already on this computer", "already on this computer", "duplicate in the file"])
        self.assertEqual(set(again["skipped_codes"][0]), {"code", "reason"})

    def test_import_of_passkeys_and_codes_asks_once(self):
        key = cose.generate_private_key(cose.ES256)
        passkey = {"id": b64encode(os.urandom(32)), "rp_id": "imported.example", "rp_name": "", "user_id": "dQ",
                   "user_name": "u", "user_display_name": "", "alg": cose.ES256,
                   "private_key": b64encode(cose.private_key_to_bytes(key)), "discoverable": True,
                   "cred_protect": 1, "created": 1700000000.0}
        reply = self.raw({"command": "import", "credentials": [passkey, dict(passkey, id=b64encode(os.urandom(32)), user_id="dg")],
                          "codes": [self.code_record()]})
        self.assertEqual(self.polkit.checks, [
            ("unix-process", ACTION_MANAGE, "Import 2 passkeys and 1 authenticator code into this computer?")])
        self.assertEqual((len(reply["imported"]), len(reply["imported_codes"])), (2, 1))
        # A passkey-only import keeps its old message and gains only empty lists.
        reply = self.raw({"command": "import", "credentials": [dict(passkey, id=b64encode(os.urandom(32)), user_id="dw")]})
        self.assertEqual(self.polkit.checks[-1][2], "Import 1 passkey into this computer?")
        self.assertEqual((reply["imported_codes"], reply["skipped_codes"]), ([], []))

    def test_a_damaged_totp_file_leaves_passkey_export_and_import_alone(self):
        self.add_passkey()
        self.store._totp_path(self.uid).write_text("{not json")
        reply = self.raw({"command": "export", "all": True})
        self.assertEqual((len(reply["exported"]), reply["exported_codes"], reply["codes"]), (1, [], []))
        ids = [c["id"] for c in reply["exported"]]
        reply = self.raw({"command": "export", "ids": ids, "codes": True})  # IDs never select codes
        self.assertEqual((len(reply["exported"]), reply["exported_codes"], reply["codes"]), (1, [], []))
        [record] = reply["credentials"]
        reply = self.raw({"command": "import", "credentials": [dict(record, id=b64encode(os.urandom(32)),
                                                                     user_id="dw")]})
        self.assertEqual((len(reply["imported"]), reply["imported_codes"]), (1, []))
        reply = self.raw({"command": "import", "credentials": [], "codes": [], "dry_run": True})
        self.assertEqual(reply["imported_codes"], [])
        # Asking for codes still fails loudly.
        for request in ({"command": "export", "all": True, "codes": True},
                        {"command": "export", "code_ids": ["abcd"]},
                        {"command": "import", "credentials": [], "codes": [self.code_record()]}):
            with self.subTest(request=request), self.assertRaises(StoreError):
                self.raw(request)

    def test_import_validates_code_records_strictly(self):
        cases = {
            "codes must be a list": {"codes": {}},
            "authenticator code 1: id is not base64url": {"codes": [self.code_record(id="!!")]},
            "authenticator code 2: the id must be 16 bytes": {
                "codes": [self.code_record(), self.code_record(id=b64encode(b"short"))]},
            "authenticator code 1: the setup key is too long": {
                "codes": [self.code_record(secret=totp.encode_secret(os.urandom(129)))]},
            "authenticator code 1: invalid site": {"codes": [self.code_record(site="a b")]},
            "authenticator code 1: site is missing or not a str": {"codes": [self.code_record(site=None)]},
            "authenticator code 1: the digits must be": {"codes": [self.code_record(digits=10)]},
            "at most 4096 authenticator codes": {"codes": [{}] * 4097},
        }
        for problem, request in cases.items():
            with self.subTest(problem=problem), self.assertRaisesRegex(ControlError, problem):
                self.raw({"command": "import", "credentials": [], **request})
        self.assertEqual(self.store.totp_entries(self.uid, self.name), [])
        self.assertEqual(self.polkit.checks, [])

    def test_import_sanitizes_the_creation_time(self):
        for created in (None, True, -1, float("inf"), time.time() + 1e6):
            records = [self.code_record(created=created)]
            reply = self.raw({"command": "import", "credentials": [], "codes": records, "dry_run": True})
            with self.subTest(created=created):
                self.assertAlmostEqual(reply["imported_codes"][0]["created"], time.time(), delta=5)

    # -- untrusted text, logs and locks -----------------------------------

    def test_hostile_labels_reach_dialogs_and_notifications_printable_only(self):
        hostile = "Bad\x1b[31m\u202eCo\u2066\x07"
        added = self.handle({"action": "add", "entry": self.entry(site="", issuer=hostile)})["added"]
        self.handle({"action": "code", "ids": [added["id"]], "ask": True})
        self.handle({"action": "delete", "all": True})
        self.handle({"action": "purge", "all": True})
        # site is validated on add, so a hostile one can only come from the file itself.
        entry_id = os.urandom(16)
        self.store.totp_add(self.uid, self.name, TotpEntry(
            id=entry_id, sealed_secret=self.store.seal(self.uid, b"totp\0" + entry_id, SECRET),
            site="ex\u202eample.com\x1b", issuer=hostile))
        self.handle({"action": "code", "ids": [entry_id.hex()], "ask": True})
        messages = [check[2] for check in self.polkit.checks]
        self.assertIn("Save an authenticator code for Bad[31mCo on this computer?", messages)
        self.assertIn("Show the authenticator code for Bad[31mCo?", messages)
        self.assertIn("Show the authenticator code for example.com?", messages)
        self.assertTrue(any(m.startswith("Permanently delete the authenticator code for Bad[31mCo?")
                            for m in messages))
        notes = [text for note in self.notifier.notes for text in note[:2]]
        self.assertIn("The authenticator code for Bad[31mCo was added to this computer.", notes)
        for text in messages + notes:
            self.assertTrue(text.isprintable(), text)

    def test_no_seed_or_code_is_logged(self):
        with self.assertLogs("localpasskey", level="DEBUG") as logs:
            self.add(digits=8)
            self.unlock()
            [code] = self.handle({"action": "code", "all": True})["codes"]
            [asked] = self.handle({"action": "code", "all": True, "ask": True})["codes"]
            export = self.raw({"command": "export", "all": True, "codes": True})
        self.assertEqual(len(export["codes"]), 1)
        text = "\n".join(logs.output)
        for secret in (totp.encode_secret(SECRET), base64.b32encode(SECRET).decode(), SECRET.hex(),
                       b64encode(SECRET), base64.b64encode(SECRET).decode(), code["code"], asked["code"]):
            self.assertNotIn(secret, text)

    def test_dialogs_run_with_the_store_lock_free(self):
        server, store = self.server, self.store
        held = []

        class LockCheckingPolkit(FakePolkit):
            def check(self, subject, action_id, message, cancelled=None, timeout=120.0):
                # The store lock is an RLock: only another thread can tell whether it is held.
                def probe():
                    for lock in (store._lock, server._unlocks_lock):
                        if lock.acquire(timeout=0):
                            lock.release()
                        else:
                            held.append(message)
                thread = threading.Thread(target=probe)
                thread.start()
                thread.join()
                return super().check(subject, action_id, message, cancelled, timeout)

        self.polkit = self.server.verifier = LockCheckingPolkit(Verdict.APPROVED)
        added = self.handle({"action": "add", "entry": self.entry()})["added"]
        self.handle({"action": "update", "id": added["id"], "account": "new"})
        self.handle({"action": "code", "all": True, "ask": True})
        self.handle({"action": "unlock"})
        self.handle({"action": "lock"})
        self.raw({"command": "export", "all": True, "codes": True})
        self.raw({"command": "import", "credentials": [], "codes": [self.code_record()]})
        self.handle({"action": "delete", "all": True})
        self.handle({"action": "restore", "all": True})
        self.handle({"action": "delete", "ids": [added["id"]]})
        self.handle({"action": "purge", "all": True})
        self.handle({"action": "settings", "require_auth": False})
        self.assertEqual(len(self.polkit.checks), 11)
        self.assertEqual(held, [])


if __name__ == "__main__":
    unittest.main()
