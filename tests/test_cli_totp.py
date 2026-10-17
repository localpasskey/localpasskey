import contextlib
import io
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from localpasskey import cli, totp, transfer
from localpasskey.control import _parse_record, code_record
from localpasskey.ctap2 import Verdict
from localpasskey.polkit import ACTION_EXPORT, ACTION_MANAGE, ACTION_TOTP
from localpasskey.store import TotpEntry, b64encode
from tests import test_control
from tests.test_transfer import fast_kdf

SECRET = bytes(range(1, 21))
KEY = totp.encode_secret(SECRET)
LINK = f"otpauth://totp/github.com:octocat?secret={KEY}&issuer=github.com"


class Terminal(io.StringIO):
    def isatty(self):
        return True


@fast_kdf
class CliTotpTests(unittest.TestCase):
    """The totp commands, and codes in export, import and status, against the
    test control server in this process so that prompts can be answered."""

    PASSPHRASE = "correct horse"

    def setUp(self):
        self.fixture = test_control.ControlTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        if self.fixture.uid == 0:
            self.skipTest("root is never asked for a password")
        self.fixture.server.start()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = tmp.name
        agent = patch("localpasskey.cli._start_tty_agent", return_value=None)
        agent.start()
        self.addCleanup(agent.stop)
        self.prompts = []

    def run_cli(self, *args, stdin="", typed=(), passphrases=(), tty=False):
        """Runs main(); the prompts asked land in self.prompts."""
        with (
            patch("localpasskey.cli.getpass.getpass", side_effect=list(passphrases)) as getpass,
            patch("localpasskey.cli.input", side_effect=list(typed), create=True) as asked,
            patch("sys.stdin", Terminal(stdin) if tty else io.StringIO(stdin)),
            contextlib.redirect_stdout(io.StringIO()) as out,
            contextlib.redirect_stderr(io.StringIO()) as err,
        ):
            code = cli.main(["--socket", self.fixture.server.path, *args])
        self.prompts = [call.args[0] for call in getpass.call_args_list + asked.call_args_list]
        for text in (out.getvalue(), err.getvalue(), *self.prompts):
            self.assertNotIn(KEY, text, "a seed must never be printed")
        return code, out.getvalue(), err.getvalue()

    def store_code(self, site="github.com", issuer="GitHub", account="octocat", **fields):
        entry_id = os.urandom(16)
        entry = TotpEntry(id=entry_id, sealed_secret=self.fixture.store.seal(self.fixture.uid, b"totp\0" + entry_id,
                                                                             SECRET),
                          site=site, issuer=issuer, account=account, created=1700000000.0, **fields)
        self.fixture.store.totp_add(self.fixture.uid, self.fixture.name, entry)
        return entry

    def codes(self, trash=False):
        store = self.fixture.store
        return (store.totp_trash if trash else store.totp_entries)(self.fixture.uid, self.fixture.name)

    def checks(self):
        return [action for _, action, _ in self.fixture.polkit.checks]

    def test_list_asks_for_nothing(self):
        code, out, _ = self.run_cli("totp", "list")
        self.assertEqual(code, 0)
        self.assertIn("No authenticator codes are stored for", out)
        self.store_code(algorithm="SHA256", digits=8, period=60)
        self.store_code(site="", issuer="Example\x1b]0;pwned\x07", account="")
        code, out, _ = self.run_cli("totp", "list")
        self.assertEqual(code, 0)
        self.assertIn("8 digits · 60 s · SHA256", out)
        self.assertNotIn("\x1b", out)
        self.assertEqual(out.splitlines()[0].split(), ["ID", "SITE", "ISSUER", "ACCOUNT", "TYPE", "CREATED"])
        code, out, _ = self.run_cli("totp", "list", "--json")
        self.assertEqual(code, 0)
        self.assertIn('"issuer": "GitHub"', out)
        code, out, _ = self.run_cli("totp", "list", "--trash")
        self.assertEqual(out.strip(), "The trash is empty.")
        self.assertEqual(self.checks(), [])

    def test_add_from_a_terminal(self):
        code, out, err = self.run_cli("totp", "add", tty=True, passphrases=[LINK], typed=["", "y"])
        self.assertEqual(code, 0, err)
        self.assertEqual(self.prompts, ["otpauth:// link or setup key: ", "Website [github.com]: ",
                                        "Save this authenticator code? [y/N] "])
        self.assertIn("Saved the authenticator code for github.com.", out)
        [entry] = self.codes()
        self.assertEqual((entry.site, entry.issuer, entry.account), ("github.com", "github.com", "octocat"))
        self.assertEqual(self.fixture.store.totp_unseal(self.fixture.uid, entry), SECRET)
        self.assertEqual(self.checks(), [ACTION_MANAGE])

        # A bare key, a site typed at the prompt and flags that replace the link's labels.
        code, _, err = self.run_cli("totp", "add", "--issuer", "Mail", "--account", "me", tty=True,
                                    passphrases=[KEY.lower()], typed=["mail.example", "y"])
        self.assertEqual(code, 0, err)
        self.assertEqual(self.prompts[1], "Website: ")
        self.assertIn(("mail.example", "Mail", "me"), {(e.site, e.issuer, e.account) for e in self.codes()})

    def test_add_cancelled_or_unusable_sends_nothing(self):
        code, out, _ = self.run_cli("totp", "add", "--site", "github.com", tty=True, passphrases=[LINK], typed=["n"])
        self.assertEqual(code, 1)
        self.assertIn("Nothing added.", out)
        for text, message in (("otpauth://hotp/x?secret=" + KEY, "HOTP"), ("ABC", "not a valid setup key"), ("", "")):
            with self.subTest(text=text):
                code, _, err = self.run_cli("totp", "add", "-y", stdin=text + "\n")
                self.assertEqual(code, 1)
                self.assertIn(message, err)
        self.assertEqual(self.codes(), [])
        self.assertEqual(self.checks(), [])

    def test_add_reads_one_line_of_stdin_without_a_terminal(self):
        code, _, err = self.run_cli("totp", "add", "-y", stdin=LINK + "\nnot read\n")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.prompts, [], "no prompt without a terminal")
        self.assertEqual(self.codes()[0].site, "github.com")

    def test_a_website_is_reduced_to_its_host_name(self):
        code, _, err = self.run_cli("totp", "add", "--account", "a", tty=True, passphrases=[KEY],
                                    typed=["https://GitHub.com/login", "y"])
        self.assertEqual(code, 0, err)
        # Without a terminal nothing is asked: --site, else the issuer's suggestion, else none.
        code, _, err = self.run_cli("totp", "add", "-y", "--site", " https://Mail.Example/inbox ",
                                    "--account", "b", stdin=KEY + "\n")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.prompts, [])
        code, _, err = self.run_cli("totp", "add", "-y", "--account", "c", stdin=KEY + "\n")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.prompts, [])
        sites = {e.account: e for e in self.codes()}
        self.assertEqual({account: e.site for account, e in sites.items()},
                         {"a": "github.com", "b": "mail.example", "c": ""})
        code, _, err = self.run_cli("totp", "edit", sites["c"].id.hex()[:8], "--site", "HTTPS://GitLab.com/")
        self.assertEqual(code, 0, err)
        self.assertEqual({e.account: e.site for e in self.codes()}["c"], "gitlab.com")

    def test_add_and_edit_strip_the_labels_they_send(self):
        with patch("localpasskey.cli._ask", wraps=cli._ask) as ask:
            code, out, err = self.run_cli("totp", "add", "-y", "--issuer", " Mail ", "--account", "\tme ",
                                          stdin=KEY + "\n")
        self.assertEqual(code, 0, err)
        sent = ask.call_args.args[0]["entry"]
        self.assertEqual((sent["issuer"], sent["account"]), ("Mail", "me"))
        self.assertIn("Saved the authenticator code for Mail.", out)
        [entry] = self.codes()
        with patch("localpasskey.cli._ask", wraps=cli._ask) as ask:
            code, out, err = self.run_cli("totp", "edit", entry.id.hex()[:8], "--issuer", " Post ",
                                          "--account", "you\n")
        self.assertEqual(code, 0, err)
        sent = ask.call_args.args[0]
        self.assertEqual((sent["issuer"], sent["account"]), ("Post", "you"))
        self.assertIn("Changed the authenticator code for Post.", out)

    def test_code_prints_only_the_code(self):
        github, _ = self.store_code(), self.store_code(site="gitlab.com", issuer="GitLab", account="tanuki")
        for query in ("GITHUB", github.id.hex()[:6], "octo"):
            with self.subTest(query=query):
                before = totp.code(SECRET)[0]
                code, out, err = self.run_cli("totp", "code", query)
                self.assertEqual(code, 0, err)
                self.assertIn(out.strip(), (before, totp.code(SECRET)[0]))
                self.assertRegex(err, r"^valid for \d+ more seconds\n$")
        sent = self.fixture.polkit.checks[-1]
        self.assertEqual(sent[1], ACTION_TOTP)
        self.assertEqual(sent[2], "Show the authenticator code for github.com?")
        self.assertEqual(self.checks(), [ACTION_TOTP] * 3, "a one-shot prompt each time")

        code, out, err = self.run_cli("totp", "code", "git")
        self.assertEqual((code, out), (1, ""))
        self.assertIn("2 authenticator codes match 'git'", err)
        self.assertIn("gitlab.com", err)
        code, out, err = self.run_cli("totp", "code", "nothing")
        self.assertEqual((code, out), (1, ""))
        self.assertIn("no authenticator code matches 'nothing'", err)
        self.assertEqual(len(self.checks()), 3)

    def test_edit(self):
        entry = self.store_code()
        code, out, err = self.run_cli("totp", "edit", entry.id.hex()[:8], "--site", "", "--account", "hubot")
        self.assertEqual(code, 0, err)
        self.assertIn("Changed the authenticator code for GitHub.", out)
        [entry] = self.codes()
        self.assertEqual((entry.site, entry.issuer, entry.account), ("", "GitHub", "hubot"))
        code, _, err = self.run_cli("totp", "edit", entry.id.hex()[:8])
        self.assertEqual(code, 1)
        self.assertIn("say what to change", err)
        self.assertEqual(self.checks(), [ACTION_MANAGE])

    def test_delete_restore_and_purge(self):
        github = self.store_code()
        self.store_code(site="gitlab.com", issuer="GitLab", account="tanuki")
        code, out, _ = self.run_cli("totp", "delete", "--all", typed=["n"])
        self.assertEqual(code, 1)
        self.assertEqual(self.prompts, ["Move these 2 authenticator codes to the trash? [y/N] "])
        self.assertIn("Nothing deleted.", out)
        code, _, err = self.run_cli("totp", "delete")
        self.assertIn("say which authenticator codes to delete", err)
        self.assertEqual(self.checks(), [])

        code, out, err = self.run_cli("totp", "delete", "--site", "github.com", "-y")
        self.assertEqual(code, 0, err)
        self.assertIn("Moved 1 authenticator code to the trash.", out)
        self.assertEqual([e.id for e in self.codes(trash=True)], [github.id])
        code, out, err = self.run_cli("totp", "list", "--trash")
        self.assertIn("DELETED", out)
        code, out, err = self.run_cli("totp", "restore", github.id.hex()[:8], typed=["y"])
        self.assertEqual(code, 0, err)
        self.assertEqual(self.prompts, ["Restore this authenticator code? [y/N] "])
        self.assertIn("Restored 1 authenticator code.", out)
        self.assertEqual(len(self.codes()), 2)

        # Purge asks to type the site, or the issuer when there is no site.
        nameless = self.store_code(site="", issuer="Bank", account="")
        self.fixture.store.totp_remove(self.fixture.uid, self.fixture.name, [nameless.id])
        code, out, _ = self.run_cli("totp", "purge", nameless.id.hex()[:8], typed=["nope"])
        self.assertEqual(code, 1)
        self.assertIn("Nothing deleted.", out)
        self.assertTrue(self.prompts[0].startswith('Type "Bank" to permanently delete this authenticator code.'))
        code, out, err = self.run_cli("totp", "purge", nameless.id.hex()[:8], typed=["bank"])
        self.assertEqual(code, 0, err)
        self.assertIn("Permanently deleted the authenticator code for Bank.", out)
        self.assertEqual(self.codes(trash=True), [])

    def test_purge_asks_for_the_site_else_the_issuer_else_delete(self):
        # The wrong answer is what a user might type instead: the issuer, the account, the old ID prefix.
        for site, issuer, name, done, wrong in (("github.com", "GitHub", "github.com", "github.com", "GitHub"),
                                                ("", "Bank", "Bank", "Bank", "me"),
                                                ("", "", "delete", "an account", None)):
            with self.subTest(name=name):
                entry = self.store_code(site=site, issuer=issuer, account="me")
                self.fixture.store.totp_remove(self.fixture.uid, self.fixture.name, [entry.id])
                prefix = entry.id.hex()[:8]
                for typed in (wrong or prefix, ""):
                    code, out, _ = self.run_cli("totp", "purge", prefix, typed=[typed])
                    self.assertEqual(code, 1, typed)
                    self.assertIn("Nothing deleted.", out)
                self.assertTrue(self.prompts[0].startswith(
                    f'Type "{name}" to permanently delete this authenticator code.'), self.prompts)
                code, out, err = self.run_cli("totp", "purge", prefix, typed=[f"  {name.upper()} "])
                self.assertEqual(code, 0, err)
                self.assertIn(f"Permanently deleted the authenticator code for {done}.", out)
                self.assertEqual(self.codes(trash=True), [])
        self.assertEqual(self.checks(), [ACTION_MANAGE] * 3, "a wrong name never reaches the service")

    def test_purge_ignores_spaces_around_the_name(self):
        # Saved before the service stripped labels; the typed text is stripped too.
        spaced = self.store_code(site="", issuer=" Bank ", account="")
        self.fixture.store.totp_remove(self.fixture.uid, self.fixture.name, [spaced.id])
        code, _, err = self.run_cli("totp", "purge", spaced.id.hex()[:8], typed=["bank"])
        self.assertEqual(code, 0, err)
        self.assertTrue(self.prompts[0].startswith('Type "Bank" to permanently delete this authenticator code.'))
        self.assertEqual(self.codes(trash=True), [])

    def test_settings(self):
        code, out, _ = self.run_cli("totp", "settings")
        self.assertEqual(out.strip(), "Your password is needed to show authenticator codes.")
        code, out, err = self.run_cli("totp", "settings", "--require-password", "no")
        self.assertEqual(code, 0, err)
        self.assertEqual(out.strip(), "Authenticator codes are shown without asking for your password.")
        self.assertFalse(self.fixture.store.totp_require_auth(self.fixture.uid, self.fixture.name))
        self.assertEqual(self.checks(), [ACTION_MANAGE])
        code, out, _ = self.run_cli("totp", "settings", "--require-password", "yes")
        self.assertEqual(code, 0)
        self.assertTrue(self.fixture.store.totp_require_auth(self.fixture.uid, self.fixture.name))
        self.assertEqual(self.checks(), [ACTION_MANAGE], "turning it on never asks")

    def test_status_counts_codes(self):
        self.store_code()
        code, out, err = self.run_cli("status")
        self.assertEqual(code, 0, err)
        self.assertIn("Passkeys stored for you: 3\nAuthenticator codes stored for you: 1\n", out)

    def test_status_reports_a_failing_code_count_after_the_passkeys(self):
        self.fixture.store._totp_path(self.fixture.uid).write_text("{not json")
        code, out, err = self.run_cli("status")
        self.assertEqual(code, 1)
        self.assertTrue(out.endswith("Passkeys stored for you: 3\n"), out)
        self.assertTrue(err.startswith("Authenticator codes: "), err)
        self.assertIn("totp.json is not valid JSON", err)
        self.assertEqual(err.count("\n"), 1)

    def test_export_includes_codes_unless_told_not_to(self):
        github = self.store_code()
        self.store_code(site="gitlab.com", issuer="GitLab", account="tanuki")
        path = os.path.join(self.tmp, "all.lpkbackup")
        with patch("localpasskey.cli.request", wraps=cli.request) as sent:
            code, out, err = self.run_cli("export", path, passphrases=[self.PASSPHRASE] * 2)
        self.assertEqual(code, 0, err)
        self.assertEqual(sent.call_args_list[0].args[0], {"command": "export", "all": True, "dry_run": True,
                                                         "codes": True})
        confirmed = sent.call_args_list[-1].args[0]
        self.assertEqual(sorted(confirmed["code_ids"]), sorted(e.id.hex() for e in self.codes()))
        self.assertIn("gitlab.com", out)
        self.assertIn("Exported 3 passkeys and 2 authenticator codes to", out)
        self.assertEqual(self.checks(), [ACTION_EXPORT])
        with open(path, "rb") as stream:
            records = transfer.load(stream.read(), lambda: self.PASSPHRASE)
        self.assertEqual((len(records), len(records.codes)), (3, 2))

        path = os.path.join(self.tmp, "passkeys.lpkbackup")
        with patch("localpasskey.cli.request", wraps=cli.request) as sent:
            code, out, err = self.run_cli("export", path, "--no-codes", passphrases=[self.PASSPHRASE] * 2)
        self.assertEqual(code, 0, err)
        self.assertNotIn("codes", sent.call_args_list[0].args[0])
        self.assertNotIn("code_ids", sent.call_args_list[-1].args[0])
        self.assertIn("Exported 3 passkeys to", out)
        self.assertNotIn("github.com", out.replace(path, ""))
        with open(path, "rb") as stream:
            self.assertEqual(transfer.load(stream.read(), lambda: self.PASSPHRASE).codes, [])

        # --site picks the codes for that site too.
        path = os.path.join(self.tmp, "site.lpkbackup")
        code, out, err = self.run_cli("export", path, "--site", "github.com", passphrases=[self.PASSPHRASE] * 2)
        self.assertEqual(code, 0, err)
        self.assertIn("Exported 1 authenticator code to", out)
        with open(path, "rb") as stream:
            self.assertEqual(transfer.load(stream.read(), lambda: self.PASSPHRASE).codes[0]["id"],
                             b64encode(github.id))

    def test_export_of_codes_only(self):
        ids = [c.id for c in self.fixture.creds]
        self.fixture.store.remove(self.fixture.uid, self.fixture.name, ids)
        self.fixture.store.purge(self.fixture.uid, self.fixture.name, ids)
        self.store_code()
        path = os.path.join(self.tmp, "codes.lpkbackup")
        code, out, err = self.run_cli("export", path, passphrases=[self.PASSPHRASE] * 2)
        self.assertEqual(code, 0, err)
        self.assertNotIn("LAST USED", out)
        self.assertIn("Exported 1 authenticator code to", out)
        with open(path, "rb") as stream:
            records = transfer.load(stream.read(), lambda: self.PASSPHRASE)
        self.assertEqual((len(records), len(records.codes)), (0, 1))

    def test_cxf_export_says_codes_are_left_out(self):
        path = os.path.join(self.tmp, "keys.json")
        code, _, err = self.run_cli("export", path, "--format", "cxf", "--unencrypted")
        self.assertEqual(code, 0, err)
        self.assertNotIn("authenticator codes", err)
        self.store_code()
        with patch("localpasskey.cli.request", wraps=cli.request) as sent:
            code, out, err = self.run_cli("export", path, "--format", "cxf", "--unencrypted", "--force")
        self.assertEqual(code, 0, err)
        self.assertIn("authenticator codes are not included in CXF files", err)
        self.assertIn("Exported 3 passkeys to", out)
        self.assertTrue(all("codes" not in call.args[0] and "code_ids" not in call.args[0]
                            for call in sent.call_args_list))

    def test_import_plans_and_sends_codes(self):
        existing = self.store_code()
        fresh = code_record(TotpEntry(id=os.urandom(16), sealed_secret=b"", site="gitlab.com", issuer="GitLab",
                                      account="tanuki", created=1700000000.0), SECRET)
        bad = {**fresh, "id": b64encode(os.urandom(16)), "secret": "1", "site": "bad.example"}
        cred = self.fixture.normalized()
        path = os.path.join(self.tmp, "keys.lpkbackup")
        with open(path, "wb") as stream:
            stream.write(transfer.export_backup(
                [cred], self.PASSPHRASE,
                [code_record(existing, SECRET), fresh, dict(fresh), bad]))

        code, out, err = self.run_cli("import", path, passphrases=[self.PASSPHRASE], typed=["n"])
        self.assertEqual(code, 1, err)
        self.assertEqual(self.prompts[-1], "Import 1 passkey and 1 authenticator code? [y/N] ")
        self.assertIn("gitlab.com", out)
        for reason in ("already on this computer", "duplicate in the file", "not a valid setup key"):
            self.assertIn(reason, out)
        self.assertIn("bad.example", out)
        self.assertIn("Nothing imported.", out)
        self.assertEqual(len(self.codes()), 1)

        with patch("localpasskey.cli.request", wraps=cli.request) as sent:
            code, out, err = self.run_cli("import", path, "--yes", passphrases=[self.PASSPHRASE])
        self.assertEqual(code, 0, err)
        self.assertEqual([r["site"] for r in sent.call_args_list[-1].args[0]["codes"]], ["gitlab.com"])
        self.assertIn("Imported 1 passkey and 1 authenticator code.", out)
        self.assertEqual(sorted(e.site for e in self.codes()), ["github.com", "gitlab.com"])
        self.assertEqual(self.checks()[-1], ACTION_MANAGE)

        # Everything is here now: nothing to import, nothing asked.
        checks = len(self.checks())
        code, out, err = self.run_cli("import", path, passphrases=[self.PASSPHRASE])
        self.assertEqual(code, 0, err)
        self.assertIn("Nothing to import.", out)
        self.assertEqual(len(self.checks()), checks)

    def test_import_without_codes_sends_no_codes(self):
        path = os.path.join(self.tmp, "keys.lpkbackup")
        with open(path, "wb") as stream:
            stream.write(transfer.export_backup([self.fixture.normalized()], self.PASSPHRASE))
        with patch("localpasskey.cli.request", wraps=cli.request) as sent:
            code, out, err = self.run_cli("import", path, "--yes", passphrases=[self.PASSPHRASE])
        self.assertEqual(code, 0, err)
        self.assertTrue(all("codes" not in call.args[0] for call in sent.call_args_list))
        self.assertIn("Imported 1 passkey.", out)

    def test_import_with_nothing_left_after_the_dialog_says_0_passkeys(self):
        fresh = self.fixture.normalized()
        path = os.path.join(self.tmp, "fresh.lpkbackup")
        with open(path, "wb") as stream:
            stream.write(transfer.export_backup([fresh], self.PASSPHRASE))

        def imported_meanwhile(subject, action_id, message, cancelled=None, timeout=120.0):
            store = self.fixture.store
            store.add(self.fixture.uid, self.fixture.name, _parse_record(0, fresh, store, self.fixture.uid))
            return Verdict.APPROVED

        self.fixture.polkit.check = imported_meanwhile
        code, out, err = self.run_cli("import", path, "--yes", passphrases=[self.PASSPHRASE])
        self.assertEqual(code, 0, err)
        self.assertIn("Imported 0 passkeys; 1 could no longer be imported:", out)

    def test_export_with_nothing_left_after_the_dialog_says_0_passkeys(self):
        def deleted_meanwhile(subject, action_id, message, cancelled=None, timeout=120.0):
            self.fixture.store.remove(self.fixture.uid, self.fixture.name, [c.id for c in self.fixture.creds])
            return Verdict.APPROVED

        self.fixture.polkit.check = deleted_meanwhile
        path = os.path.join(self.tmp, "keys.lpkbackup")
        code, out, err = self.run_cli("export", path, passphrases=[self.PASSPHRASE] * 2)
        self.assertEqual(code, 0, err)
        self.assertIn(f"Exported 0 passkeys to {path}.", out)


class CliTotpProcessTests(unittest.TestCase):
    def test_add_from_a_pipe_and_list(self):
        fixture = test_control.ControlTests()
        fixture.setUp()
        self.addCleanup(fixture.tearDown)
        fixture.server.start()

        def run(*args, input=""):
            return subprocess.run(
                [sys.executable, str(Path(__file__).resolve().parents[1] / "bin/localpasskey"),
                 "--socket", fixture.server.path, "totp", *args],
                input=input, capture_output=True, text=True, timeout=15,
            )
        result = run("add", input=LINK + "\ny\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Saved the authenticator code for github.com.", result.stdout)
        self.assertNotIn(KEY, result.stdout + result.stderr)
        result = run("list")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("6 digits · 30 s", result.stdout)


if __name__ == "__main__":
    unittest.main()
