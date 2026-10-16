import contextlib
import errno
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from localpasskey import cli, transfer
from localpasskey.control import record
from localpasskey.ctap2 import Verdict
from localpasskey.store import MAX_CREDENTIALS_PER_USER
from tests import test_control


class CliTests(unittest.TestCase):
    def test_the_ids_shown_in_the_preview_are_the_only_ones_sent(self):
        credential = {
            "id": "1234" * 16, "site": "example.com", "deleted": 1000.0, "created": 0,
            "user_name": "alice", "display_name": "Alice", "discoverable": True, "last_used": 0,
        }
        for command in ("delete", "restore"):
            for selector in (["--all"], ["--site", "example.com"], ["1234"]):
                replied = {"deleted": [credential]} if command == "delete" else {
                    "deleted": [credential], "restored": [credential]
                }
                with (
                    self.subTest(command=command, selector=selector),
                    patch("localpasskey.cli.request", side_effect=[replied, replied]) as request,
                    patch("localpasskey.cli._start_tty_agent", return_value=None),
                    contextlib.redirect_stdout(io.StringIO()),
                ):
                    self.assertEqual(cli.main([command, "--yes", *selector]), 0)
                    self.assertEqual(request.call_args.args[0], {
                        "command": command, "ids": [credential["id"]],
                    })

    def test_conflicting_selectors_do_not_send_a_request(self):
        for command in ("delete", "restore"):
            for selectors in (["--all", "--site", "example.com"], ["--all", "abcd"],
                              ["--site", "example.com", "abcd"]):
                with (
                    self.subTest(command=command, selectors=selectors),
                    patch("localpasskey.cli.request") as request,
                    contextlib.redirect_stderr(io.StringIO()),
                ):
                    self.assertEqual(cli.main([command, "--yes", *selectors]), 1)
                    request.assert_not_called()

    def test_purge_needs_the_site_typed_and_has_no_yes_flag(self):
        credential = {
            "id": "1234" * 16, "site": "example.com", "deleted": 1000.0, "created": 0,
            "user_name": "alice", "display_name": "Alice", "discoverable": True, "last_used": 0,
        }
        with patch("localpasskey.cli.request") as request:
            with contextlib.redirect_stderr(io.StringIO()) as errors:
                with self.assertRaises(SystemExit):
                    cli.main(["purge", "1234", "--yes"])
            request.assert_not_called()
        self.assertIn("--yes", errors.getvalue())

        for typed, expected in (("nope\n", 1), ("\n", 1), ("example.com\n", 0), ("Example.COM\n", 0)):
            with (
                self.subTest(typed=typed),
                patch("localpasskey.cli.request", return_value={"deleted": [credential]}) as request,
                patch("localpasskey.cli.input", return_value=typed, create=True),
                patch("localpasskey.cli._start_tty_agent", return_value=None),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(cli.main(["purge", "1234"]), expected)
                sent = [call.args[0] for call in request.call_args_list]
                self.assertEqual(len(sent), 2 if expected == 0 else 1, "a mismatch must not reach the daemon")
                self.assertEqual(sent[0]["dry_run"], True)

    def test_purge_and_errors_do_not_echo_control_characters(self):
        credential = {
            "id": "1234" * 16, "site": "evil\u200b.example\x1b]0;pwned\x07", "deleted": 1000.0, "created": 0,
            "user_name": "alice", "display_name": "Alice", "discoverable": True, "last_used": 0,
        }
        with (
            patch("localpasskey.cli.request", return_value={"deleted": [credential]}),
            patch("localpasskey.cli.input", return_value="evil.example]0;pwned\n", create=True) as typed,
            patch("localpasskey.cli._start_tty_agent", return_value=None),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            self.assertEqual(cli.main(["purge", "1234"]), 0)
        for text in (typed.call_args.args[0], output.getvalue()):
            self.assertFalse(any(ch in text for ch in "\x1b\x07\u200b"))
        with (
            patch("localpasskey.cli.request", side_effect=cli.ServiceError("bad site: \x1b]0;pwned\x07")),
            contextlib.redirect_stderr(io.StringIO()) as errors,
        ):
            self.assertEqual(cli.main(["list"]), 1)
        self.assertNotIn("\x1b", errors.getvalue())

    def test_user_selection_reaches_the_daemon(self):
        credential = {
            "id": "1234" * 16, "site": "example.com", "deleted": 1000.0, "created": 0,
            "user_name": "alice", "display_name": "Alice", "discoverable": True, "last_used": 0,
        }
        replies = {
            "delete": {"deleted": [credential]},
            "list": {"credentials": [credential]},
            "pin": {"set": False, "retries": 8},
        }
        for command, extra in (("delete", ["--all", "--yes"]), ("list", []), ("pin", ["status"])):
            with (
                self.subTest(command=command),
                patch("localpasskey.cli.request", return_value=replies[command]) as request,
                patch("localpasskey.cli._start_tty_agent", return_value=None),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                cli.main([command, *extra, "--user", "alice"])
                self.assertEqual(request.call_args.args[0]["user"], "alice")

    def test_purge_takes_exactly_one_id(self):
        with patch("localpasskey.cli.request") as request:
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                cli.main(["purge", "1234", "abcd"])
            request.assert_not_called()

    def test_pin_set_reads_the_pin_twice(self):
        with (
            patch("localpasskey.cli.getpass.getpass", side_effect=["1234", "1234"]) as getpass,
            patch("localpasskey.cli.request", return_value={"ok": True}) as request,
            patch("localpasskey.cli._start_tty_agent", return_value=None),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            self.assertEqual(cli.main(["pin", "set"]), 0)
        self.assertEqual(getpass.call_args_list[0].args, ("New PIN: ",))
        self.assertEqual(request.call_args.args[0], {"command": "pin", "action": "set", "pin": "1234"})
        self.assertEqual(output.getvalue().strip(), "Security key PIN set.")

        with (
            patch("localpasskey.cli.getpass.getpass", side_effect=["1234", "4321"]),
            patch("localpasskey.cli.request") as request,
            contextlib.redirect_stderr(io.StringIO()) as errors,
        ):
            self.assertEqual(cli.main(["pin", "set"]), 1)
        self.assertIn("the PINs do not match", errors.getvalue())
        request.assert_not_called()

    def test_pin_status_and_remove(self):
        with (
            patch("localpasskey.cli.request",
                  return_value={"ok": True, "user": "alice", "set": True, "retries": 7}),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            self.assertEqual(cli.main(["pin", "status"]), 0)
        self.assertEqual(output.getvalue().strip(), "A security key PIN is set (7 attempts left).")

        with (
            patch("localpasskey.cli.request",
                  return_value={"ok": True, "user": "alice", "set": False, "retries": 8}),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            self.assertEqual(cli.main(["pin", "status"]), 0)
        self.assertEqual(output.getvalue().strip(), "No security key PIN is set. Browsers need one to list or delete passkeys.")

        with (
            patch("localpasskey.cli.request", return_value={"ok": True}) as request,
            patch("localpasskey.cli._start_tty_agent", return_value=None),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            self.assertEqual(cli.main(["pin", "remove"]), 0)
        self.assertEqual(request.call_args.args[0], {"command": "pin", "action": "remove"})
        self.assertEqual(output.getvalue().strip(), "Security key PIN removed.")

    def test_list_prints_the_trash_with_its_own_columns(self):
        trashed = {
            "id": "1234" * 16, "site": "example.com", "deleted": 1700000000.0, "created": 1600000000.0,
            "user_name": "alice", "display_name": "Alice", "discoverable": True, "last_used": 0,
        }
        with (
            patch("localpasskey.cli.request", return_value={"ok": True, "user": "alice",
                                                           "credentials": [trashed]}) as request,
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            self.assertEqual(cli.main(["list", "--trash"]), 0)
        self.assertEqual(request.call_args.args[0], {"command": "list", "trash": True})
        self.assertIn("DELETED", output.getvalue())

        with (
            patch("localpasskey.cli.request", return_value={"ok": True, "user": "alice",
                                                           "credentials": []}),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            self.assertEqual(cli.main(["list", "--trash"]), 0)
        self.assertEqual(output.getvalue().strip(), "The trash is empty.")

    def test_terminal_control_sequences_are_not_rendered(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            cli._print_table(("SITE", "ACCOUNT"), [("example.com", "\x1b[2Jalice\nforged row\r\x07")])
        self.assertNotIn("\x1b", output.getvalue())
        self.assertNotIn("\r", output.getvalue())
        self.assertNotIn("\x07", output.getvalue())
        self.assertEqual(len(output.getvalue().splitlines()), 2)


    def test_write_private_file_never_follows_links_or_leaves_half_a_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            target, victim = os.path.join(tmp, "keys"), os.path.join(tmp, "victim")
            os.symlink(victim, target)
            with self.assertRaises(FileExistsError):
                cli.write_private_file(target, b"secret")
            self.assertFalse(os.path.lexists(victim))
            with open(victim, "w") as stream:
                stream.write("victim")
            stale = os.path.join(tmp, f".keys.{os.getpid()}.tmp")
            open(stale, "w").close()  # left by an earlier run that was killed
            cli.write_private_file(target, b"secret", overwrite=True)
            os.unlink(stale)
            with open(victim) as stream:
                self.assertEqual(stream.read(), "victim")
            self.assertFalse(os.path.islink(target))
            self.assertEqual(os.stat(target).st_mode & 0o777, 0o600)
            real_fdopen = os.fdopen

            def full_disk(fd, mode):
                stream = real_fdopen(fd, mode)
                stream.write = lambda data: (_ for _ in ()).throw(OSError(errno.ENOSPC, "No space left"))
                return stream
            with patch("os.fdopen", full_disk):
                with self.assertRaises(OSError):
                    cli.write_private_file(target, b"new", overwrite=True)
                with self.assertRaises(OSError):
                    cli.write_private_file(os.path.join(tmp, "fresh"), b"new")
            with patch("os.replace", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
                cli.write_private_file(target, b"new", overwrite=True)
            with open(target, "rb") as stream:
                self.assertEqual(stream.read(), b"secret")
            self.assertEqual(sorted(os.listdir(tmp)), ["keys", "victim"])

class CliProcessTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_control.ControlTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.fixture.server.start()

    def run_cli(self, *args, input=""):
        return subprocess.run(
            [sys.executable, str(Path(__file__).resolve().parents[1] / "bin/localpasskey"),
             "--socket", self.fixture.server.path, *args],
            input=input, capture_output=True, text=True, timeout=15,
        )

    def test_list_status_cancel_delete_and_authenticated_delete(self):
        result = self.run_cli("list", "--json")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(json.loads(result.stdout)), 3)
        result = self.run_cli("status")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Passkeys stored for you: 3", result.stdout)
        result = self.run_cli("delete", "--all", input="n\n")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(self.fixture.polkit.checks, [])
        self.assertEqual(len(self.fixture.store.credentials(self.fixture.uid, self.fixture.name)), 3)
        result = self.run_cli("delete", "--site", "example.com", "--yes")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Moved 2 passkeys to the trash.", result.stdout)
        self.assertEqual([c.rp_id for c in self.fixture.store.credentials(self.fixture.uid, self.fixture.name)], ["other.org"])
        self.assertEqual(len(self.fixture.store.trash(self.fixture.uid, self.fixture.name)), 2)
        result = self.run_cli("list", "--trash")
        self.assertIn("DELETED", result.stdout)
        result = self.run_cli("restore", "--site", "example.com", "--yes")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Restored 2 passkeys.", result.stdout)
        self.assertEqual(len(self.fixture.store.credentials(self.fixture.uid, self.fixture.name)), 3)
        result = self.run_cli("list", "--trash")
        self.assertEqual(result.stdout.strip(), "The trash is empty.")

    def test_purge_from_the_trash(self):
        result = self.run_cli("delete", "--all", "--yes")
        self.assertEqual(result.returncode, 0, result.stderr)
        prefix = self.fixture.creds[0].id.hex()[:8]
        result = self.run_cli("purge", prefix, input="nope\n")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("Nothing deleted.", result.stdout)
        self.assertEqual(len(self.fixture.store.trash(self.fixture.uid, self.fixture.name)), 3)
        result = self.run_cli("purge", prefix, input="example.com\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Permanently deleted the passkey for example.com.", result.stdout)
        self.assertEqual(len(self.fixture.store.trash(self.fixture.uid, self.fixture.name)), 2)

    def test_pin_status_set_and_remove(self):
        result = self.run_cli("pin", "status")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "No security key PIN is set. Browsers need one to list or delete passkeys.")
        result = self.run_cli("pin", "set", input="1234\n1234\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Security key PIN set.", result.stdout)
        result = self.run_cli("pin", "status")
        self.assertIn("A security key PIN is set (8 attempts left).", result.stdout)
        result = self.run_cli("pin", "remove")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Security key PIN removed.", result.stdout)
        result = self.run_cli("pin", "status")
        self.assertEqual(result.stdout.strip(), "No security key PIN is set. Browsers need one to list or delete passkeys.")

    def test_denied_delete_preserves_all_credentials(self):
        if os.getuid() == 0:
            self.skipTest("root intentionally bypasses polkit")
        self.fixture.polkit.verdict = Verdict.DENIED
        result = self.run_cli("delete", "--all", "--yes")
        self.assertEqual(result.returncode, 1)
        self.assertIn("authentication denied", result.stderr)
        self.assertEqual(len(self.fixture.store.credentials(self.fixture.uid, self.fixture.name)), 3)
        self.assertEqual(self.fixture.store.trash(self.fixture.uid, self.fixture.name), [])

    def test_delete_all_at_full_store_capacity(self):
        template = self.fixture.creds[0]
        secret = self.fixture.store.unseal(self.fixture.uid, template)
        credentials = []
        for i in range(MAX_CREDENTIALS_PER_USER):
            cred_id = i.to_bytes(32, "big")
            credentials.append(replace(
                template, id=cred_id, user_id=str(i).encode(),
                sealed_key=self.fixture.store.seal(self.fixture.uid, cred_id, secret),
            ))
        self.fixture.store._write(self.fixture.uid, self.fixture.name, credentials)
        result = self.run_cli("delete", "--all", "--yes")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"Moved {MAX_CREDENTIALS_PER_USER} passkeys to the trash.", result.stdout)
        self.assertEqual(self.fixture.store.credentials(self.fixture.uid, self.fixture.name), [])
        # The file keeps every record so that restore can still bring them back.
        self.assertEqual(len(self.fixture.store.trash(self.fixture.uid, self.fixture.name)),
                         MAX_CREDENTIALS_PER_USER)
        self.assertEqual(len(self.fixture.store._read(self.fixture.uid, self.fixture.name)),
                         MAX_CREDENTIALS_PER_USER)

    def test_root_only_user_selection_is_enforced_over_socket(self):
        if os.getuid() == 0:
            self.skipTest("test needs an unprivileged caller")
        result = self.run_cli("list", "--user", "root")
        self.assertEqual(result.returncode, 1)
        self.assertIn("only root", result.stderr)


class CliTransferTests(unittest.TestCase):
    """export and import end to end against the test control server, in this
    process so that the passphrase prompts can be answered."""

    PASSPHRASE = "correct horse"

    def setUp(self):
        self.fixture = test_control.ControlTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.fixture.server.start()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = tmp.name
        agent = patch("localpasskey.cli._start_tty_agent", return_value=None)
        agent.start()
        self.addCleanup(agent.stop)

    def run_cli(self, *args, passphrases=(), typed=()):
        with (
            patch("localpasskey.cli.getpass.getpass", side_effect=list(passphrases)) as getpass,
            patch("localpasskey.cli.input", side_effect=list(typed), create=True),
            contextlib.redirect_stdout(io.StringIO()) as out,
            contextlib.redirect_stderr(io.StringIO()) as err,
        ):
            code = cli.main(["--socket", self.fixture.server.path, *args])
        return code, out.getvalue(), err.getvalue(), getpass.call_count

    def live(self):
        return self.fixture.store.credentials(self.fixture.uid, self.fixture.name)

    def test_backup_round_trip_skips_what_is_already_here(self):
        path = os.path.join(self.tmp, "keys.lpkbackup")
        code, out, err, asked = self.run_cli("export", path, passphrases=[self.PASSPHRASE] * 2)
        self.assertEqual(code, 0, err)
        self.assertIn("Exported 3 passkeys", out)
        self.assertEqual(asked, 2)
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        self.assertEqual(self.fixture.polkit.checks[-1][1], "org.localpasskey.export")
        with open(path, "rb") as stream:
            self.assertEqual(len(transfer.load(stream.read(), lambda: self.PASSPHRASE)), 3)

        # Everything is still here: the plan skips all three and asks nothing.
        checks = len(self.fixture.polkit.checks)
        code, out, err, _ = self.run_cli("import", path, passphrases=[self.PASSPHRASE])
        self.assertEqual(code, 0, err)
        self.assertEqual(out.count("already on this computer"), 3)
        self.assertIn("Nothing to import.", out)
        self.assertEqual(len(self.fixture.polkit.checks), checks)

        # Purge them, then the backup brings them back, after a wrong passphrase.
        ids = [c.id for c in self.live()]
        self.fixture.store.remove(self.fixture.uid, self.fixture.name, ids)
        self.fixture.store.purge(self.fixture.uid, self.fixture.name, ids)
        code, out, err, asked = self.run_cli("import", path, passphrases=["wrong one", self.PASSPHRASE],
                                             typed=["y"])
        self.assertEqual(code, 0, err)
        self.assertIn("Wrong passphrase", err)
        self.assertEqual(asked, 2)
        self.assertIn("Imported 3 passkeys.", out)
        self.assertEqual(sorted(c.id for c in self.live()), sorted(ids))

    def test_export_refuses_before_asking_the_daemon(self):
        path = os.path.join(self.tmp, "keys.lpkbackup")
        open(path, "w").close()
        cases = [
            (("export", path), [], "already exists"),
            (("export", path + "2", "--format", "cxf"), [], "--unencrypted"),
            (("export", path + "3", "--unencrypted"), [], "only --format cxf"),
            (("export", path + "4"), ["short", "short"], "at least 8 characters"),
            (("export", path + "5"), ["long enough", "different"], "the passphrases do not match"),
        ]
        for args, passphrases, message in cases:
            with self.subTest(args=args):
                code, _, err, _ = self.run_cli(*args, passphrases=passphrases)
                self.assertEqual(code, 1)
                self.assertIn(message, err)
        self.assertEqual(self.fixture.polkit.checks, [])
        self.assertEqual(sorted(os.listdir(self.tmp)), ["keys.lpkbackup"])

    def test_unencrypted_cxf_export_warns_and_force_replaces(self):
        path = os.path.join(self.tmp, "keys.json")
        with open(path, "w") as stream:
            stream.write("old")
        os.chmod(path, 0o644)
        code, out, err, asked = self.run_cli("export", path, "--site", "example.com", "--format", "cxf",
                                             "--unencrypted", "--force")
        self.assertEqual(code, 0, err)
        self.assertIn("NOT be encrypted", err)
        self.assertEqual(asked, 0)
        self.assertIn("Exported 2 passkeys", out)
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        with open(path, "rb") as stream:
            records = transfer.load(stream.read(), lambda: self.fail("CXF has no passphrase"))
        self.assertEqual(records.format, "cxf")
        self.assertEqual({r["rp_id"] for r in records}, {"example.com"})

    def test_import_reports_skips_and_cancel_imports_nothing(self):
        fresh = self.fixture.normalized()
        duplicate = dict(fresh)
        existing = transfer.load(
            transfer.export_cxf([cli_record(self.fixture, self.fixture.creds[0])]), lambda: "")[0]
        path = os.path.join(self.tmp, "keys.lpkbackup")
        with open(path, "wb") as stream:
            stream.write(transfer.export_backup([fresh, duplicate, existing], self.PASSPHRASE))
        code, out, err, _ = self.run_cli("import", path, passphrases=[self.PASSPHRASE], typed=["n"])
        self.assertEqual(code, 1, err)
        self.assertIn("duplicate in the file", out)
        self.assertIn("already on this computer", out)
        self.assertIn("Nothing imported.", out)
        self.assertEqual(len(self.live()), 3)
        code, out, err, _ = self.run_cli("import", path, "--yes", passphrases=[self.PASSPHRASE])
        self.assertEqual(code, 0, err)
        self.assertIn("Imported 1 passkey.", out)
        self.assertEqual(len(self.live()), 4)

    def test_import_of_a_file_that_is_not_supported(self):
        path = os.path.join(self.tmp, "notes.json")
        with open(path, "w") as stream:
            stream.write("[]")
        code, _, err, _ = self.run_cli("import", path)
        self.assertEqual(code, 1)
        self.assertIn("not a LocalPasskey backup", err)


def cli_record(fixture, cred):
    return record(cred, fixture.store.unseal(fixture.uid, cred))


if __name__ == "__main__":
    unittest.main()
