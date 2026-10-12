import contextlib
import io
import json
import os
import subprocess
import sys
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from localpasskey import cli
from localpasskey.ctap2 import Verdict
from localpasskey.store import MAX_CREDENTIALS_PER_USER
from tests import test_control


class CliTests(unittest.TestCase):
    def test_delete_only_sends_the_ids_shown_in_the_preview(self):
        credential = {
            "id": "1234" * 16, "site": "example.com", "user_name": "alice",
            "display_name": "Alice", "discoverable": True, "created": 0, "last_used": 0,
        }
        for selector in (["--all"], ["--site", "example.com"], ["1234"]):
            with (
                self.subTest(selector=selector),
                patch("localpasskey.cli.request", return_value={"deleted": [credential]}) as request,
                patch("localpasskey.cli._start_tty_agent", return_value=None),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(cli.main(["delete", "--yes", *selector]), 0)
                self.assertEqual(request.call_args.args[0], {
                    "command": "delete", "ids": [credential["id"]],
                })

    def test_conflicting_selectors_do_not_send_a_request(self):
        for selectors in (["--all", "--site", "example.com"], ["--all", "abcd"], ["--site", "example.com", "abcd"]):
            with (
                self.subTest(selectors=selectors),
                patch("localpasskey.cli.request") as request,
                contextlib.redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(cli.main(["delete", "--yes", *selectors]), 1)
                request.assert_not_called()

    def test_terminal_control_sequences_are_not_rendered(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            cli._print_table(("SITE", "ACCOUNT"), [("example.com", "\x1b[2Jalice\nforged row\r\x07")])
        self.assertNotIn("\x1b", output.getvalue())
        self.assertNotIn("\r", output.getvalue())
        self.assertNotIn("\x07", output.getvalue())
        self.assertEqual(len(output.getvalue().splitlines()), 2)


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
        self.assertIn("Deleted 2 passkeys.", result.stdout)
        self.assertEqual([c.rp_id for c in self.fixture.store.credentials(self.fixture.uid, self.fixture.name)], ["other.org"])

    def test_denied_delete_preserves_all_credentials(self):
        if os.getuid() == 0:
            self.skipTest("root intentionally bypasses polkit")
        self.fixture.polkit.verdict = Verdict.DENIED
        result = self.run_cli("delete", "--all", "--yes")
        self.assertEqual(result.returncode, 1)
        self.assertIn("authentication denied", result.stderr)
        self.assertEqual(len(self.fixture.store.credentials(self.fixture.uid, self.fixture.name)), 3)

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
        self.assertIn(f"Deleted {MAX_CREDENTIALS_PER_USER} passkeys.", result.stdout)
        self.assertEqual(self.fixture.store.credentials(self.fixture.uid, self.fixture.name), [])

    def test_root_only_user_selection_is_enforced_over_socket(self):
        if os.getuid() == 0:
            self.skipTest("test needs an unprivileged caller")
        result = self.run_cli("list", "--user", "root")
        self.assertEqual(result.returncode, 1)
        self.assertIn("only root", result.stderr)


if __name__ == "__main__":
    unittest.main()
