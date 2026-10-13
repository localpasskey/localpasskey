import errno
import json
import os
import pwd
import socket
import tempfile
import threading
import time
import unittest

from localpasskey import client, cose
from localpasskey.clientpin import MAX_PIN_RETRIES
from localpasskey.control import MAX_REQUEST, ControlError, ControlServer
from localpasskey.ctap2 import Verdict
from localpasskey.polkit import ACTION_MANAGE
from localpasskey.store import Credential, CredentialStore


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
        self.server._notify_deleted(self.uid, many, caller_uid=self.uid + 1, what="moved to the trash")
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
