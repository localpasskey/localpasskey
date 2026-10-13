"""Open the window against a stand-in for localpasskeyd with sample passkeys.

    python3 -m tests.gui_demo

No root and no virtual device are involved: a ControlServer serves a
temporary store, and deleting "authenticates" after a second.
"""

import os
import pwd
import sys
import tempfile
import time

from localpasskey import cose
from localpasskey.control import ControlServer
from localpasskey.ctap2 import Verdict
from localpasskey.store import Credential, CredentialStore

# site, site name, user name, display name, passkey?, created (days ago), last used (hours ago)
SAMPLES = [
    ("github.com", "GitHub", "octocat", "The Octocat", True, 40, 2),
    ("github.com", "GitHub", "octo-work", "Octocat at work", True, 12, 30),
    ("google.com", "Google", "alice@example.com", "Alice Example", True, 90, 5),
    ("login.microsoft.com", "Microsoft", "alice@example.net", "Alice Example", True, 400, 72),
    ("amazon.com", "Amazon", "alice@example.com", "Alice Example", True, 30, None),
    ("proton.me", "Proton", "alice@example.org", "Alice Example", True, 60, 26),
    ("webauthn.io", "webauthn.io", "alice", "alice", False, 3, 1),
]

# site, site name, user name, display name, created (days ago), deleted (days ago)
TRASHED = [
    ("github.com", "GitHub", "octocat-old", "The Octocat", 200, 7),
    ("gitlab.com", "GitLab", "alice@example.com", "Alice Example", 15, 2),
]


class SlowApproval:
    def check(self, subject, action_id, message, cancelled=None, timeout=120.0):
        time.sleep(1)
        return Verdict.APPROVED


def start_backend():
    """Serve the sample passkeys; returns (server, tmpdir) to clean up."""
    tmp = tempfile.TemporaryDirectory()
    store = CredentialStore(os.path.join(tmp.name, "state"))
    uid = os.getuid()
    username = pwd.getpwuid(uid).pw_name
    now = time.time()
    for site, site_name, user, display, passkey, created_days, used_hours in SAMPLES:
        cred_id = os.urandom(32)
        key = cose.generate_private_key(cose.ES256)
        store.add(uid, username, Credential(
            id=cred_id, rp_id=site, user_id=user.encode(), alg=cose.ES256,
            sealed_key=store.seal(uid, cred_id, cose.private_key_to_bytes(key)),
            rp_name=site_name, user_name=user, user_display_name=display, discoverable=passkey,
            created=now - created_days * 86400,
            last_used=None if used_hours is None else now - used_hours * 3600,
        ))
    doomed = []
    for site, site_name, user, display, created_days, deleted_days in TRASHED:
        cred_id = os.urandom(32)
        key = cose.generate_private_key(cose.ES256)
        doomed.append((cred_id, now - deleted_days * 86400))
        store.add(uid, username, Credential(
            id=cred_id, rp_id=site, user_id=user.encode(), alg=cose.ES256,
            sealed_key=store.seal(uid, cred_id, cose.private_key_to_bytes(key)),
            rp_name=site_name, user_name=user, user_display_name=display, discoverable=True,
            created=now - created_days * 86400, last_used=now - (created_days - 1) * 86400,
        ))
    # Backdate the deleted stamps so the trash view shows a plausible age; the
    # store itself only ever stamps "now".
    store.remove(uid, username, [cred_id for cred_id, _ in doomed])
    records = store._read(uid, username)
    for record in records:
        for cred_id, deleted_at in doomed:
            if record.id == cred_id:
                record.deleted = deleted_at
    store._write(uid, username, records)

    path = os.path.join(tmp.name, "control.sock")
    server = ControlServer(path, store, SlowApproval(), lambda: {"version": "demo", "device": "/dev/hidraw-demo"})
    server.start()
    os.environ["LOCALPASSKEY_SOCKET"] = path
    return server, tmp


def main():
    server, tmp = start_backend()

    from localpasskey.gui import main as run_window

    try:
        return run_window(sys.argv[:1])
    finally:
        server.stop()
        tmp.cleanup()


if __name__ == "__main__":
    sys.exit(main())
