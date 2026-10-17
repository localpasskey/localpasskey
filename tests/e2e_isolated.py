"""Isolated real-UHID e2e with explicit, process-local FAKE polkit approval.

Run from this checkout: sudo python3 -m tests.e2e_isolated --user <desktop-user>
Requires the normal daemon dependencies, /dev/uhid, a system bus, and desktop
udev access for that user. Uses temporary credentials and a separate device;
does not change polkit policies or open the installed authenticator.
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import pwd
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PRODUCT_ID = 0x4C52
SECRET = b"12345678901234567890123456789012"  # the SHA-256 seed of RFC 6238 Appendix B
SETUP_KEY = base64.b32encode(SECRET).decode().rstrip("=")
PASSPHRASE = "isolated e2e backup"


def rfc6238(at):
    """The code for SECRET at Unix time ``at`` as the test's link sets it up: SHA-256, 8 digits, 30 s."""
    digest = hmac.new(SECRET, struct.pack(">Q", int(at) // 30), hashlib.sha256).digest()
    offset = digest[-1] & 0x0F
    return "%08d" % ((struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 10**8)


def leaks(data):
    """Whether ``data`` holds SECRET in the clear: raw, as Base32 in any case, or base64url."""
    return (SECRET in data or SETUP_KEY.encode() in data.upper()
            or base64.urlsafe_b64encode(SECRET).rstrip(b"=") in data)


def snapshot(path):
    """What any write to ``path`` changes, even a write of the same bytes."""
    return path.read_bytes(), path.stat().st_mtime_ns


def daemon_main(root):
    from localpasskey import daemon, polkit
    from localpasskey.config import Config
    from localpasskey.ctap2 import Verdict

    expected_uid = (root / "client").stat().st_uid

    class FakeVerifier:
        def __init__(self, bus):
            pass

        def verify(self, requester, message, cancelled, timeout):
            assert requester.uid == expected_uid, "real requester resolver selected the wrong user"
            value = (root / "verdict").read_text()
            if value == "wait":
                return Verdict.CANCELLED if cancelled.wait(timeout) else Verdict.TIMED_OUT
            return Verdict(value)

        def check(self, subject, action_id, message, cancelled=None, timeout=120):
            return Verdict((root / "verdict").read_text())

    polkit.PolkitVerifier = FakeVerifier
    daemon._setup_logging("info")
    return daemon.run(
        Config(notifications=False, product_id=PRODUCT_ID, prompt_timeout=5),
        str(root / "state"), str(root / "control.sock"),
    )


def client_main(stage, root, device_path):
    from fido2.ctap import CtapError
    from fido2.ctap2 import Ctap2
    from fido2.hid import CtapHidDevice, linux
    from fido2.webauthn import AttestedCredentialData

    from .e2e_device import register, sign_in

    assert os.geteuid() != 0, "the HID client must run as the desktop user"

    def cli(*args, expected=0, stdin=""):
        result = subprocess.run(
            [sys.executable, str(REPO / "bin/localpasskey"), "--socket", str(root / "control.sock"), *args],
            input=stdin, capture_output=True, text=True, timeout=10,
            start_new_session=True,  # no controlling terminal: nothing may wait on the one this ran from
        )
        assert result.returncode == expected, result.stdout + result.stderr
        assert not leaks((result.stdout + result.stderr).encode()), "the CLI printed the setup key"
        return result.stdout if expected == 0 else result.stderr  # a failure is checked by its message

    def show(code_id):
        """Check the code the CLI prints against RFC 6238 at the daemon's time, on either side of a step."""
        before = time.time()
        shown = cli("totp", "code", code_id).strip()
        assert shown in (rfc6238(before), rfc6238(time.time())), "the code is not the RFC 6238 one"

    assert device_path in cli("status")
    if stage == "delete":
        assert "Moved 2 passkeys to the trash." in cli("delete", "--site", "example.com", "--yes")
        remaining = json.loads(cli("list", "--json"))
        assert [c["site"] for c in remaining] == ["other.example.org"]
        trashed = json.loads(cli("list", "--trash", "--json"))
        assert [c["site"] for c in trashed] == ["example.com", "example.com"]
        assert all(c["deleted"] for c in trashed)
        assert "Restored 2 passkeys." in cli("restore", "--site", "example.com", "--yes")
        assert len(json.loads(cli("list", "--json"))) == 3
        assert cli("list", "--trash").strip() == "The trash is empty."
        assert "Moved 3 passkeys to the trash." in cli("delete", "--all", "--yes")
        assert json.loads(cli("list", "--json")) == []
        assert "Restored 3 passkeys." in cli("restore", "--all", "--yes")
        assert len(json.loads(cli("list", "--json"))) == 3
        print("CLI status/list/delete/trash/restore: OK")
        return
    if stage == "totp":
        assert rfc6238(59) == "46119246", "the test's own RFC 6238 code is wrong"
        link = f"otpauth://totp/Example:alice@example.com?secret={SETUP_KEY}&issuer=Example&algorithm=SHA256&digits=8"
        # Pasted on stdin, which is no terminal here; never on the command line. With no
        # terminal to confirm on, the CLI wants -y and sends nothing without it.
        assert "add -y to save it without asking" in cli(
            "totp", "add", "--site", "example.com", stdin=f"{link}\n", expected=1)
        assert json.loads(cli("totp", "list", "--json")) == []
        assert "Saved the authenticator code for example.com." in cli(
            "totp", "add", "--site", "example.com", "-y", stdin=f"{link}\n")
        [code] = json.loads(cli("totp", "list", "--json"))
        assert {key: code[key] for key in ("site", "issuer", "account", "algorithm", "digits", "period", "deleted")} == {
            "site": "example.com", "issuer": "Example", "account": "alice@example.com",
            "algorithm": "SHA256", "digits": 8, "period": 30, "deleted": None}, code
        show(code["id"])
        assert "without asking" in cli("totp", "settings", "--require-password", "no")
        assert "without asking" in cli("totp", "settings")  # stays off: totp-denied turns it on
        assert "Moved 1 authenticator code to the trash." in cli("totp", "delete", code["id"], "--yes")
        assert json.loads(cli("totp", "list", "--json")) == []
        [trashed] = json.loads(cli("totp", "list", "--trash", "--json"))
        assert trashed["id"] == code["id"] and trashed["deleted"]
        assert "Restored 1 authenticator code." in cli("totp", "restore", code["id"], "--yes")
        assert json.loads(cli("totp", "list", "--json")) == [code]
        # Without a terminal, getpass reads the passphrases from stdin.
        backup = root / "client" / "codes.lpkbackup"
        assert f"Exported 3 passkeys and 1 authenticator code to {backup}." in cli(
            "export", str(backup), stdin=f"{PASSPHRASE}\n{PASSPHRASE}\n")
        assert not leaks(backup.read_bytes()), "the backup holds the setup key in the clear"
        cli("totp", "delete", code["id"], "--yes")
        assert "Permanently deleted the authenticator code for example.com." in cli(
            "totp", "purge", code["id"], stdin="example.com\n")
        assert json.loads(cli("totp", "list", "--json")) == json.loads(cli("totp", "list", "--trash", "--json")) == []
        assert "Imported 1 authenticator code." in cli("import", str(backup), stdin=f"{PASSPHRASE}\ny\n")
        assert json.loads(cli("totp", "list", "--json")) == [code]  # the same ID, labels and parameters
        show(code["id"])
        print("CLI authenticator codes add/list/code/settings/trash/restore/purge/export/import: OK")
        return
    if stage == "totp-denied":
        [code] = json.loads(cli("totp", "list", "--json"))
        show(code["id"])  # the password is off: no dialog to deny
        assert "password is needed" in cli("totp", "settings", "--require-password", "yes")  # never asks
        assert "not shown: authentication denied" in cli("totp", "code", code["id"], expected=1)
        assert "not changed: authentication denied" in cli(
            "totp", "settings", "--require-password", "no", expected=1)
        assert "password is needed" in cli("totp", "settings")
        print("totp-denied: a denied password shows no code and keeps it required: OK")
        return

    deadline = time.monotonic() + 5
    while True:
        try:
            descriptor = linux.get_descriptor(device_path)
            break
        except PermissionError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.1)  # udev may still be granting desktop access
    assert (descriptor.vid, descriptor.pid) == (0x1209, PRODUCT_ID)
    with CtapHidDevice(descriptor, linux.open_connection(descriptor)) as device:
        if stage in ("denied", "cancelled"):
            ctap = Ctap2(device)
            event = threading.Event()
            timer = threading.Timer(0.3, event.set) if stage == "cancelled" else None
            if timer:
                timer.start()
            try:
                ctap.make_credential(
                    os.urandom(32), {"id": "example.com"}, {"id": b"must-not-be-saved"},
                    [{"type": "public-key", "alg": -7}], options={"rk": True, "uv": True}, event=event,
                )
            except CtapError as error:
                expected = CtapError.ERR.KEEPALIVE_CANCEL if timer else CtapError.ERR.OPERATION_DENIED
                assert error.code == expected, error
            else:
                raise AssertionError(f"{stage} registration unexpectedly succeeded")
            finally:
                if timer:
                    timer.cancel()
                    timer.join()
            if stage == "denied":
                try:
                    ctap.get_assertion("example.com", os.urandom(32), options={"uv": True})
                except CtapError as error:
                    assert error.code == CtapError.ERR.OPERATION_DENIED, error
                else:
                    raise AssertionError("denied assertion unexpectedly succeeded")
                cli("delete", "--all", "--yes", expected=1)
            assert len(json.loads(cli("list", "--json"))) == 3
            print(f"{stage} requests preserve all three credentials: OK")
            return

        public_file = root / "client" / "public-credentials.json"
        if stage == "register":
            credentials = {
                "example.com": [register(device, "example.com", name.encode(), name) for name in ("alice", "bob")],
                "other.example.org": [register(device, "other.example.org", b"carol", "carol")],
            }
            public_file.write_text(json.dumps({rp: [bytes(c).hex() for c in creds] for rp, creds in credentials.items()}))
        else:
            credentials = {rp: [AttestedCredentialData(bytes.fromhex(c)) for c in creds]
                           for rp, creds in json.loads(public_file.read_text()).items()}
        assert sign_in(device, "example.com", credentials["example.com"]) == ["bob", "alice"]
        assert sign_in(device, "other.example.org", credentials["other.example.org"]) == ["carol"]
        for rp, creds in credentials.items():
            for cred in creds:
                challenge = os.urandom(32)
                assertion = Ctap2(device).get_assertion(
                    rp, challenge, [{"type": "public-key", "id": cred.credential_id}], options={"uv": True}
                )
                assert assertion.auth_data.is_user_present() and assertion.auth_data.is_user_verified()
                cred.public_key.verify(assertion.auth_data + challenge, assertion.signature)
        assert len(json.loads(cli("list", "--json"))) == 3
        print(f"{stage}: all three public keys verify UP+UV signatures: OK")


def stop(process):
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)


def ready(process, root):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("isolated daemon exited before becoming ready")
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(0.5)
                connection.connect(str(root / "control.sock"))
                connection.sendall(b'{"command":"status"}\n')
                with connection.makefile("rb") as stream:
                    reply = json.loads(stream.readline(4096))
            if reply.get("ok") and reply.get("device") and Path(reply["device"]).exists():
                return reply["device"]
        except (OSError, ValueError):
            pass
        time.sleep(0.05)
    raise TimeoutError("isolated daemon did not expose its HID device")


def run(user):
    if os.geteuid() != 0:
        raise SystemExit("Run with sudo; the test client will drop to --user.")
    account = pwd.getpwnam(user)
    if account.pw_uid == 0:
        raise SystemExit("--user must be a non-root desktop user")
    print("Real UHID + source daemon + desktop-user clients; FAKE polkit approval only in the test daemon.", flush=True)
    with tempfile.TemporaryDirectory(prefix="localpasskey-e2e-", dir="/tmp") as temporary:
        root = Path(temporary)
        root.chmod(0o711)
        (root / "client").mkdir(mode=0o700)
        os.chown(root / "client", account.pw_uid, account.pw_gid)
        (root / "verdict").write_text("approved")
        (root / "verdict").chmod(0o600)
        command = [sys.executable, "-m", "tests.e2e_isolated"]
        env = {key: value for key, value in os.environ.items() if key not in ("NOTIFY_SOCKET", "JOURNAL_STREAM")}
        # The client cannot read the daemon's state, so the code stages' files are checked here.
        credentials = root / "state" / "users" / str(account.pw_uid) / "credentials.json"
        codes = credentials.with_name("totp.json")
        try:
            for stages in (("register", "denied", "cancelled"), ("restart", "delete", "totp", "totp-denied")):
                with (root / "daemon.log").open("a") as log:
                    process = subprocess.Popen(
                        [*command, "--daemon", str(root)], cwd=REPO, env=env,
                        stdout=log, stderr=log, start_new_session=True,
                    )
                    try:
                        device = ready(process, root)
                        print(f"Isolated device: {device}", flush=True)
                        for stage in stages:
                            (root / "verdict").write_text(
                                {"denied": "denied", "totp-denied": "denied", "cancelled": "wait"}.get(stage, "approved"))
                            if stage == "totp":
                                passkeys = snapshot(credentials)
                            client = subprocess.Popen(
                                [*command, "--client", stage, "--root", str(root), "--device", device],
                                cwd=REPO, env=env, user=account.pw_uid, group=account.pw_gid,
                                extra_groups=os.getgrouplist(account.pw_name, account.pw_gid),
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, start_new_session=True,
                            )
                            try:
                                output, _ = client.communicate(timeout=40)
                                print(output, end="", flush=True)
                                assert client.returncode == 0, f"{stage} client exited {client.returncode}"
                            finally:
                                stop(client)
                            if stage.startswith("totp"):
                                assert snapshot(credentials) == passkeys, f"{stage} wrote credentials.json"
                                assert codes.stat().st_mode & 0o777 == 0o600
                                assert not leaks(codes.read_bytes()), "totp.json holds the setup key in the clear"
                                assert not leaks((root / "daemon.log").read_bytes()), "the daemon logged the setup key"
                    finally:
                        stop(process)
                    assert process.returncode == 0, f"daemon exited {process.returncode}"
                    assert not (root / "control.sock").exists(), "daemon left its control socket"
            assert (root / "state").stat().st_mode & 0o777 == 0o700
            assert (root / "state" / "master.key").stat().st_mode & 0o777 == 0o600
        except BaseException:
            if (root / "daemon.log").exists():
                print((root / "daemon.log").read_text(), file=sys.stderr)
            raise
    assert not root.exists(), "temporary credential state was not removed"
    print("OK: registration, signatures, denial, cancellation, restart persistence, CLI deletion, "
          "authenticator codes, and cleanup.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--user", help="desktop user for the unprivileged client")
    parser.add_argument("--daemon", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--client", choices=("register", "denied", "cancelled", "restart", "delete", "totp", "totp-denied"),
                        help=argparse.SUPPRESS)
    parser.add_argument("--root", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--device", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.daemon:
        return daemon_main(args.daemon)
    if args.client:
        return client_main(args.client, args.root, args.device)
    if not args.user:
        parser.error("--user is required")
    run(args.user)


if __name__ == "__main__":
    sys.exit(main())
