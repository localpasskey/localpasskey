"""localpasskey: list, delete, restore, export and import the passkeys stored
on this computer.

Deleting moves a passkey to the trash, where it can be restored; only ``purge``
deletes one for good. Export and import read and write files here, as the
user: the daemon only ever sees normalized records.
"""

from __future__ import annotations

import argparse
import contextlib
import getpass
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

from . import transfer
from .client import ServiceError, request, socket_path
from .store import _fsync_dir


class CliError(Exception):
    pass


def _when(timestamp):
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(timestamp)) if timestamp else "never"


def _account(cred):
    name, display = cred["user_name"], cred["display_name"]
    if name and display and name != display:
        return f"{display} <{name}>"
    return name or display or "-"


def _print_table(headers, rows):
    rows = [["".join(ch if ch.isprintable() else " " for ch in str(cell)) for cell in row]
            for row in [headers, *rows]]
    widths = [max(len(row[i]) for row in rows) for i in range(len(headers))]
    for row in rows:
        print("  ".join(cell.ljust(width) for cell, width in zip(row, widths)).rstrip())


def _print_credentials(creds, deleted=False):
    """One table either way; the last column is what happened to the passkey."""
    last, heading = ("deleted", "DELETED") if deleted else ("last_used", "LAST USED")
    rows = [
        (
            c["id"][:12],
            c["site"],
            _account(c),
            "passkey" if c["discoverable"] else "security key",
            _when(c["created"]),
            _when(c[last]),
        )
        for c in sorted(creds, key=lambda c: (c["site"], c["user_name"], c["created"]))
    ]
    _print_table(("ID", "SITE", "ACCOUNT", "TYPE", "CREATED", heading), rows)


def _with_user(payload, args):
    if args.user is not None:  # an empty --user must fail, not fall back to the caller
        payload["user"] = args.user
    return payload


def cmd_list(args):
    payload = _with_user({"command": "list"}, args)
    if args.trash:
        payload["trash"] = True
    response = request(payload, args.socket)
    creds = response["credentials"]
    what = "trashed passkeys" if args.trash else "passkeys"
    if args.json:
        print(json.dumps(creds, indent=2))
    elif not creds:
        print("The trash is empty." if args.trash else f"No {what} are stored for {response['user']}.")
    else:
        _print_credentials(creds, deleted=args.trash)
    return 0


def _start_tty_agent():
    """Let polkit ask for the password in this terminal when no graphical
    authentication agent is available (over SSH, for example)."""
    if os.geteuid() == 0 or not sys.stdin.isatty() or not shutil.which("pkttyagent"):
        return None
    notify_read, notify_write = os.pipe()
    agent = subprocess.Popen(
        ["pkttyagent", "--notify-fd", str(notify_write), "--fallback"], pass_fds=(notify_write,)
    )
    os.close(notify_write)
    os.read(notify_read, 1)  # returns once the agent is registered
    os.close(notify_read)
    return agent


def _selector(args, command):
    if sum(bool(value) for value in (args.all, args.site, args.ids)) > 1:
        raise CliError("choose one selector: IDs, --site, or --all")
    if args.all:
        selector = {"all": True}
    elif args.site:
        selector = {"site": args.site}
    elif args.ids:
        selector = {"ids": args.ids}
    else:
        raise CliError(f"say which passkeys to {command}: one or more IDs, --site SITE, or --all")
    return _with_user({"command": command, **selector}, args)


def _ask(payload, args):
    """Send one request that will make polkit ask for the password."""
    agent = _start_tty_agent()
    try:
        return request(payload, args.socket)
    finally:
        if agent is not None:
            agent.terminate()
            agent.wait()


def _apply(args, command, key, verb, prompt, done=None):
    """delete/restore: preview what the selector matches, confirm, then send
    exactly the IDs the user approved."""
    selector = _selector(args, command)
    doomed = request({**selector, "dry_run": True}, args.socket)["deleted"]
    # Send exactly the IDs the user saw approved.
    selector = _with_user({"command": command, "ids": [cred["id"] for cred in doomed]}, args)
    _print_credentials(doomed, deleted=command == "restore")
    what = "this passkey" if len(doomed) == 1 else f"these {len(doomed)} passkeys"
    if not args.yes and input(prompt.format(what=what)).strip().lower() not in ("y", "yes"):
        print(f"Nothing {command}d.")
        return 1
    count = len(_ask(selector, args)[key])
    print(f"{verb} {_plural(count)}{done or ''}.")
    return 0


def cmd_delete(args):
    return _apply(args, "delete", "deleted", "Moved", "Move {what} to the trash? [y/N] ",
                  " to the trash. Restore with `localpasskey restore`")


def cmd_restore(args):
    return _apply(args, "restore", "restored", "Restored", "Restore {what}? [y/N] ")


def cmd_purge(args):
    selector = _with_user({"command": "purge", "ids": args.ids}, args)
    [doomed] = request({**selector, "dry_run": True}, args.socket)["deleted"]
    _print_credentials([doomed], deleted=True)
    # The site is the one identifier every passkey has: the account name is
    # optional in CTAP and often empty. Uniqueness is not needed because the
    # passkey is already pinned by the ID in the table above.
    site = "".join(ch for ch in doomed["site"] if ch.isprintable())  # any website picked it: no terminal escapes
    typed = input(f'Type "{site}" to permanently delete this passkey. This cannot be undone.\n> ')
    if typed.strip().casefold() != site.casefold():
        print("Nothing deleted.")
        return 1
    _ask({**selector, "ids": [doomed["id"]]}, args)
    print(f"Permanently deleted the passkey for {site}.")
    return 0


def cmd_pin(args):
    payload = _with_user({"command": "pin", "action": args.action}, args)
    if args.action == "status":
        status = request(payload, args.socket)
        if status["set"]:
            print(f"A security key PIN is set ({status['retries']} attempts left).")
        else:
            print("No security key PIN is set. Browsers need one to list or delete passkeys.")
        return 0
    if args.action == "set":
        pin = getpass.getpass("New PIN: ")
        if pin != getpass.getpass("Repeat the new PIN: "):
            raise CliError("the PINs do not match")
        payload["pin"] = pin
    _ask(payload, args)
    print("Security key PIN set." if args.action == "set" else "Security key PIN removed.")
    return 0


def write_private_file(path, data, overwrite=False):
    """Write ``data`` readable by the owner only, and on disk before this
    returns. Without ``overwrite`` an existing file is an error; with it, the
    old file is replaced atomically."""
    if overwrite:
        fd, temporary = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(path)),
                                         prefix=f".{os.path.basename(path)}.", suffix=".tmp")
        _fill(fd, temporary, data)
        try:
            os.replace(temporary, path)
        except BaseException:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(temporary)  # gone already if the rename finished before the interrupt
            raise
    else:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        _fill(fd, path, data)
    with contextlib.suppress(OSError):  # the file itself is synced; some directories refuse fsync
        _fsync_dir(os.path.dirname(os.path.abspath(path)))


def _fill(fd, path, data):
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        os.unlink(path)  # never leave half a backup behind
        raise


def _plural(count):
    return f"{count} passkey{'s' if count != 1 else ''}"


def cmd_export(args):
    if args.format == "cxf" and not args.unencrypted:
        raise CliError("CXF files are not encrypted: add --unencrypted if you really want one")
    if args.unencrypted and args.format != "cxf":
        raise CliError("only --format cxf writes an unencrypted file")
    if os.path.lexists(args.file) and not args.force:
        raise CliError(f"{args.file} already exists (use --force to replace it)")
    directory = os.path.dirname(os.path.abspath(args.file))
    if os.path.isdir(args.file):
        raise CliError(f"cannot write {args.file}: it is a directory")
    if not os.access(directory, os.W_OK | os.X_OK):  # find out before the password is asked for
        raise CliError(f"cannot write {args.file}: {directory} does not exist or is not writable")
    if not (args.all or args.site or args.ids):
        args.all = True
    selector = _selector(args, "export")
    chosen = request({**selector, "dry_run": True}, args.socket)["exported"]
    _print_credentials(chosen)
    if args.unencrypted:
        print("localpasskey: warning: the file will NOT be encrypted. Anyone who can read it can sign "
              "in as you on these sites.", file=sys.stderr)
    else:
        passphrase = getpass.getpass("New passphrase to encrypt the export (not your login password): ")
        problem = transfer.passphrase_problem(passphrase)
        if problem is None and passphrase != getpass.getpass("Confirm the passphrase: "):
            problem = "The passphrases do not match"
        if problem:
            raise CliError(problem[:1].lower() + problem[1:])
    # Send exactly the IDs shown above.
    selector = _with_user({"command": "export", "ids": [cred["id"] for cred in chosen]}, args)
    records = _ask(selector, args)["credentials"]
    data = transfer.export_cxf(records) if args.unencrypted else transfer.export_backup(records, passphrase)
    try:
        write_private_file(args.file, data, overwrite=args.force)
    except OSError as e:
        raise CliError(f"cannot write {args.file}: {e.strerror or e}") from None
    print(f"Exported {_plural(len(records))} to {args.file}.")
    return 0


def planned_records(records, planned):
    """The records the user saw in the import plan, once each: a duplicate in
    the file was already reported as skipped."""
    wanted = {cred["id"] for cred in planned}
    chosen = []
    for record in records:
        cred_id = transfer.describe(record)["id"]
        if cred_id in wanted:
            wanted.discard(cred_id)
            chosen.append(record)
    return chosen


def _print_skipped(skipped):
    rows = [(s["credential"].get("id", "")[:12] or "-", s["credential"].get("site") or "-",
             _account(s["credential"]), s["reason"]) for s in skipped]
    _print_table(("ID", "SITE", "ACCOUNT", "SKIPPED BECAUSE"), rows)


def cmd_import(args):
    try:
        with open(args.file, "rb") as stream:
            data = stream.read()
    except OSError as e:
        raise CliError(f"cannot read {args.file}: {e.strerror or e}") from None
    for attempt in range(3):
        try:
            records = transfer.load(data, lambda: getpass.getpass("Passphrase this file was exported with: "))
            break
        except transfer.WrongPassphrase as e:
            if attempt == 2:
                raise
            print(f"localpasskey: {e}", file=sys.stderr)
    plan = request(_with_user({"command": "import", "credentials": records, "dry_run": True}, args), args.socket)
    skipped = records.skipped + plan["skipped"]
    if plan["imported"]:
        _print_credentials(plan["imported"])
    if skipped:
        if plan["imported"]:
            print()
        _print_skipped(skipped)
    if not plan["imported"]:
        print("Nothing to import.")
        return 0
    what = "this passkey" if len(plan["imported"]) == 1 else f"these {len(plan['imported'])} passkeys"
    if not args.yes and input(f"Import {what}? [y/N] ").strip().lower() not in ("y", "yes"):
        print("Nothing imported.")
        return 1
    chosen = planned_records(records, plan["imported"])
    result = _ask(_with_user({"command": "import", "credentials": chosen}, args), args)
    late = len(result["skipped"])
    print(f"Imported {_plural(len(result['imported']))}"
          + (f"; {late} could no longer be imported:" if late else "."))
    if late:
        _print_skipped(result["skipped"])
    return 0


def cmd_status(args):
    status = request({"command": "status"}, args.socket)
    print(f"localpasskeyd {status['version']} is running.")
    print(f"Virtual security key: {status.get('device') or 'not available'}")
    creds = request({"command": "list"}, args.socket)["credentials"]
    print(f"Passkeys stored for you: {len(creds)}")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="localpasskey", description="Manage the passkeys that localpasskeyd stores on this computer."
    )
    parser.add_argument("--socket", default=socket_path(), help=argparse.SUPPRESS)
    commands = parser.add_subparsers(dest="command", metavar="COMMAND")
    commands.required = True

    sub = commands.add_parser("list", help="list your passkeys, or the trash with --trash")
    sub.add_argument("--trash", action="store_true", help="list the passkeys you deleted")
    sub.add_argument("--user", help="list another user's passkeys (root only)")
    sub.add_argument("--json", action="store_true", help="print the full details as JSON")
    sub.set_defaults(func=cmd_list)

    sub = commands.add_parser("delete", help="move passkeys to the trash")
    sub.add_argument("ids", nargs="*", metavar="ID", help="passkey ID (or a unique prefix of it) from `list`")
    sub.add_argument("--site", help="delete every passkey for this site, e.g. github.com")
    sub.add_argument("--all", action="store_true", help="delete all of your passkeys")
    sub.add_argument("--user", help="act on another user's passkeys (root only)")
    sub.add_argument("-y", "--yes", action="store_true", help="do not ask for confirmation")
    sub.set_defaults(func=cmd_delete)

    sub = commands.add_parser("restore", help="restore passkeys from the trash")
    sub.add_argument("ids", nargs="*", metavar="ID", help="passkey ID (or a unique prefix of it) from `list --trash`")
    sub.add_argument("--site", help="restore every passkey for this site, e.g. github.com")
    sub.add_argument("--all", action="store_true", help="restore all of your trashed passkeys")
    sub.add_argument("--user", help="act on another user's passkeys (root only)")
    sub.add_argument("-y", "--yes", action="store_true", help="do not ask for confirmation")
    sub.set_defaults(func=cmd_restore)

    sub = commands.add_parser("purge", help="permanently delete one passkey from the trash")
    sub.add_argument("ids", nargs=1, metavar="ID", help="passkey ID (or a unique prefix of it) from `list --trash`")
    sub.add_argument("--user", help="act on another user's passkeys (root only)")
    sub.set_defaults(func=cmd_purge)

    sub = commands.add_parser(
        "pin",
        help="manage the security key PIN browsers ask for in their security-key settings to list or "
        "delete passkeys (not your login password)",
    )
    sub.add_argument("action", choices=("status", "set", "remove"), help="show, set or remove the PIN")
    sub.add_argument("--user", help="act on another user's PIN (root only)")
    sub.set_defaults(func=cmd_pin)

    sub = commands.add_parser("export", help="save passkeys to an encrypted backup file")
    sub.add_argument("file", metavar="FILE", help="file to write, e.g. passkeys.lpkbackup")
    sub.add_argument("ids", nargs="*", metavar="ID", help="passkey ID (or a unique prefix of it) from `list`")
    sub.add_argument("--site", help="export every passkey for this site")
    sub.add_argument("--all", action="store_true", help="export all of your passkeys (the default)")
    sub.add_argument("--format", choices=("localpasskey", "cxf"), default="localpasskey",
                     help="localpasskey: encrypted backup (default); cxf: FIDO Credential Exchange Format")
    sub.add_argument("--unencrypted", action="store_true", help="required for --format cxf: write the keys in the clear")
    sub.add_argument("--force", action="store_true", help="replace FILE if it exists")
    sub.add_argument("--user", help="export another user's passkeys (root only)")
    sub.set_defaults(func=cmd_export)

    sub = commands.add_parser("import", help="add the passkeys from a backup, CXF or Bitwarden JSON file")
    sub.add_argument("file", metavar="FILE", help="LocalPasskey backup, CXF file or unencrypted Bitwarden JSON export")
    sub.add_argument("--user", help="import into another user's passkeys (root only)")
    sub.add_argument("-y", "--yes", action="store_true", help="do not ask for confirmation")
    sub.set_defaults(func=cmd_import)

    sub = commands.add_parser("status", help="check that the service is running")
    sub.set_defaults(func=cmd_status)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (CliError, ServiceError, transfer.TransferError) as e:
        print("localpasskey:", "".join(ch if ch.isprintable() else " " for ch in str(e)), file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print()
        return 130
