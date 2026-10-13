"""localpasskey: list, delete and restore the passkeys stored on this computer.

Deleting moves a passkey to the trash, where it can be restored; only ``purge``
deletes one for good.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import shutil
import subprocess
import sys
import time

from .client import ServiceError, request, socket_path


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
    if args.user:
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
    print(f"{verb} {count} passkey{'s' if count != 1 else ''}{done or ''}.")
    return 0


def cmd_delete(args):
    return _apply(args, "delete", "deleted", "Moved", "Move {what} to the trash? [y/N] ",
                  " to the trash. Restore with `localpasskey restore`")


def cmd_restore(args):
    return _apply(args, "restore", "restored", "Restored", "Restore {what}? [y/N] ")


def cmd_purge(args):
    if len(args.ids) != 1:
        raise CliError("purge permanently deletes one passkey at a time")
    selector = _with_user({"command": "purge", "ids": args.ids}, args)
    [doomed] = request({**selector, "dry_run": True}, args.socket)["deleted"]
    _print_credentials([doomed], deleted=True)
    # The site is the one identifier every passkey has: the account name is
    # optional in CTAP and often empty. Uniqueness is not needed because the
    # passkey is already pinned by the ID in the table above.
    site = doomed["site"]
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
            print(f"A PIN is set ({status['retries']} attempts left).")
        else:
            print("No PIN is set.")
        return 0
    if args.action == "set":
        pin = getpass.getpass("New PIN: ")
        if pin != getpass.getpass("Repeat the new PIN: "):
            raise CliError("the PINs do not match")
        payload["pin"] = pin
    _ask(payload, args)
    print("PIN set." if args.action == "set" else "PIN removed.")
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
        help="manage the PIN browsers ask for in their security-key settings to list or delete passkeys",
    )
    sub.add_argument("action", choices=("status", "set", "remove"), help="show, set or remove the PIN")
    sub.add_argument("--user", help="act on another user's PIN (root only)")
    sub.set_defaults(func=cmd_pin)

    sub = commands.add_parser("status", help="check that the service is running")
    sub.set_defaults(func=cmd_status)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (CliError, ServiceError) as e:
        print(f"localpasskey: {e}", file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print()
        return 130
