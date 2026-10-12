"""localpasskey: list and delete the passkeys stored on this computer."""

from __future__ import annotations

import argparse
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


def _print_credentials(creds):
    rows = [
        (
            c["id"][:12],
            c["site"],
            _account(c),
            "passkey" if c["discoverable"] else "security key",
            _when(c["created"]),
            _when(c["last_used"]),
        )
        for c in sorted(creds, key=lambda c: (c["site"], c["user_name"], c["created"]))
    ]
    _print_table(("ID", "SITE", "ACCOUNT", "TYPE", "CREATED", "LAST USED"), rows)


def _with_user(payload, args):
    if args.user:
        payload["user"] = args.user
    return payload


def cmd_list(args):
    response = request(_with_user({"command": "list"}, args), args.socket)
    creds = response["credentials"]
    if args.json:
        print(json.dumps(creds, indent=2))
    elif not creds:
        print(f"No passkeys are stored for {response['user']}.")
    else:
        _print_credentials(creds)
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


def cmd_delete(args):
    if sum(bool(value) for value in (args.all, args.site, args.ids)) > 1:
        raise CliError("choose one selector: IDs, --site, or --all")
    if args.all:
        selector = {"all": True}
    elif args.site:
        selector = {"site": args.site}
    elif args.ids:
        selector = {"ids": args.ids}
    else:
        raise CliError("say which passkeys to delete: one or more IDs, --site SITE, or --all")
    selector = _with_user({"command": "delete", **selector}, args)

    doomed = request({**selector, "dry_run": True}, args.socket)["deleted"]
    selector = _with_user({"command": "delete", "ids": [cred["id"] for cred in doomed]}, args)
    _print_credentials(doomed)
    if not args.yes:
        answer = input(f"Delete {'this passkey' if len(doomed) == 1 else f'these {len(doomed)} passkeys'}? [y/N] ")
        if answer.strip().lower() not in ("y", "yes"):
            print("Nothing deleted.")
            return 1
    agent = _start_tty_agent()
    try:
        deleted = request(selector, args.socket)["deleted"]
    finally:
        if agent is not None:
            agent.terminate()
            agent.wait()
    print(f"Deleted {len(deleted)} passkey{'s' if len(deleted) != 1 else ''}.")
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

    sub = commands.add_parser("list", help="list your passkeys")
    sub.add_argument("--user", help="list another user's passkeys (root only)")
    sub.add_argument("--json", action="store_true", help="print the full details as JSON")
    sub.set_defaults(func=cmd_list)

    sub = commands.add_parser("delete", help="delete passkeys")
    sub.add_argument("ids", nargs="*", metavar="ID", help="passkey ID (or a unique prefix of it) from `list`")
    sub.add_argument("--site", help="delete every passkey for this site, e.g. github.com")
    sub.add_argument("--all", action="store_true", help="delete all of your passkeys")
    sub.add_argument("--user", help="act on another user's passkeys (root only)")
    sub.add_argument("-y", "--yes", action="store_true", help="do not ask for confirmation")
    sub.set_defaults(func=cmd_delete)

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
