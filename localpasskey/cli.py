"""localpasskey: list, delete, restore, export and import the passkeys and
authenticator codes stored on this computer.

Deleting moves a passkey or code to the trash, where it can be restored; only
``purge`` deletes one for good. Export and import read and write files here, as
the user: the daemon only ever sees normalized records. A code's setup key is
read from the terminal or stdin, never from the command line, and never printed.
"""

from __future__ import annotations

import argparse
import contextlib
import getpass
import json
import math
import os
import shutil
import subprocess
import sys
import tempfile
import time

from . import totp, transfer
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


def _printable(text):
    """Anything a file, a website or the user typed: no terminal escapes."""
    return "".join(ch for ch in text if ch.isprintable())


def _code_type(code):
    kind = f"{code['digits']} digits · {code['period']} s"
    return kind if code["algorithm"] == "SHA1" else f"{kind} · {code['algorithm']}"


def _code_name(code):
    """What the CLI calls a code, like the daemon's dialogs: its site, else its issuer."""
    return _printable(code["site"] or code["issuer"]) or "an account"


def _print_codes(codes, deleted=False):
    last, heading = ("deleted", "DELETED") if deleted else ("created", "CREATED")
    rows = [
        (c["id"][:8], c["site"] or "-", c["issuer"] or "-", c["account"] or "-", _code_type(c), _when(c[last]))
        for c in sorted(codes, key=lambda c: (c["site"], c["issuer"], c["account"], c["created"]))
    ]
    _print_table(("ID", "SITE", "ISSUER", "ACCOUNT", "TYPE", heading), rows)


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


def _payload(args, command, codes=False):
    """A request for ``command``, which is an action of ``totp`` for codes."""
    return _with_user({"command": "totp", "action": command} if codes else {"command": command}, args)


def _selector(args, command, codes=False):
    if sum(bool(value) for value in (args.all, args.site, args.ids)) > 1:
        raise CliError("choose one selector: IDs, --site, or --all")
    if args.all:
        selector = {"all": True}
    elif args.site:
        selector = {"site": args.site}
    elif args.ids:
        selector = {"ids": args.ids}
    else:
        what = "authenticator codes" if codes else "passkeys"
        raise CliError(f"say which {what} to {command}: one or more IDs, --site SITE, or --all")
    return {**_payload(args, command, codes), **selector}


def _these(passkeys, codes):
    """ "this passkey", "these 3 authenticator codes", "1 passkey and 2 authenticator codes"."""
    if passkeys and codes:
        return join_counts(passkeys, codes)
    count, noun = (passkeys, "passkey") if passkeys else (codes, "authenticator code")
    return f"this {noun}" if count == 1 else f"these {count} {noun}s"


def _ask(payload, args):
    """Send one request that will make polkit ask for the password."""
    agent = _start_tty_agent()
    try:
        return request(payload, args.socket)
    finally:
        if agent is not None:
            agent.terminate()
            agent.wait()


def _apply(args, command, key, verb, prompt, done=None, codes=False):
    """delete/restore of passkeys or codes: preview what the selector matches,
    confirm, then send exactly the IDs the user approved."""
    selector = _selector(args, command, codes)
    doomed = request({**selector, "dry_run": True}, args.socket)["deleted"]
    # Send exactly the IDs the user saw approved.
    selector = {**_payload(args, command, codes), "ids": [cred["id"] for cred in doomed]}
    (_print_codes if codes else _print_credentials)(doomed, deleted=command == "restore")
    what = _these(0, len(doomed)) if codes else _these(len(doomed), 0)
    if not args.yes and input(prompt.format(what=what)).strip().lower() not in ("y", "yes"):
        print(f"Nothing {command}d.")
        return 1
    count = len(_ask(selector, args)[key])
    print(f"{verb} {plural_codes(count) if codes else plural(count)}{done or ''}.")
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
    site = _printable(doomed["site"])  # any website picked it: no terminal escapes
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


def unwritable(path):
    """Why ``path`` cannot be written, found before any password is asked for; or None."""
    if os.path.isdir(path):
        return "it is a directory"
    directory = os.path.dirname(os.path.abspath(path))
    if not os.access(directory, os.W_OK | os.X_OK):
        return f"{directory} does not exist or is not writable"
    return None


def plural(count):
    return f"{count} passkey{'s' if count != 1 else ''}"


def plural_codes(count):
    return f"{count} authenticator code{'s' if count != 1 else ''}"


def join_counts(passkeys, codes):
    """ "3 passkeys and 2 authenticator codes", omitting a part that is zero;
    "0 passkeys" when both are, as passkey-only messages always said."""
    parts = ([plural(passkeys)] if passkeys else []) + ([plural_codes(codes)] if codes else [])
    return " and ".join(parts) or plural(0)


@contextlib.contextmanager
def _suggest_no_codes(with_codes):
    """Only the codes can be left out; a damaged totp.json or seal should not block a passkey export."""
    try:
        yield
    except ServiceError as e:
        if with_codes and ("totp.json" in str(e) or "authenticator code" in str(e)):
            raise CliError(f"{e} (use --no-codes to export only passkeys)") from None
        raise


def cmd_export(args):
    if args.format == "cxf" and not args.unencrypted:
        raise CliError("CXF files are not encrypted: add --unencrypted if you really want one")
    if args.unencrypted and args.format != "cxf":
        raise CliError("only --format cxf writes an unencrypted file")
    if os.path.lexists(args.file) and not args.force:
        raise CliError(f"{args.file} already exists (use --force to replace it)")
    problem = unwritable(args.file)
    if problem:
        raise CliError(f"cannot write {args.file}: {problem}")
    if not (args.all or args.site or args.ids):
        args.all = True
    selector = _selector(args, "export")
    # Passkey IDs select no codes, so they never make the service read totp.json.
    with_codes = not args.no_codes and args.format != "cxf" and bool(args.all or args.site)
    with _suggest_no_codes(with_codes):
        plan = request({**selector, "dry_run": True, **({"codes": True} if with_codes else {})}, args.socket)
    chosen, chosen_codes = plan["exported"], plan.get("exported_codes", [])
    if chosen or not chosen_codes:
        _print_credentials(chosen)
    if chosen_codes:
        if chosen:
            print()
        _print_codes(chosen_codes)
    if args.format == "cxf" and not args.no_codes:
        with contextlib.suppress(ServiceError):  # only a note: counting the codes must not stop the export
            if request(_payload(args, "status", True), args.socket)["count"]:
                print("localpasskey: authenticator codes are not included in CXF files; use the default "
                      "format to back them up.", file=sys.stderr)
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
    if chosen_codes:
        selector["code_ids"] = [code["id"] for code in chosen_codes]
    with _suggest_no_codes(chosen_codes):
        exported = _ask(selector, args)
    records, codes = exported["credentials"], exported.get("codes", [])
    if args.unencrypted:
        data = transfer.export_cxf(records)
    else:
        data = transfer.export_backup(records, passphrase, codes)
    try:
        write_private_file(args.file, data, overwrite=args.force)
    except OSError as e:
        raise CliError(f"cannot write {args.file}: {e.strerror or e}") from None
    print(f"Exported {join_counts(len(records), len(codes))} to {args.file}.")
    return 0


def planned_records(records, planned, describe=transfer.describe):
    """The records the user saw in the import plan, once each: a duplicate in
    the file was already reported as skipped. Codes pass ``transfer.describe_code``."""
    wanted = {cred["id"] for cred in planned}
    chosen = []
    for record in records:
        cred_id = describe(record)["id"]
        if cred_id in wanted:
            wanted.discard(cred_id)
            chosen.append(record)
    return chosen


def _print_skipped(skipped):
    rows = [(s["credential"].get("id", "")[:12] or "-", s["credential"].get("site") or "-",
             _account(s["credential"]), s["reason"]) for s in skipped]
    _print_table(("ID", "SITE", "ACCOUNT", "SKIPPED BECAUSE"), rows)


def _print_skipped_codes(skipped):
    rows = [(s["code"].get("id", "")[:8] or "-", s["code"].get("site") or "-", s["code"].get("issuer") or "-",
             s["code"].get("account") or "-", s["reason"]) for s in skipped]
    _print_table(("ID", "SITE", "ISSUER", "ACCOUNT", "SKIPPED BECAUSE"), rows)


def _print_plan(imported, imported_codes, skipped, skipped_codes):
    """The import tables that have rows, one blank line apart."""
    tables = [(imported, _print_credentials), (imported_codes, _print_codes),
              (skipped, _print_skipped), (skipped_codes, _print_skipped_codes)]
    for i, (rows, show) in enumerate([table for table in tables if table[0]]):
        if i:
            print()
        show(rows)


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
    payload = _with_user({"command": "import", "credentials": records, "dry_run": True}, args)
    if records.codes:  # a file without codes sends the request a 0.3 daemon knows
        payload["codes"] = records.codes
    plan = request(payload, args.socket)
    imported, imported_codes = plan["imported"], plan.get("imported_codes", [])
    _print_plan(imported, imported_codes, records.skipped + plan["skipped"],
                records.skipped_codes + plan.get("skipped_codes", []))
    if not imported and not imported_codes:
        print("Nothing to import.")
        return 0
    what = _these(len(imported), len(imported_codes))
    if not args.yes and input(f"Import {what}? [y/N] ").strip().lower() not in ("y", "yes"):
        print("Nothing imported.")
        return 1
    payload = _with_user({"command": "import", "credentials": planned_records(records, imported)}, args)
    if imported_codes:
        payload["codes"] = planned_records(records.codes, imported_codes, transfer.describe_code)
    result = _ask(payload, args)
    done_codes, late_codes = result.get("imported_codes", []), result.get("skipped_codes", [])
    late = len(result["skipped"]) + len(late_codes)
    print(f"Imported {join_counts(len(result['imported']), len(done_codes))}"
          + (f"; {late} could no longer be imported:" if late else "."))
    _print_plan([], [], result["skipped"], late_codes)
    return 0


def cmd_status(args):
    status = request({"command": "status"}, args.socket)
    print(f"localpasskeyd {status['version']} is running.")
    print(f"Virtual security key: {status.get('device') or 'not available'}")
    creds = request({"command": "list"}, args.socket)["credentials"]
    print(f"Passkeys stored for you: {len(creds)}")
    try:
        codes = request({"command": "totp", "action": "status"}, args.socket)["count"]
    except ServiceError as e:  # a damaged totp.json, say: the lines above still stand
        print(f"Authenticator codes: {_printable(str(e))}", file=sys.stderr)
        return 1
    print(f"Authenticator codes stored for you: {codes}")
    return 0


def cmd_totp_list(args):
    payload = _payload(args, "list", codes=True)
    if args.trash:
        payload["trash"] = True
    response = request(payload, args.socket)
    codes = response["codes"]
    if args.json:
        print(json.dumps(codes, indent=2))
    elif not codes:
        print("The trash is empty." if args.trash else f"No authenticator codes are stored for {response['user']}.")
    else:
        _print_codes(codes, deleted=args.trash)
    return 0


def _read_setup_key():
    """The link or setup key, from the terminal without echo or as one line of stdin."""
    if sys.stdin.isatty():
        return getpass.getpass("otpauth:// link or setup key: ")
    return sys.stdin.readline()


def cmd_totp_add(args):
    try:
        parsed = totp.parse(_read_setup_key())
    except totp.OtpError as e:
        raise CliError(str(e)) from None
    issuer = parsed["issuer"] if args.issuer is None else args.issuer.strip()
    account = parsed["account"] if args.account is None else args.account.strip()
    site = args.site
    if site is None:
        site = totp.site_from_issuer(issuer)
        if sys.stdin.isatty():
            site = input(f"Website [{_printable(site)}]: " if site else "Website: ").strip() or site
    site = totp.normalize_site(site)  # "https://github.com/login" -> "github.com"
    entry = {"site": site, "issuer": issuer, "account": account, "algorithm": parsed["algorithm"],
             "digits": parsed["digits"], "period": parsed["period"]}
    _print_table(("WEBSITE", "ISSUER", "ACCOUNT", "TYPE"),
                 [(site or "-", issuer or "-", account or "-", _code_type(entry))])
    if not args.yes and input("Save this authenticator code? [y/N] ").strip().lower() not in ("y", "yes"):
        print("Nothing added.")
        return 1
    entry["secret"] = totp.encode_secret(parsed["secret"])
    added = _ask({**_payload(args, "add", codes=True), "entry": entry}, args)["added"]
    print(f"Saved the authenticator code for {_code_name(added)}.")
    return 0


def cmd_totp_code(args):
    codes = request(_payload(args, "list", codes=True), args.socket)["codes"]
    query = args.query.lower()
    # An ID prefix wins over text that happens to match it.
    matches = [c for c in codes if len(query) >= 4 and c["id"].startswith(query)]
    if not matches:
        query = args.query.casefold()
        matches = [c for c in codes if any(query in c[field].casefold() for field in ("site", "issuer", "account"))]
    if not matches:
        raise CliError(f"no authenticator code matches {args.query!r}")
    if len(matches) > 1:
        with contextlib.redirect_stdout(sys.stderr):  # stdout is for the code only
            _print_codes(matches)
        raise CliError(f"{len(matches)} authenticator codes match {args.query!r}: use more of the ID")
    reply = _ask({**_payload(args, "code", codes=True), "ids": [matches[0]["id"]], "ask": True}, args)
    if not reply["codes"]:
        raise CliError(f"no authenticator code with ID {matches[0]['id']}")  # deleted during the dialog
    [code] = reply["codes"]
    print(code["code"])
    print(f"valid for {math.ceil(code['remaining'])} more seconds", file=sys.stderr)  # an int or, from newer daemons, a float
    return 0


def cmd_totp_edit(args):
    site = None if args.site is None else totp.normalize_site(args.site)
    changes = {name: value.strip() for name, value in (("site", site), ("issuer", args.issuer),
                                                       ("account", args.account)) if value is not None}
    if not changes:
        raise CliError("say what to change: --site, --issuer or --account")
    updated = _ask({**_payload(args, "update", codes=True), "id": args.id, **changes}, args)["updated"]
    print(f"Changed the authenticator code for {_code_name(updated)}.")
    return 0


def cmd_totp_delete(args):
    return _apply(args, "delete", "deleted", "Moved", "Move {what} to the trash? [y/N] ",
                  " to the trash. Restore with `localpasskey totp restore`", codes=True)


def cmd_totp_restore(args):
    return _apply(args, "restore", "restored", "Restored", "Restore {what}? [y/N] ", codes=True)


def cmd_totp_purge(args):
    selector = {**_payload(args, "purge", codes=True), "ids": args.ids}
    [doomed] = request({**selector, "dry_run": True}, args.socket)["deleted"]
    _print_codes([doomed], deleted=True)
    # Like passkeys, the code is pinned by the ID above; the name is only a
    # check that the user means it, the same one the window asks for.
    name = _printable(doomed["site"]).strip() or _printable(doomed["issuer"]).strip() or "delete"
    typed = input(f'Type "{name}" to permanently delete this authenticator code. You may lose access to '
                  "that account. This cannot be undone.\n> ")
    if typed.strip().casefold() != name.casefold():
        print("Nothing deleted.")
        return 1
    _ask({**selector, "ids": [doomed["id"]]}, args)
    print(f"Permanently deleted the authenticator code for {_code_name(doomed)}.")
    return 0


def cmd_totp_settings(args):
    if args.require_password is None:
        require_auth = request(_payload(args, "status", codes=True), args.socket)["require_auth"]
    elif args.require_password == "yes":
        require_auth = request({**_payload(args, "settings", codes=True), "require_auth": True},
                               args.socket)["require_auth"]
    else:  # only turning the password off asks for it
        require_auth = _ask({**_payload(args, "settings", codes=True), "require_auth": False},
                            args)["require_auth"]
    if require_auth:
        print("Your password is needed to show authenticator codes.")
    else:
        print("Authenticator codes are shown without asking for your password.")
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

    sub = commands.add_parser("export", help="save passkeys and authenticator codes to an encrypted backup file")
    sub.add_argument("file", metavar="FILE", help="file to write, e.g. passkeys.lpkbackup")
    sub.add_argument("ids", nargs="*", metavar="ID", help="passkey ID (or a unique prefix of it) from `list`")
    sub.add_argument("--site", help="export every passkey for this site")
    sub.add_argument("--all", action="store_true", help="export all of your passkeys (the default)")
    sub.add_argument("--format", choices=("localpasskey", "cxf"), default="localpasskey",
                     help="localpasskey: encrypted backup (default); cxf: FIDO Credential Exchange Format")
    sub.add_argument("--unencrypted", action="store_true", help="required for --format cxf: write the keys in the clear")
    sub.add_argument("--force", action="store_true", help="replace FILE if it exists")
    sub.add_argument("--no-codes", action="store_true",
                     help="leave out your authenticator codes (included by default; CXF never has them)")
    sub.add_argument("--user", help="export another user's passkeys (root only)")
    sub.set_defaults(func=cmd_export)

    sub = commands.add_parser("import", help="add the passkeys from a backup, CXF or Bitwarden JSON file")
    sub.add_argument("file", metavar="FILE", help="LocalPasskey backup, CXF file or unencrypted Bitwarden JSON export")
    sub.add_argument("--user", help="import into another user's passkeys (root only)")
    sub.add_argument("-y", "--yes", action="store_true", help="do not ask for confirmation")
    sub.set_defaults(func=cmd_import)

    sub = commands.add_parser("totp", help="manage the authenticator codes (TOTP) stored on this computer")
    actions = sub.add_subparsers(dest="action", metavar="ACTION")
    actions.required = True

    sub = actions.add_parser("list", help="list your authenticator codes, or the trash with --trash")
    sub.add_argument("--trash", action="store_true", help="list the authenticator codes you deleted")
    sub.add_argument("--json", action="store_true", help="print the full details as JSON")
    sub.add_argument("--user", help="list another user's authenticator codes (root only)")
    sub.set_defaults(func=cmd_totp_list)

    sub = actions.add_parser("add", help="save an authenticator code from an otpauth:// link or setup key, "
                             "read from the terminal or stdin")
    sub.add_argument("--site", help="the website the code signs in to, e.g. github.com")
    sub.add_argument("--issuer", metavar="TEXT", help="replace the issuer the link names")
    sub.add_argument("--account", metavar="TEXT", help="replace the account name the link names")
    sub.add_argument("-y", "--yes", action="store_true", help="do not ask for confirmation")
    sub.add_argument("--user", help="add to another user's authenticator codes (root only)")
    sub.set_defaults(func=cmd_totp_add)

    sub = actions.add_parser("code", help="print the current authenticator code for one account")
    sub.add_argument("query", metavar="QUERY", help="an ID prefix from `totp list`, or part of the site, "
                     "issuer or account")
    sub.add_argument("--user", help="show another user's authenticator code (root only)")
    sub.set_defaults(func=cmd_totp_code)

    sub = actions.add_parser("edit", help="change the website, issuer or account of an authenticator code")
    sub.add_argument("id", metavar="ID", help="authenticator code ID (or a unique prefix of it) from `totp list`")
    sub.add_argument("--site", help="the new website, or \"\" for none")
    sub.add_argument("--issuer", metavar="TEXT", help="the new issuer")
    sub.add_argument("--account", metavar="TEXT", help="the new account name")
    sub.add_argument("--user", help="act on another user's authenticator codes (root only)")
    sub.set_defaults(func=cmd_totp_edit)

    sub = actions.add_parser("delete", help="move authenticator codes to the trash")
    sub.add_argument("ids", nargs="*", metavar="ID",
                     help="authenticator code ID (or a unique prefix of it) from `totp list`")
    sub.add_argument("--site", help="delete every authenticator code for this site")
    sub.add_argument("--all", action="store_true", help="delete all of your authenticator codes")
    sub.add_argument("--user", help="act on another user's authenticator codes (root only)")
    sub.add_argument("-y", "--yes", action="store_true", help="do not ask for confirmation")
    sub.set_defaults(func=cmd_totp_delete)

    sub = actions.add_parser("restore", help="restore authenticator codes from the trash")
    sub.add_argument("ids", nargs="*", metavar="ID",
                     help="authenticator code ID (or a unique prefix of it) from `totp list --trash`")
    sub.add_argument("--site", help="restore every authenticator code for this site")
    sub.add_argument("--all", action="store_true", help="restore all of your trashed authenticator codes")
    sub.add_argument("--user", help="act on another user's authenticator codes (root only)")
    sub.add_argument("-y", "--yes", action="store_true", help="do not ask for confirmation")
    sub.set_defaults(func=cmd_totp_restore)

    sub = actions.add_parser("purge", help="permanently delete one authenticator code from the trash")
    sub.add_argument("ids", nargs=1, metavar="ID",
                     help="authenticator code ID (or a unique prefix of it) from `totp list --trash`")
    sub.add_argument("--user", help="act on another user's authenticator codes (root only)")
    sub.set_defaults(func=cmd_totp_purge)

    sub = actions.add_parser("settings", help="show or change whether showing a code asks for your password")
    sub.add_argument("--require-password", choices=("yes", "no"),
                     help="ask for your password before showing authenticator codes (the default), or not")
    sub.add_argument("--user", help="act on another user's setting (root only)")
    sub.set_defaults(func=cmd_totp_settings)

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
