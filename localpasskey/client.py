"""Client side of localpasskeyd's control socket (CLI and window)."""

from __future__ import annotations

import json
import os
import socket
from typing import Optional

DEFAULT_SOCKET = "/run/localpasskey/control.sock"


class ServiceError(Exception):
    """localpasskeyd refused the request."""


class ServiceUnavailable(ServiceError):
    """localpasskeyd is not running or cannot be reached."""


def socket_path() -> str:
    return os.environ.get("LOCALPASSKEY_SOCKET", DEFAULT_SOCKET)


def request(payload: dict, path: Optional[str] = None) -> dict:
    path = path or socket_path()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC) as sock:
            sock.settimeout(180)  # Allow the management authentication dialog to finish.
            sock.connect(path)
            sock.sendall(json.dumps(payload).encode() + b"\n")
            with sock.makefile("rb") as stream:
                data = stream.readline()
    except (FileNotFoundError, ConnectionRefusedError):
        raise ServiceUnavailable(
            "localpasskeyd is not running (start it with: sudo systemctl start localpasskey)"
        ) from None
    except PermissionError:
        raise ServiceUnavailable(f"permission denied while connecting to {path}") from None
    except OSError as e:
        raise ServiceUnavailable(f"could not communicate with localpasskeyd: {e}") from None
    if not data:
        raise ServiceUnavailable("no reply from localpasskeyd")
    if not data.endswith(b"\n"):
        raise ServiceUnavailable("incomplete reply from localpasskeyd")
    try:
        response = json.loads(data)
    except (ValueError, UnicodeError):
        raise ServiceError("invalid reply from localpasskeyd") from None
    if not isinstance(response, dict) or not isinstance(response.get("ok"), bool):
        raise ServiceError("invalid reply from localpasskeyd")
    if not response.get("ok"):
        raise ServiceError(response.get("error", "request failed"))
    return response
