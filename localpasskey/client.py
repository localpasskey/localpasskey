"""Client side of localpasskeyd's control socket (CLI and window)."""

from __future__ import annotations

import json
import os
import socket
from typing import Optional

DEFAULT_SOCKET = "/run/localpasskey/control.sock"
MAX_REQUEST = 16 * 1024 * 1024  # control.MAX_REQUEST: the service drops a longer request unanswered


class ServiceError(Exception):
    """localpasskeyd refused the request."""


class ServiceUnavailable(ServiceError):
    """localpasskeyd is not running or cannot be reached."""


def socket_path() -> str:
    return os.environ.get("LOCALPASSKEY_SOCKET", DEFAULT_SOCKET)


def request(payload: dict, path: Optional[str] = None, timeout: float = 180) -> dict:
    path = path or socket_path()
    line = json.dumps(payload).encode() + b"\n"
    if len(line) > MAX_REQUEST:
        raise ServiceError(f"the request is too large for localpasskeyd (over {MAX_REQUEST // 2**20} MiB); "
                           "import a smaller backup, for example one website at a time")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC) as sock:
            sock.settimeout(timeout)  # 180 s by default: allow the management authentication dialog to finish.
            sock.connect(path)
            sock.sendall(line)
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
