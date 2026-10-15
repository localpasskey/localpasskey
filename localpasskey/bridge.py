"""Native messaging host org.localpasskey.bridge for Chrome and Chromium.

The LocalPasskey browser extension uses chrome.webAuthenticationProxy to take
over WebAuthn, so "create a passkey on this device" requests reach LocalPasskey
instead of failing on Linux. The browser starts one host process per request
and talks to it over stdin/stdout: a 4-byte native-endian length followed by
that many bytes of UTF-8 JSON. The host answers once and exits.

Requests are {"type": "status"}, answered with {"available": bool}, and
{"type": "create" | "get", "requestDetailsJson": "..."}, answered with
{"responseJson": "..."} or {"error": {"name": ..., "message": ...}}. The
ceremony runs on the LocalPasskey virtual key through python-fido2, which
builds clientDataJSON for the origin the browser verified and checks the rp ID
against it again. Closing stdin cancels a running ceremony.
"""

from __future__ import annotations

import json
import logging
import os
import struct
import sys
import threading
from urllib.parse import urlsplit

from fido2.hid import CtapHidDevice, list_descriptors, open_connection

from .config import load_config

log = logging.getLogger(__name__)

MAX_MESSAGE = 1024 * 1024
LOCAL_ORIGINS = ("localhost", "127.0.0.1")  # http allowed for testing, like browsers do

NOT_ALLOWED = ("NotAllowedError", "The operation either timed out or was not allowed.")


class ProtocolError(ValueError):
    """The browser sent something that is not a native message."""


class Refused(Exception):
    """The request is not handled; the page gets NotAllowedError."""


def read_message(stream):
    """Read one message, or return None at end of input."""
    header = stream.read(4)
    if not header:
        return None
    if len(header) != 4:
        raise ProtocolError("truncated length")
    (length,) = struct.unpack("=I", header)
    if length > MAX_MESSAGE:
        raise ProtocolError("message too large")
    data = stream.read(length)
    if len(data) != length:
        raise ProtocolError("truncated message")
    try:
        message = json.loads(data.decode("utf-8"))
    except (UnicodeError, ValueError):
        raise ProtocolError("message is not JSON") from None
    if not isinstance(message, dict):
        raise ProtocolError("message is not an object")
    return message


def write_message(stream, message):
    data = json.dumps(message).encode()
    stream.write(struct.pack("=I", len(data)) + data)
    stream.flush()


def find_device():
    """The HID descriptor of the LocalPasskey virtual key, or None. Other
    security keys are not used."""
    config = load_config()
    wanted = (config.vendor_id, config.product_id, config.device_name)
    for descriptor in list_descriptors():
        if (descriptor.vid, descriptor.pid, descriptor.product_name) == wanted:
            return descriptor
    return None


def open_device():
    descriptor = find_device()
    if descriptor is None:
        raise Refused("LocalPasskey device not found")
    return CtapHidDevice(descriptor, open_connection(descriptor))


def request_origin(details):
    """Take the origin Chromium checked against the rp ID out of the request."""
    extensions = details.get("extensions") or {}
    if not isinstance(extensions, dict):
        raise Refused("bad extensions")
    override = extensions.pop("remoteDesktopClientOverride", None)
    if not isinstance(override, dict) or not isinstance(override.get("origin"), str):
        raise Refused("no origin")
    if override.get("sameOriginWithAncestors") is not True:
        raise Refused("cross-origin iframe")
    origin = override["origin"]
    url = urlsplit(origin)
    if url.path or url.query or url.fragment or "@" in url.netloc or not url.hostname:
        raise Refused("not an origin")
    if url.scheme != "https" and not (url.scheme == "http" and url.hostname in LOCAL_ORIGINS):
        raise Refused("insecure origin")
    return origin


def ceremony(kind, details_json, cancel, open_device=open_device):
    details = json.loads(details_json)
    if not isinstance(details, dict):
        raise Refused("request is not an object")
    request_origin(details)
    open_device()
    raise Refused("not implemented yet")


def handle(message, cancel, open_device=open_device, find_device=find_device):
    """Answer one request. Failures never carry request data or tracebacks."""
    kind = message.get("type")
    try:
        if kind == "status":
            return {"available": find_device() is not None}
        if kind in ("create", "get"):
            response = ceremony(kind, message.get("requestDetailsJson"), cancel, open_device)
            return {"responseJson": json.dumps(response)}
        raise Refused("unknown request type")
    except Exception as e:
        log.debug("request failed: %s", type(e).__name__)  # no request data in logs
        if kind == "status":
            return {"available": False}
        return {"error": {"name": NOT_ALLOWED[0], "message": NOT_ALLOWED[1]}}


def _cancel_at_eof(stream, cancel):
    while stream.read(4096):
        pass  # one request per process: anything after it is ignored
    cancel.set()


def serve(stdin, stdout, open_device=open_device, find_device=find_device):
    try:
        message = read_message(stdin)
    except ProtocolError as e:
        log.debug("bad native message: %s", e)
        return 1
    if message is None:
        return 0
    cancel = threading.Event()
    threading.Thread(target=_cancel_at_eof, args=(stdin, cancel), daemon=True).start()
    reply = handle(message, cancel, open_device, find_device)
    try:
        write_message(stdout, reply)
    except OSError:
        return 1  # the browser went away
    return 0


def main():
    logging.basicConfig(format="localpasskey-bridge: %(message)s", level=logging.WARNING)
    if os.environ.get("LOCALPASSKEY_BRIDGE_DEBUG"):
        log.setLevel(logging.DEBUG)
    # Browser arguments (caller origin, --parent-window) are not needed.
    return serve(sys.stdin.buffer, sys.stdout.buffer)
