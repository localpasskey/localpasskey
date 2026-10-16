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
builds clientDataJSON for the origin the browser verified. The rp ID is not
checked again: Chromium already did, including Related Origin Requests
(/.well-known/webauthn), which python-fido2 cannot check. Closing stdin
cancels a running ceremony.
"""

from __future__ import annotations

import json
import logging
import os
import struct
import sys
import threading
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
import fido2.features
from fido2.client import ClientError, Fido2Client
from fido2.ctap import CtapError
from fido2.ctap2.extensions import CredPropsExtension, CredProtectExtension
from fido2.hid import CtapHidDevice, list_descriptors, open_connection
from fido2.utils import websafe_decode, websafe_encode
from fido2.webauthn import PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions

from . import cose
from .config import load_config

log = logging.getLogger(__name__)

MAX_MESSAGE = 1024 * 1024
# Chromium's JSON names; python-fido2 reads the same names for credProtect.
CREATE_EXTENSIONS = ("credProps", "credentialProtectionPolicy", "enforceCredentialProtectionPolicy")
LOCAL_ORIGINS = ("localhost",)  # http allowed for testing, like browsers do

NOT_ALLOWED = ("NotAllowedError", "The operation either timed out or was not allowed.")
ERRORS = {
    CtapError.ERR.CREDENTIAL_EXCLUDED: (
        "InvalidStateError",
        "The authenticator already contains one of the credentials registered with this site.",
    ),
    CtapError.ERR.UNSUPPORTED_ALGORITHM: (
        "NotSupportedError",
        "None of the requested algorithms are supported.",
    ),
}


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


def _bytes(value):
    if not isinstance(value, str):
        raise ValueError("expected base64url")
    return websafe_decode(value)


def _descriptors(values):
    # Transports are hints for the browser, not for the authenticator.
    return [{"type": value["type"], "id": _bytes(value["id"])} for value in values or []]


def creation_options(details):
    selection = dict(details.get("authenticatorSelection") or {})
    selection.pop("authenticatorAttachment", None)  # LocalPasskey is the platform authenticator here
    extensions = details.get("extensions") or {}
    return PublicKeyCredentialCreationOptions.from_dict({
        "rp": details["rp"],
        "user": {**details["user"], "id": _bytes(details["user"]["id"])},
        "challenge": _bytes(details["challenge"]),
        "pubKeyCredParams": details["pubKeyCredParams"],
        "timeout": details.get("timeout"),
        "excludeCredentials": _descriptors(details.get("excludeCredentials")),
        "authenticatorSelection": selection,
        "attestation": details.get("attestation"),
        "extensions": {k: v for k, v in extensions.items() if k in CREATE_EXTENSIONS},
    })


def request_options(details):
    # No getAssertion extensions are supported (appid, prf, largeBlob, ...).
    return PublicKeyCredentialRequestOptions.from_dict({
        "challenge": _bytes(details["challenge"]),
        "timeout": details.get("timeout"),
        "rpId": details.get("rpId"),
        "allowCredentials": _descriptors(details.get("allowCredentials")),
        "userVerification": details.get("userVerification"),
    })


def _spki(key):
    alg = key[3]
    if alg == cose.ES256:
        public = ec.EllipticCurvePublicNumbers(
            int.from_bytes(key[-2], "big"), int.from_bytes(key[-3], "big"), ec.SECP256R1()
        ).public_key()
    elif alg == cose.EDDSA:
        public = ed25519.Ed25519PublicKey.from_public_bytes(key[-2])
    elif alg == cose.RS256:
        public = rsa.RSAPublicNumbers(
            int.from_bytes(key[-2], "big"), int.from_bytes(key[-1], "big")
        ).public_key()
    else:
        raise ValueError(f"unsupported COSE algorithm {alg}")
    return public.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def creation_response(result):
    attestation = result.attestation_object
    credential = attestation.auth_data.credential_data
    credential_id = websafe_encode(credential.credential_id)
    extensions = dict(result.extension_results or {})
    return {
        "id": credential_id,
        "rawId": credential_id,
        "type": "public-key",
        "authenticatorAttachment": "platform",
        "response": {
            "clientDataJSON": websafe_encode(result.client_data),
            "attestationObject": websafe_encode(attestation),
            "authenticatorData": websafe_encode(attestation.auth_data),
            "publicKey": websafe_encode(_spki(credential.public_key)),
            "publicKeyAlgorithm": credential.public_key[3],
            # usb: the passkey still works through the USB route without the extension.
            "transports": ["internal", "usb"],
        },
        "clientExtensionResults": extensions,
    }


def assertion_response(selection):
    # shortcut: with several discoverable passkeys for the site the newest is
    # used (the confirmation dialog names none); add an account chooser if needed.
    result = selection.get_response(0)
    credential_id = websafe_encode(result.credential_id)
    response = {
        "clientDataJSON": websafe_encode(result.client_data),
        "authenticatorData": websafe_encode(result.authenticator_data),
        "signature": websafe_encode(result.signature),
    }
    if result.user_handle:
        response["userHandle"] = websafe_encode(result.user_handle)
    return {
        "id": credential_id,
        "rawId": credential_id,
        "type": "public-key",
        "authenticatorAttachment": "platform",
        "response": response,
        "clientExtensionResults": {},
    }


def _error(exc):
    cause = exc.cause if isinstance(exc, ClientError) else exc
    name, message = ERRORS.get(cause.code, NOT_ALLOWED) if isinstance(cause, CtapError) else NOT_ALLOWED
    return {"error": {"name": name, "message": message}}


def ceremony(kind, details_json, cancel, open_device=open_device):
    details = json.loads(details_json)
    if not isinstance(details, dict):
        raise Refused("request is not an object")
    origin = request_origin(details)
    options = creation_options(details) if kind == "create" else request_options(details)
    # Chromium checked the rp ID against the origin, related origins included.
    client = Fido2Client(
        open_device(), origin, verify=lambda rp_id, origin: True,
        extension_types=[CredPropsExtension, CredProtectExtension],
    )
    if kind == "create":
        return creation_response(client.make_credential(options, event=cancel))
    return assertion_response(client.get_assertion(options, event=cancel))


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
        return _error(e)


def _cancel_at_eof(stream, cancel):
    # Read below the buffer: a thread blocked holding the buffer's lock makes
    # interpreter shutdown abort ("could not acquire lock ... <stdin>").
    stream = getattr(stream, "raw", stream)
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
    fido2.features.webauthn_json_mapping.enabled = False  # bytes are passed as bytes
    if os.environ.get("LOCALPASSKEY_BRIDGE_DEBUG"):
        log.setLevel(logging.DEBUG)
    # Browser arguments (caller origin, --parent-window) are not needed.
    return serve(sys.stdin.buffer, sys.stdout.buffer)
