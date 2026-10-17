"""Authenticator codes: time-based one-time passwords (RFC 6238 TOTP).

Sites show a setup key, usually as a QR code whose text is an
``otpauth://totp/...`` link. Users paste that link, or the bare Base32 key, and
this module turns it into a secret plus the parameters needed to compute the
current code. Everything that comes out of a link is untrusted text.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
import struct
import time
from typing import Optional, Tuple
from urllib.parse import parse_qsl, unquote, urlsplit

from .ctap2 import MAX_LABEL_LENGTH, valid_rp_id

ALGORITHMS = ("SHA1", "SHA256", "SHA512")
DIGITS = (6, 8)
MIN_PERIOD, MAX_PERIOD = 1, 300
DEFAULT_ALGORITHM, DEFAULT_DIGITS, DEFAULT_PERIOD = "SHA1", 6, 30
MIN_SECRET_BYTES, MAX_SECRET_BYTES = 10, 128  # 80 bits: below RFC 4226's 128, but common in the wild
MAX_INPUT = 2048  # characters of pasted text
MAX_LABEL = MAX_LABEL_LENGTH  # site, issuer and account

_HASHES = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}
_BASE32 = re.compile(r"[A-Z2-7]*")
_NUMBER = re.compile(r"[0-9]{1,4}")
# A dotted host name of ASCII letters, digits and hyphens: what "Open Website" can open.
_HOST = re.compile(r"(?=.{1,253}\Z)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?",
                   re.ASCII)


class OtpError(ValueError):
    """Text that is not a usable setup key or link; the message is for the user."""


def decode_secret(text: str) -> bytes:
    """A Base32 setup key as users paste it: any case, spaces, dashes, padding."""
    key = re.sub(r"[\s-]", "", text)
    # Before upper(): "ſ", "ı", "ß" and "ﬀ" upper-case to ASCII letters.
    if not key.isascii():
        raise OtpError("this is not a valid setup key")
    key = key.upper().rstrip("=")
    # 0, 1 and 8 are not remapped: guessing O, I or B could save a wrong key.
    if not _BASE32.fullmatch(key) or len(key) % 8 in (1, 3, 6):
        raise OtpError("this is not a valid setup key")
    try:
        secret = base64.b32decode(key + "=" * (-len(key) % 8))
    except (binascii.Error, ValueError):
        raise OtpError("this is not a valid setup key") from None
    if len(secret) < MIN_SECRET_BYTES:
        raise OtpError("the setup key is too short")
    if len(secret) > MAX_SECRET_BYTES:
        raise OtpError("the setup key is too long")
    return secret


def encode_secret(secret: bytes) -> str:
    """RFC 4648 Base32, upper case, without padding."""
    return base64.b32encode(secret).decode("ascii").rstrip("=")


def _clean_label(text: str) -> str:
    text = "".join(ch if ch.isprintable() else " " for ch in text).strip()
    return text[:MAX_LABEL]


def _number(value: str, name: str) -> int:
    if not _NUMBER.fullmatch(value):
        raise OtpError(f"the {name} parameter is not a number")
    return int(value)


def parse(text: str) -> dict:
    """Parse a pasted ``otpauth://totp/`` link or bare setup key.

    Returns a dict with the keys secret (bytes), issuer, account, algorithm,
    digits and period. Raises OtpError with a message for the user."""
    if len(text) > MAX_INPUT:
        raise OtpError("the text is too long for a setup key or link")
    text = text.strip()
    result = {
        "secret": b"",
        "issuer": "",
        "account": "",
        "algorithm": DEFAULT_ALGORITHM,
        "digits": DEFAULT_DIGITS,
        "period": DEFAULT_PERIOD,
    }
    if "://" not in text and not text.lower().startswith("otpauth:"):
        result["secret"] = decode_secret(text)
        return result
    try:
        url = urlsplit(text)
    except ValueError:
        raise OtpError("not an otpauth://totp/ link or a setup key") from None
    kind = url.netloc.lower()
    if url.scheme.lower() == "otpauth" and kind == "hotp":
        raise OtpError("counter-based (HOTP) codes are not supported")
    if url.scheme.lower() != "otpauth" or kind != "totp":
        raise OtpError("not an otpauth://totp/ link or a setup key")

    label = unquote(url.path[1:])
    issuer, account = label.split(":", 1) if ":" in label else ("", label)
    params = {}
    for key, value in parse_qsl(url.query, keep_blank_values=True):
        params.setdefault(key.lower(), value)

    encoder = params.get("encoder", "").strip().lower()
    if encoder == "steam":
        raise OtpError("Steam codes are not supported")
    if encoder:
        raise OtpError("the encoder parameter is not supported")  # its codes are not RFC 6238 digits
    if "secret" not in params:
        raise OtpError("the link has no secret parameter")
    result["secret"] = decode_secret(params["secret"])
    if params.get("issuer", "").strip():
        issuer = params["issuer"]
    if "algorithm" in params:
        algorithm = params["algorithm"].upper().replace("-", "")
        if algorithm not in ALGORITHMS:
            raise OtpError("the algorithm parameter must be SHA1, SHA256 or SHA512")
        result["algorithm"] = algorithm
    if "digits" in params:
        digits = _number(params["digits"], "digits")
        if digits not in DIGITS:
            raise OtpError("the digits parameter must be 6 or 8")
        result["digits"] = digits
    if "period" in params:
        period = _number(params["period"], "period")
        if not MIN_PERIOD <= period <= MAX_PERIOD:
            raise OtpError(f"the period parameter must be {MIN_PERIOD} to {MAX_PERIOD} seconds")
        result["period"] = period
    result["issuer"] = _clean_label(issuer)
    result["account"] = _clean_label(account)
    return result


def hotp(secret: bytes, counter: int, algorithm: str = "SHA1", digits: int = 6) -> str:
    """The RFC 4226 one-time password for ``counter``."""
    digest = hmac.new(secret, struct.pack(">Q", counter), _HASHES[algorithm]).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10**digits).zfill(digits)


def code(
    secret: bytes,
    algorithm: str = "SHA1",
    digits: int = 6,
    period: int = 30,
    now: Optional[float] = None,
) -> Tuple[str, float]:
    """The current RFC 6238 code and the seconds it stays valid, to the millisecond."""
    now = time.time() if now is None else now
    # The fraction too: clients that drop it show an expired code for up to a second.
    return hotp(secret, int(now) // period, algorithm, digits), round(period - now % period, 3)


def normalize_site(text: str) -> str:
    """The host of a typed website: "https://GitHub.com/login" -> "github.com".

    Without a scheme too: "github.com/login", "www.github.com:443" and
    "me@github.com" give their host. Anything that is not a plain host name
    comes back stripped but otherwise as typed, for the service to accept or refuse."""
    text = text.strip()
    try:
        host = urlsplit(text if "://" in text else "//" + text).hostname or ""
    except ValueError:
        host = ""
    host = host.rstrip(".").lower()
    return host if _HOST.fullmatch(host) else text


def site_from_issuer(issuer: str) -> str:
    """A website suggestion when the issuer is a host name, otherwise ""."""
    host = issuer.strip().rstrip(".").lower()
    if "." in host and _HOST.fullmatch(host) and valid_rp_id(host):
        return host
    return ""
