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
MAX_INPUT = 8192  # characters of pasted text: a migration link holds a batch of codes
MAX_COUNTER = 2**53 - 1  # the largest counter a JavaScript client handles exactly
MAX_MIGRATION_ENTRIES = 64  # more than Google Authenticator's batch of 10, less than a flood
MAX_LABEL = MAX_LABEL_LENGTH  # site, issuer and account
STEAM_ALPHABET, STEAM_DIGITS = "23456789BCDFGHJKMNPQRTVWXY", 5

_HASHES = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}
_BASE32 = re.compile(r"[A-Z2-7]*")
_NUMBER = re.compile(r"[0-9]{1,4}")
_COUNTER = re.compile(r"[0-9]{1,16}")
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


def _counter(value: str, name: str = "counter") -> int:
    # A JavaScript client shows this link too: keep the counter a safe integer.
    if not _COUNTER.fullmatch(value) or int(value) > MAX_COUNTER:
        raise OtpError(f"the {name} parameter must be 0 to {MAX_COUNTER}")
    return int(value)


def _steam(result: dict) -> dict:
    result.update(kind="steam", algorithm="SHA1", digits=STEAM_DIGITS, period=DEFAULT_PERIOD, counter=0)
    return result


def parse(text: str) -> dict:
    """Parse a pasted ``otpauth://`` link or bare setup key.

    Returns a dict with the keys secret (bytes), issuer, account, algorithm,
    digits, period, kind ("totp", "hotp" or "steam") and counter (only an
    hotp code uses it). Raises OtpError with a message for the user."""
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
        "kind": "totp",
        "counter": 0,
    }
    if "://" not in text and not text.lower().startswith("otpauth:"):
        result["secret"] = decode_secret(text)
        return result
    try:
        url = urlsplit(text)
    except ValueError:
        raise OtpError("not an otpauth://totp/ link or a setup key") from None
    scheme, kind = url.scheme.lower(), url.netloc.lower()
    if scheme == "steam":
        result["secret"] = decode_secret(url.netloc + url.path)  # steam://BASE32
        return _steam(result)
    if scheme != "otpauth" or kind not in ("totp", "hotp", "steam"):
        raise OtpError("not an otpauth://totp/ link or a setup key")

    label = unquote(url.path[1:])
    issuer, account = label.split(":", 1) if ":" in label else ("", label)
    params = {}
    for key, value in parse_qsl(url.query, keep_blank_values=True):
        params.setdefault(key.lower(), value)

    if kind == "steam":
        # otpauth://steam/BASE32 has the key in the path and no label.
        result["secret"] = decode_secret(params["secret"] if "secret" in params else url.path[1:])
        result["issuer"] = _clean_label(params.get("issuer", ""))
        return _steam(result)

    encoder = params.get("encoder", "").strip().lower()
    if encoder and encoder != "steam":
        raise OtpError("the encoder parameter is not supported")  # its codes are not RFC 6238 digits
    if "secret" not in params:
        raise OtpError("the link has no secret parameter")
    result["secret"] = decode_secret(params["secret"])
    if params.get("issuer", "").strip():
        issuer = params["issuer"]
    if kind == "hotp":
        if "counter" not in params:
            raise OtpError("the link has no counter parameter")
        result["kind"] = "hotp"
        result["counter"] = _counter(params["counter"])
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
    if encoder == "steam":
        return _steam(result)  # its own alphabet: no algorithm, digits or period to read
    return result


class _BadPayload(Exception):
    """Protobuf bytes that do not decode; fail closed, never guess."""


def _varint(data: memoryview, pos: int) -> Tuple[int, int]:
    value = 0
    for shift in range(0, 70, 7):
        if pos >= len(data):
            raise _BadPayload("truncated")
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            if shift == 63 and value >> 64:  # a 10th byte past 64 bits is an overflow
                raise _BadPayload("overflow")
            return value, pos
    raise _BadPayload("overlong")


def _fields(data: bytes):
    """The (number, value) pairs of a protobuf message; length-delimited values are bytes."""
    view, pos = memoryview(data), 0
    while pos < len(view):
        key, pos = _varint(view, pos)
        number, wire = key >> 3, key & 7
        if not number:
            raise _BadPayload("field 0")
        if wire == 0:
            value, pos = _varint(view, pos)
        elif wire == 2:
            size, pos = _varint(view, pos)
            if size > len(view) - pos:
                raise _BadPayload("length past the end")
            value, pos = bytes(view[pos : pos + size]), pos + size
        else:
            raise _BadPayload("wire type")  # no fixed-width fields, no groups
        yield number, value


ALGORITHM_NAMES = {1: "SHA1", 2: "SHA256", 3: "SHA512"}  # 4 is MD5, which is refused
MIGRATION_DIGITS = {1: 6, 2: 8}


def parse_migration(text: str) -> Tuple[list, list]:
    """The entries of a Google Authenticator export link, and the codes skipped.

    Returns ``(entries, skipped)``: dicts like ``parse``'s but with the secret as
    bytes, which the caller encodes, and ``(label, reason)`` pairs. The link is
    protobuf in Base64; there is no dependency to decode it."""
    if len(text) > MAX_INPUT:
        raise OtpError("the text is too long for a setup key or link")
    text = text.strip()
    if not text.lower().startswith("otpauth-migration://"):
        raise OtpError("not a migration link")
    query = urlsplit(text).query
    data = ""
    for part in query.split("&"):
        name, _, value = part.partition("=")
        if name.lower() == "data":
            # unquote, not parse_qsl: "+" is a Base64 digit here, not a space.
            data = unquote(value)
            break
    try:
        payload = base64.b64decode(data + "=" * (-len(data) % 4), validate=False)
    except (binascii.Error, ValueError):
        raise OtpError("this migration link is damaged") from None
    try:
        return _migration_entries(payload)
    except (_BadPayload, UnicodeDecodeError):
        raise OtpError("this migration link is damaged") from None


def _migration_entries(payload: bytes) -> Tuple[list, list]:
    messages = [value for number, value in _fields(payload) if number == 1]
    if not messages:
        raise OtpError("this migration link holds no codes")
    if len(messages) > MAX_MIGRATION_ENTRIES:
        raise OtpError("this migration link holds too many codes")
    entries, skipped = [], []
    for message in messages:
        if not isinstance(message, bytes):
            raise _BadPayload("not a message")
        wanted, secret = {}, b""
        for number, value in _fields(message):
            if number == 1 and isinstance(value, bytes):
                secret = value
            elif number in (2, 3):
                if not isinstance(value, bytes):
                    raise _BadPayload("not text")
                wanted[number] = value.decode("utf-8")
            elif number in (4, 5, 6, 7):
                if not isinstance(value, int):
                    raise _BadPayload("not a number")
                wanted[number] = value
        # Fail closed on an enum this build does not know: a guessed code is no code.
        if (wanted.get(4, 0) not in (0, 1, 2, 3, 4) or wanted.get(5, 0) not in (0, 1, 2)
                or wanted.get(6, 0) not in (0, 1, 2)):
            raise _BadPayload("enum")
        label = _clean_label(wanted.get(2, ""))
        issuer, account = label.split(":", 1) if ":" in label else ("", label)
        issuer = _clean_label(wanted.get(3, "")) or issuer
        if wanted.get(4) == 4:
            skipped.append((label, "MD5-based codes are not supported"))
            continue
        if len(secret) < MIN_SECRET_BYTES:
            skipped.append((label, "the setup key is too short"))
            continue
        if len(secret) > MAX_SECRET_BYTES:
            skipped.append((label, "the setup key is too long"))
            continue
        counter = wanted.get(7, 0)
        if not 0 <= counter <= MAX_COUNTER:
            raise _BadPayload("counter")
        kind = {1: "hotp", 2: "totp"}.get(wanted.get(6), "hotp" if counter else "totp")
        entries.append({
            "secret": secret,
            "issuer": issuer,
            "account": account,
            "algorithm": ALGORITHM_NAMES.get(wanted.get(4), DEFAULT_ALGORITHM),
            "digits": MIGRATION_DIGITS.get(wanted.get(5), DEFAULT_DIGITS),
            "period": DEFAULT_PERIOD,
            "kind": kind,
            "counter": counter if kind == "hotp" else 0,
        })
    return entries, skipped


def migration_entry_id(kind: str, issuer: str, account: str, secret: bytes) -> bytes:
    """The stable 16-byte ID of a migration entry: importing the same batch twice is idempotent."""
    data = b"\0".join([kind.encode(), issuer.encode("utf-8", "surrogateescape"),
                       account.encode("utf-8", "surrogateescape"), secret])
    return hashlib.blake2b(data, key=b"lpk-migration", digest_size=16).digest()


def _truncate(secret: bytes, counter: int, algorithm: str) -> int:
    """RFC 4226 dynamic truncation: the 31-bit value both code alphabets start from."""
    if isinstance(counter, bool) or not isinstance(counter, int) or not 0 <= counter < 2**64:
        raise OtpError("the counter must be 0 to 2**64-1")
    digest = hmac.new(secret, struct.pack(">Q", counter), _HASHES[algorithm]).digest()
    offset = digest[-1] & 0x0F
    return struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF


def hotp(secret: bytes, counter: int, algorithm: str = "SHA1", digits: int = 6) -> str:
    """The RFC 4226 one-time password for ``counter``."""
    if isinstance(digits, bool) or not isinstance(digits, int) or not 1 <= digits <= 10:
        raise OtpError("the digits must be 1 to 10")
    return str(_truncate(secret, counter, algorithm) % 10**digits).zfill(digits)


def steam_code(secret: bytes, counter: int) -> str:
    """The Steam Guard code for ``counter``: five characters of Steam's alphabet."""
    value = _truncate(secret, counter, "SHA1")
    chars = []
    for _ in range(STEAM_DIGITS):
        value, index = divmod(value, len(STEAM_ALPHABET))
        chars.append(STEAM_ALPHABET[index])
    return "".join(chars)


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
    # Never 0.0: in the last half millisecond the code is still this one, so say "1 more second".
    return hotp(secret, int(now) // period, algorithm, digits), max(round(period - now % period, 3), 0.001)


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
