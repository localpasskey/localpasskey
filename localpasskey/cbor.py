"""Minimal CBOR (RFC 8949) codec covering what CTAP2 uses.

The encoder always produces CTAP2 canonical CBOR: shortest-form integers and
lengths, definite lengths only, and map keys sorted by major type, then by
encoded length, then by encoded bytes. Chromium rejects responses that are not
canonical, so this matters.

The decoder accepts integers, byte/text strings, arrays, maps, booleans and
null, which is everything CTAP2 requests contain.
"""

import struct

MAX_DEPTH = 16


class CBORDecodeError(ValueError):
    pass


def _head(major, value):
    if value < 24:
        return bytes([major << 5 | value])
    if value < 0x100:
        return bytes([major << 5 | 24, value])
    if value < 0x10000:
        return bytes([major << 5 | 25]) + struct.pack(">H", value)
    if value < 0x100000000:
        return bytes([major << 5 | 26]) + struct.pack(">I", value)
    if value < 0x10000000000000000:
        return bytes([major << 5 | 27]) + struct.pack(">Q", value)
    raise ValueError("integer too large for CBOR")


def _map_key_order(encoded_key):
    return encoded_key[0] >> 5, len(encoded_key), encoded_key


def encode(obj):
    if obj is False:
        return b"\xf4"
    if obj is True:
        return b"\xf5"
    if obj is None:
        return b"\xf6"
    if isinstance(obj, int):
        return _head(0, obj) if obj >= 0 else _head(1, -1 - obj)
    if isinstance(obj, (bytes, bytearray, memoryview)):
        data = bytes(obj)
        return _head(2, len(data)) + data
    if isinstance(obj, str):
        data = obj.encode("utf-8")
        return _head(3, len(data)) + data
    if isinstance(obj, (list, tuple)):
        return _head(4, len(obj)) + b"".join(encode(item) for item in obj)
    if isinstance(obj, dict):
        items = sorted(
            ((encode(k), encode(v)) for k, v in obj.items()),
            key=lambda kv: _map_key_order(kv[0]),
        )
        return _head(5, len(items)) + b"".join(k + v for k, v in items)
    raise TypeError(f"cannot CBOR-encode {type(obj).__name__}")


def decode(data):
    data = bytes(data)
    value, offset = _decode(data, 0, 0)
    if offset != len(data):
        raise CBORDecodeError("trailing bytes after CBOR item")
    return value


def _take(data, offset, size):
    end = offset + size
    if end > len(data):
        raise CBORDecodeError("truncated CBOR item")
    return data[offset:end], end


def _decode(data, offset, depth):
    if depth > MAX_DEPTH:
        raise CBORDecodeError("CBOR nesting too deep")
    if offset >= len(data):
        raise CBORDecodeError("truncated CBOR item")
    initial = data[offset]
    offset += 1
    major, info = initial >> 5, initial & 0x1F

    if major == 7:
        simple = {20: False, 21: True, 22: None}
        if info in simple:
            return simple[info], offset
        raise CBORDecodeError("unsupported CBOR simple value or float")

    if info < 24:
        arg = info
    elif info <= 27:
        raw, offset = _take(data, offset, 1 << (info - 24))
        arg = int.from_bytes(raw, "big")
    else:
        raise CBORDecodeError("indefinite-length CBOR items are not allowed")

    if major == 0:
        return arg, offset
    if major == 1:
        return -1 - arg, offset
    if major == 2:
        return _take(data, offset, arg)
    if major == 3:
        raw, offset = _take(data, offset, arg)
        try:
            return raw.decode("utf-8"), offset
        except UnicodeDecodeError:
            raise CBORDecodeError("invalid UTF-8 in CBOR text string") from None
    if major == 4:
        items = []
        for _ in range(arg):
            item, offset = _decode(data, offset, depth + 1)
            items.append(item)
        return items, offset
    if major == 5:
        result = {}
        for _ in range(arg):
            key, offset = _decode(data, offset, depth + 1)
            if isinstance(key, bool) or not isinstance(key, (int, str, bytes)):
                raise CBORDecodeError("unsupported CBOR map key type")
            if key in result:
                raise CBORDecodeError("duplicate CBOR map key")
            result[key], offset = _decode(data, offset, depth + 1)
        return result, offset
    raise CBORDecodeError("CBOR tags are not supported")
