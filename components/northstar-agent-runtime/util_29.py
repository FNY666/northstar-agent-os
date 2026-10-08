"""Bytes helpers: xor, concat, split, PKCS7 pad. What this IS: small binary plumbing. What this IS NOT: not a cipher."""

from __future__ import annotations

import ast


#: Module version.
UTIL_29_VERSION = "util-29.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.util-29.v1"


class BytesError(Exception):
    """Bytes helper failure."""


def xor_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        raise BytesError("empty key")
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def concat(*parts: bytes) -> bytes:
    return b"".join(parts)


def split_at(data: bytes, n: int):
    return data[:n], data[n:]


def pad_pkcs7(data: bytes, block=16) -> bytes:
    if not 1 <= block <= 255:
        raise BytesError("block must be in [1, 255]")
    pad = block - (len(data) % block)
    return data + bytes([pad]) * pad


def unpad_pkcs7(data: bytes) -> bytes:
    if not data:
        raise BytesError("empty data")
    pad = data[-1]
    if pad < 1 or pad > min(16, len(data)) or data[-pad:] != bytes([pad]) * pad:
        raise BytesError("bad padding")
    return data[:-pad]


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = ['__future__', 'ast', 'pathlib']
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    """Self-check."""
    assert xor_bytes(xor_bytes(b"hello", b"key"), b"key") == b"hello"
    assert concat(b"a", b"b") == b"ab"
    assert split_at(b"abcd", 2) == (b"ab", b"cd")
    assert unpad_pkcs7(pad_pkcs7(b"hi", 8)) == b"hi"
    assert len(pad_pkcs7(b"12345678", 8)) == 16
    print("bytes helpers OK")


if __name__ == "__main__":
    main()
