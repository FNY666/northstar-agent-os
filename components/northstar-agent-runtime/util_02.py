"""Encoding helpers: base64, base64url, hex, URL. What this IS: safe text/binary codecs with clear errors. What this IS NOT: not encryption."""

from __future__ import annotations

import ast
import base64
import binascii
import urllib.parse

#: Module version.
UTIL_02_VERSION = "util-02.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.util-02.v1"


class EncodingError(Exception):
    """Decode failure."""


def b64encode_text(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


def b64decode_text(s: str) -> str:
    try:
        return base64.b64decode(s.encode("ascii"), validate=True).decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError) as e:
        raise EncodingError(f"bad base64: {e}") from e


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def b64url_decode(s: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(s.encode("ascii"))
    except (binascii.Error, ValueError) as e:
        raise EncodingError(f"bad base64url: {e}") from e


def hex_encode(data: bytes) -> str:
    return data.hex()


def hex_decode(s: str) -> bytes:
    try:
        return bytes.fromhex(s)
    except ValueError as e:
        raise EncodingError(f"bad hex: {e}") from e


def url_encode(s: str) -> str:
    return urllib.parse.quote(s, safe="")


def url_decode(s: str) -> str:
    return urllib.parse.unquote(s)


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = ['__future__', 'ast', 'base64', 'binascii', 'pathlib', 'urllib']
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
    assert b64encode_text("hello") == "aGVsbG8="
    assert b64decode_text("aGVsbG8=") == "hello"
    assert hex_decode(hex_encode(b"abc")) == b"abc"
    assert url_decode(url_encode("a b/c")) == "a b/c"
    assert b64url_decode(b64url_encode(b"\xfb\xff")) == b"\xfb\xff"
    print("encoding helpers OK")


if __name__ == "__main__":
    main()
