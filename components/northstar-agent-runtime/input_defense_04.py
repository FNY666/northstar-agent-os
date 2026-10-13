"""Encoding normalization: strict UTF-8 decode + BOM handling, Simulated.

Bytes must decode as strict UTF-8; any invalid sequence raises
InputDefense04Error (fail-closed) instead of being replaced or ignored.
A leading BOM (U+FEFF) is stripped because it is a common smuggling vector
that changes byte-level fingerprints of otherwise identical text.

What this IS: a fail-closed UTF-8 normalization gate.

What this IS NOT:
* A charset sniffer (non-UTF-8 encodings are rejected, not transcoded).
* A sanitizer of decoded text content.
"""

from __future__ import annotations

import ast
import pathlib

#: Module version.
INPUT_DEFENSE_04_VERSION = "input-defense-04.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.input-defense-04.v1"


class InputDefense04Error(Exception):
    """Fail-closed."""


#: Byte-order mark, stripped when leading.
_BOM = "\ufeff"


def normalize_bytes(data: bytes) -> str:
    """Strict UTF-8 decode; strip leading BOM; raise on invalid sequences."""
    if not isinstance(data, bytes):
        raise InputDefense04Error(
            f"normalize_bytes() requires bytes, got {type(data).__name__}"
        )
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise InputDefense04Error(f"invalid UTF-8 sequence: {exc}") from exc
    if text.startswith(_BOM):
        text = text[len(_BOM):]
    return text


def normalize_text(text: str) -> str:
    """Strip a leading BOM; otherwise return text unchanged."""
    if not isinstance(text, str):
        raise InputDefense04Error(
            f"normalize_text() requires str, got {type(text).__name__}"
        )
    if text.startswith(_BOM):
        return text[len(_BOM):]
    return text


def is_valid_utf8(data: bytes) -> bool:
    """True iff data decodes as strict UTF-8 (BOM is allowed)."""
    if not isinstance(data, bytes):
        raise InputDefense04Error(
            f"is_valid_utf8() requires bytes, got {type(data).__name__}"
        )
    try:
        data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return False
    return True


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib"}
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
    assert normalize_bytes(b"hello") == "hello"
    assert normalize_bytes("héllo".encode("utf-8")) == "héllo"
    assert normalize_bytes(b"\xef\xbb\xbfhello") == "hello"
    assert normalize_bytes(b"") == ""
    # Mid-string BOM is kept; only a leading BOM is stripped.
    assert normalize_bytes("a\ufeffb".encode("utf-8")) == "a\ufeffb"
    try:
        normalize_bytes(b"\xff\xfe\x00bad")
    except InputDefense04Error:
        pass
    else:
        raise AssertionError("invalid UTF-8 must raise")
    try:
        normalize_bytes("not bytes")  # type: ignore[arg-type]
    except InputDefense04Error:
        pass
    else:
        raise AssertionError("non-bytes input must raise")
    assert normalize_text("\ufeffhello") == "hello"
    assert normalize_text("hello") == "hello"
    try:
        normalize_text(b"nope")  # type: ignore[arg-type]
    except InputDefense04Error:
        pass
    else:
        raise AssertionError("non-str input must raise")
    assert is_valid_utf8(b"ok") is True
    assert is_valid_utf8(b"\xff") is False
    assert is_valid_utf8(b"\xef\xbb\xbfbom-ok") is True
    assert stdlib_only()
    print("input-defense-04 OK")


if __name__ == "__main__":
    main()
