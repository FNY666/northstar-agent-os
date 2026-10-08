"""Mock HTTP/3 parser: QUIC varint frame type/length/payload.

What this IS: parser/validator for HTTP/3 (mock).
Mock/simulation for agent-runtime gates -- not a full implementation.

What this IS NOT:
* Not a complete HTTP/3 (mock) implementation.
* Host enforces real protocol behavior; this validates structure.
"""

from __future__ import annotations



#: Module version.
PROTO_30_VERSION = "proto-30-http3.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.proto-30-http3.v1"


class Proto30Error(Exception):
    """Fail-closed."""


def _read_varint(data: bytes, pos: int):
    if pos >= len(data):
        raise Proto30Error("truncated varint")
    first = data[pos]
    size = 1 << (first >> 6)
    if pos + size > len(data):
        raise Proto30Error("truncated varint")
    value = first & 0x3F
    for i in range(1, size):
        value = (value << 8) | data[pos + i]
    return value, pos + size


def _write_varint(value: int) -> bytes:
    if value < 0x40:
        return bytes([value])
    if value < 0x4000:
        return bytes([0x40 | (value >> 8), value & 0xFF])
    raise Proto30Error("varint too large for mock")


def parse_frame(data: bytes) -> dict:
    """Parse an HTTP/3 frame. Raises Proto30Error."""
    ftype, pos = _read_varint(data, 0)
    length, pos = _read_varint(data, pos)
    if pos + length > len(data):
        raise Proto30Error("truncated payload")
    return {"type": ftype, "length": length, "payload": data[pos:pos + length]}


def validate_frame(data: bytes) -> tuple:
    """Validate an HTTP/3 frame. Returns (ok, reason)."""
    try:
        parse_frame(data)
    except Proto30Error as exc:
        return False, str(exc)
    return True, "valid HTTP/3 frame"


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import ast
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "typing"}
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
    frame = _write_varint(0) + _write_varint(3) + b"abc"
    p = parse_frame(frame)
    assert p == {"type": 0, "length": 3, "payload": b"abc"}
    ok, _ = validate_frame(b"\x40")
    assert ok is False

    assert stdlib_only()
    print("proto-30 (http3): OK")


if __name__ == "__main__":
    main()
