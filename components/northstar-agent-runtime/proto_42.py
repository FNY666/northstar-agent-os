"""Mock Protobuf parser: varint, tags, wire types 0/1/2/5.

What this IS: parser/validator for Protobuf (mock).
Mock/simulation for agent-runtime gates -- not a full implementation.

What this IS NOT:
* Not a complete Protobuf (mock) implementation.
* Host enforces real protocol behavior; this validates structure.
"""

from __future__ import annotations



#: Module version.
PROTO_42_VERSION = "proto-42-protobuf.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.proto-42-protobuf.v1"


class Proto42Error(Exception):
    """Fail-closed."""


def _read_varint(data: bytes, pos: int):
    result = 0
    shift = 0
    while True:
        if pos >= len(data):
            raise Proto42Error("truncated varint")
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, pos
        shift += 7
        if shift >= 64:
            raise Proto42Error("varint too long")


def parse_fields(data: bytes) -> list:
    """Parse protobuf wire format into [(field, wire_type, value)]."""
    fields = []
    pos = 0
    while pos < len(data):
        tag, pos = _read_varint(data, pos)
        field = tag >> 3
        wire = tag & 0x07
        if field == 0:
            raise Proto42Error("field number 0 invalid")
        if wire == 0:
            value, pos = _read_varint(data, pos)
        elif wire == 1:
            if pos + 8 > len(data):
                raise Proto42Error("truncated 64-bit")
            value = data[pos:pos + 8]
            pos += 8
        elif wire == 2:
            ln, pos = _read_varint(data, pos)
            if pos + ln > len(data):
                raise Proto42Error("truncated length-delimited")
            value = data[pos:pos + ln]
            pos += ln
        elif wire == 5:
            if pos + 4 > len(data):
                raise Proto42Error("truncated 32-bit")
            value = data[pos:pos + 4]
            pos += 4
        else:
            raise Proto42Error("unsupported wire type %d" % wire)
        fields.append((field, wire, value))
    return fields


def validate_fields(data: bytes) -> tuple:
    """Validate protobuf wire format. Returns (ok, reason)."""
    try:
        parse_fields(data)
    except Proto42Error as exc:
        return False, str(exc)
    return True, "valid mock protobuf"


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
    # field 1 varint 150, field 2 length-delimited b"hi"
    data = bytes([0x08, 0x96, 0x01, 0x12, 0x02]) + b"hi"
    fields = parse_fields(data)
    assert fields == [(1, 0, 150), (2, 2, b"hi")]
    ok, _ = validate_fields(bytes([0x08]))
    assert ok is False

    assert stdlib_only()
    print("proto-42 (protobuf): OK")


if __name__ == "__main__":
    main()
