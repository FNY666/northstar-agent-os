"""Mock BSON parser: document length, int32/string/bool elements.

What this IS: parser/validator for BSON (mock).
Mock/simulation for agent-runtime gates -- not a full implementation.

What this IS NOT:
* Not a complete BSON (mock) implementation.
* Host enforces real protocol behavior; this validates structure.
"""

from __future__ import annotations

import struct

#: Module version.
PROTO_46_VERSION = "proto-46-bson.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.proto-46-bson.v1"


class Proto46Error(Exception):
    """Fail-closed."""


def parse_bson(data: bytes) -> dict:
    """Parse a mock BSON document. Raises Proto46Error."""
    if len(data) < 5:
        raise Proto46Error("too short")
    (length,) = struct.unpack("<i", data[:4])
    if length != len(data):
        raise Proto46Error("length prefix mismatch")
    if data[-1] != 0x00:
        raise Proto46Error("missing trailing NUL")
    doc = {}
    pos = 4
    while data[pos] != 0x00:
        etype = data[pos]
        pos += 1
        end = data.index(b"\x00", pos)
        name = data[pos:end].decode("utf-8", "replace")
        pos = end + 1
        if etype == 0x10:
            if pos + 4 > len(data):
                raise Proto46Error("truncated int32")
            value = struct.unpack("<i", data[pos:pos + 4])[0]
            pos += 4
        elif etype == 0x08:
            value = bool(data[pos])
            pos += 1
        elif etype == 0x02:
            (slen,) = struct.unpack("<i", data[pos:pos + 4])
            if slen < 1 or pos + 4 + slen > len(data):
                raise Proto46Error("truncated string")
            value = data[pos + 4:pos + 4 + slen - 1].decode("utf-8", "replace")
            pos += 4 + slen
        else:
            raise Proto46Error("unsupported element type 0x%02X" % etype)
        doc[name] = value
    return doc


def validate_bson(data: bytes) -> tuple:
    """Validate a mock BSON document. Returns (ok, reason)."""
    try:
        parse_bson(data)
    except Proto46Error as exc:
        return False, str(exc)
    return True, "valid mock BSON"


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import ast
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "struct", "typing"}
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
    body = b"\x10" + b"a\x00" + struct.pack("<i", 5) + b"\x00"
    data = struct.pack("<i", 4 + len(body)) + body
    assert parse_bson(data) == {"a": 5}
    ok, _ = validate_bson(b"\x00" * 5)
    assert ok is False

    assert stdlib_only()
    print("proto-46 (bson): OK")


if __name__ == "__main__":
    main()
