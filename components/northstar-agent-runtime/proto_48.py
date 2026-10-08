"""Mock UBJSON parser: type markers i/U/S/Z/T/F and arrays.

What this IS: parser/validator for UBJSON (mock).
Mock/simulation for agent-runtime gates -- not a full implementation.

What this IS NOT:
* Not a complete UBJSON (mock) implementation.
* Host enforces real protocol behavior; this validates structure.
"""

from __future__ import annotations

import struct

#: Module version.
PROTO_48_VERSION = "proto-48-ubjson.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.proto-48-ubjson.v1"


class Proto48Error(Exception):
    """Fail-closed."""


def parse_ubjson(data: bytes, pos: int = 0):
    """Parse one UBJSON value. Returns (value, new_pos)."""
    if pos >= len(data):
        raise Proto48Error("truncated")
    marker = chr(data[pos])
    pos += 1
    if marker == "Z":
        return None, pos
    if marker == "T":
        return True, pos
    if marker == "F":
        return False, pos
    if marker == "i":
        if pos >= len(data):
            raise Proto48Error("truncated int8")
        return struct.unpack("b", data[pos:pos + 1])[0], pos + 1
    if marker == "U":
        if pos >= len(data):
            raise Proto48Error("truncated uint8")
        return data[pos], pos + 1
    if marker == "S":
        ln, pos = parse_ubjson(data, pos)
        if not isinstance(ln, int) or ln < 0:
            raise Proto48Error("bad string length")
        if pos + ln > len(data):
            raise Proto48Error("truncated string")
        return data[pos:pos + ln].decode("utf-8", "replace"), pos + ln
    if marker == "[":
        items = []
        while pos < len(data) and chr(data[pos]) != "]":
            v, pos = parse_ubjson(data, pos)
            items.append(v)
        if pos >= len(data):
            raise Proto48Error("unterminated array")
        return items, pos + 1
    raise Proto48Error("unsupported marker %r" % marker)


def validate_ubjson(data: bytes) -> tuple:
    """Validate mock UBJSON. Returns (ok, reason)."""
    try:
        _, pos = parse_ubjson(data, 0)
    except Proto48Error as exc:
        return False, str(exc)
    if pos != len(data):
        return False, "trailing bytes"
    return True, "valid mock UBJSON"


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
    assert parse_ubjson(b"i\x2A") == (42, 2)
    assert parse_ubjson(b"SU\x02hi") == ("hi", 5)
    assert parse_ubjson(b"[i\x01i\x02]") == ([1, 2], 6)
    assert parse_ubjson(b"Z") == (None, 1)
    ok, _ = validate_ubjson(b"[i\x01")
    assert ok is False

    assert stdlib_only()
    print("proto-48 (ubjson): OK")


if __name__ == "__main__":
    main()
