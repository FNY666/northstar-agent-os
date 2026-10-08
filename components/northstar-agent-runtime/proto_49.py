"""Mock Smile parser: ':)\n' header, version byte, S-len strings.

What this IS: parser/validator for Smile (mock).
Mock/simulation for agent-runtime gates -- not a full implementation.

What this IS NOT:
* Not a complete Smile (mock) implementation.
* Host enforces real protocol behavior; this validates structure.
"""

from __future__ import annotations



#: Module version.
PROTO_49_VERSION = "proto-49-smile.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.proto-49-smile.v1"


class Proto49Error(Exception):
    """Fail-closed."""


_HEADER = b":)\n"


def parse_smile(data: bytes) -> dict:
    """Parse mock Smile framing. Raises Proto49Error."""
    if len(data) < 4:
        raise Proto49Error("too short")
    if data[:3] != _HEADER:
        raise Proto49Error("missing Smile header")
    version = data[3]
    values = []
    pos = 4
    while pos < len(data):
        marker = data[pos]
        pos += 1
        if marker != 0x53:
            raise Proto49Error("bad value marker 0x%02X" % marker)
        if pos >= len(data):
            raise Proto49Error("truncated string length")
        ln = data[pos]
        pos += 1
        if pos + ln > len(data):
            raise Proto49Error("truncated string")
        values.append(data[pos:pos + ln].decode("utf-8", "replace"))
        pos += ln
    return {"version": version, "values": values}


def validate_smile(data: bytes) -> tuple:
    """Validate mock Smile. Returns (ok, reason)."""
    try:
        parse_smile(data)
    except Proto49Error as exc:
        return False, str(exc)
    return True, "valid mock Smile"


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
    data = b":)\n" + bytes([0]) + b"S\x02hi" + b"S\x01!"
    p = parse_smile(data)
    assert p == {"version": 0, "values": ["hi", "!"]}
    ok, _ = validate_smile(b"nope")
    assert ok is False

    assert stdlib_only()
    print("proto-49 (smile): OK")


if __name__ == "__main__":
    main()
