"""Mock Arrow IPC parser: ARROW1 magic at both ends, schema length.

What this IS: parser/validator for Arrow (mock).
Mock/simulation for agent-runtime gates -- not a full implementation.

What this IS NOT:
* Not a complete Arrow (mock) implementation.
* Host enforces real protocol behavior; this validates structure.
"""

from __future__ import annotations

import struct

#: Module version.
PROTO_41_VERSION = "proto-41-arrow.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.proto-41-arrow.v1"


class Proto41Error(Exception):
    """Fail-closed."""


_MAGIC = b"ARROW1"


def parse_arrow(data: bytes) -> dict:
    """Parse mock Arrow IPC framing. Raises Proto41Error."""
    if len(data) < 16:
        raise Proto41Error("too short")
    if data[:6] != _MAGIC or data[-6:] != _MAGIC:
        raise Proto41Error("missing ARROW1 magic")
    (schema_len,) = struct.unpack("<I", data[6:10])
    if 10 + schema_len > len(data) - 6:
        raise Proto41Error("schema length out of range")
    return {"schema_len": schema_len, "schema": data[10:10 + schema_len]}


def validate_arrow(data: bytes) -> tuple:
    """Validate mock Arrow framing. Returns (ok, reason)."""
    try:
        parse_arrow(data)
    except Proto41Error as exc:
        return False, str(exc)
    return True, "valid mock Arrow"


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
    schema = b"SCHEMA!"
    data = b"ARROW1" + struct.pack("<I", len(schema)) + schema + b"\x00" * 4 + b"ARROW1"
    p = parse_arrow(data)
    assert p["schema"] == schema
    ok, _ = validate_arrow(b"ARROW1" + b"\x00" * 10)
    assert ok is False

    assert stdlib_only()
    print("proto-41 (arrow): OK")


if __name__ == "__main__":
    main()
