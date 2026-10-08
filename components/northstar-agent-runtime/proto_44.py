"""Mock FlatBuffers parser: root offset, vtable bounds.

What this IS: parser/validator for FlatBuffers (mock).
Mock/simulation for agent-runtime gates -- not a full implementation.

What this IS NOT:
* Not a complete FlatBuffers (mock) implementation.
* Host enforces real protocol behavior; this validates structure.
"""

from __future__ import annotations

import struct

#: Module version.
PROTO_44_VERSION = "proto-44-flatbuffers.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.proto-44-flatbuffers.v1"


class Proto44Error(Exception):
    """Fail-closed."""


def parse_table(data: bytes, offset: int = 0) -> dict:
    """Parse a mock FlatBuffers table root. Raises Proto44Error."""
    if len(data) < offset + 4:
        raise Proto44Error("too short for root offset")
    (root,) = struct.unpack("<I", data[offset:offset + 4])
    table_pos = offset + root
    if len(data) < table_pos + 4:
        raise Proto44Error("root out of range")
    (vtable_soff,) = struct.unpack("<i", data[table_pos:table_pos + 4])
    vtable_pos = table_pos - vtable_soff
    if vtable_pos < 0 or len(data) < vtable_pos + 4:
        raise Proto44Error("vtable out of range")
    vlen, tlen = struct.unpack("<HH", data[vtable_pos:vtable_pos + 4])
    return {"root": root, "vtable_len": vlen, "table_len": tlen}


def validate_table(data: bytes) -> tuple:
    """Validate a mock FlatBuffers table. Returns (ok, reason)."""
    try:
        parse_table(data)
    except Proto44Error as exc:
        return False, str(exc)
    return True, "valid mock FlatBuffers"


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
    # vtable at 0 (vlen=8, tlen=12); root u32 at 8 -> table at 16; soff=16 -> vtable at 0
    data = (struct.pack("<HH", 8, 12) + bytes(4) + struct.pack("<I", 8)
            + bytes(4) + struct.pack("<i", 16))
    p = parse_table(data, offset=8)
    assert p == {"root": 8, "vtable_len": 8, "table_len": 12}
    ok, _ = validate_table(b"\x00" * 4)
    assert ok is False

    assert stdlib_only()
    print("proto-44 (flatbuffers): OK")


if __name__ == "__main__":
    main()
