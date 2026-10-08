"""Mock Cap'n Proto parser: segment table (count + word lengths).

What this IS: parser/validator for Cap'n Proto (mock).
Mock/simulation for agent-runtime gates -- not a full implementation.

What this IS NOT:
* Not a complete Cap'n Proto (mock) implementation.
* Host enforces real protocol behavior; this validates structure.
"""

from __future__ import annotations

import struct

#: Module version.
PROTO_43_VERSION = "proto-43-capnp.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.proto-43-capnp.v1"


class Proto43Error(Exception):
    """Fail-closed."""


def parse_segment_table(data: bytes) -> dict:
    """Parse a Cap'n Proto segment table. Raises Proto43Error."""
    if len(data) < 4:
        raise Proto43Error("too short")
    (count_minus_one,) = struct.unpack("<I", data[:4])
    count = count_minus_one + 1
    if count > 512:
        raise Proto43Error("too many segments")
    if len(data) < 4 + 4 * count:
        raise Proto43Error("truncated segment table")
    lengths = struct.unpack("<%dI" % count, data[4:4 + 4 * count])
    return {"segments": count, "lengths_words": list(lengths)}


def validate_segment_table(data: bytes) -> tuple:
    """Validate a segment table. Returns (ok, reason)."""
    try:
        parse_segment_table(data)
    except Proto43Error as exc:
        return False, str(exc)
    return True, "valid mock Cap'n Proto"


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
    data = struct.pack("<III", 1, 10, 20)
    p = parse_segment_table(data)
    assert p == {"segments": 2, "lengths_words": [10, 20]}
    ok, _ = validate_segment_table(b"\x00\x00")
    assert ok is False

    assert stdlib_only()
    print("proto-43 (capnp): OK")


if __name__ == "__main__":
    main()
