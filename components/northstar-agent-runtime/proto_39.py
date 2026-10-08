"""Mock Parquet parser: PAR1 magic at both ends, footer length.

What this IS: parser/validator for Parquet (mock).
Mock/simulation for agent-runtime gates -- not a full implementation.

What this IS NOT:
* Not a complete Parquet (mock) implementation.
* Host enforces real protocol behavior; this validates structure.
"""

from __future__ import annotations

import struct

#: Module version.
PROTO_39_VERSION = "proto-39-parquet.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.proto-39-parquet.v1"


class Proto39Error(Exception):
    """Fail-closed."""


_MAGIC = b"PAR1"


def parse_parquet(data: bytes) -> dict:
    """Parse mock Parquet framing. Raises Proto39Error."""
    if len(data) < 12:
        raise Proto39Error("too short")
    if data[:4] != _MAGIC:
        raise Proto39Error("missing leading PAR1 magic")
    if data[-4:] != _MAGIC:
        raise Proto39Error("missing trailing PAR1 magic")
    (footer_len,) = struct.unpack("<I", data[-8:-4])
    if footer_len > len(data) - 12:
        raise Proto39Error("footer length out of range")
    start = len(data) - 8 - footer_len
    return {"footer_len": footer_len, "footer": data[start:len(data) - 8]}


def validate_parquet(data: bytes) -> tuple:
    """Validate mock Parquet framing. Returns (ok, reason)."""
    try:
        parse_parquet(data)
    except Proto39Error as exc:
        return False, str(exc)
    return True, "valid mock Parquet"


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
    footer = b"FOOTER!"
    data = b"PAR1" + b"\x00" * 10 + footer + struct.pack("<I", len(footer)) + b"PAR1"
    p = parse_parquet(data)
    assert p["footer"] == footer
    ok, _ = validate_parquet(b"PAR1" + b"\x00" * 8)
    assert ok is False

    assert stdlib_only()
    print("proto-39 (parquet): OK")


if __name__ == "__main__":
    main()
