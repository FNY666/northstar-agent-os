"""Mock QUIC parser: long/short header form, connection IDs.

What this IS: parser/validator for QUIC (mock).
Mock/simulation for agent-runtime gates -- not a full implementation.

What this IS NOT:
* Not a complete QUIC (mock) implementation.
* Host enforces real protocol behavior; this validates structure.
"""

from __future__ import annotations

import struct

#: Module version.
PROTO_28_VERSION = "proto-28-quic.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.proto-28-quic.v1"


class Proto28Error(Exception):
    """Fail-closed."""


def parse_quic(data: bytes) -> dict:
    """Parse a mock QUIC header. Raises Proto28Error."""
    if not data:
        raise Proto28Error("empty")
    first = data[0]
    if first & 0x80:
        if len(data) < 7:
            raise Proto28Error("truncated long header")
        (version,) = struct.unpack("!I", data[1:5])
        dcid_len = data[5]
        pos = 6
        if len(data) < pos + dcid_len + 1:
            raise Proto28Error("truncated dcid")
        dcid = data[pos:pos + dcid_len]
        pos += dcid_len
        scid_len = data[pos]
        pos += 1
        if len(data) < pos + scid_len:
            raise Proto28Error("truncated scid")
        scid = data[pos:pos + scid_len]
        return {"form": "long", "type": first & 0x7F, "version": version,
                "dcid": dcid.hex(), "scid": scid.hex()}
    return {"form": "short", "dcid": data[1:].hex()}


def validate_quic(data: bytes) -> tuple:
    """Validate a mock QUIC header. Returns (ok, reason)."""
    try:
        parse_quic(data)
    except Proto28Error as exc:
        return False, str(exc)
    return True, "valid mock QUIC"


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
    long = bytes([0xC0]) + struct.pack("!I", 1) + bytes([2]) + b"dc" + bytes([2]) + b"sc"
    p = parse_quic(long)
    assert p["form"] == "long" and p["dcid"] == b"dc".hex()
    s = parse_quic(bytes([0x40]) + b"connid")
    assert s["form"] == "short"
    ok, _ = validate_quic(b"")
    assert ok is False

    assert stdlib_only()
    print("proto-28 (quic): OK")


if __name__ == "__main__":
    main()
