"""Mock Thrift parser: strict binary protocol message header.

What this IS: parser/validator for Thrift (mock).
Mock/simulation for agent-runtime gates -- not a full implementation.

What this IS NOT:
* Not a complete Thrift (mock) implementation.
* Host enforces real protocol behavior; this validates structure.
"""

from __future__ import annotations

import struct

#: Module version.
PROTO_37_VERSION = "proto-37-thrift.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.proto-37-thrift.v1"


class Proto37Error(Exception):
    """Fail-closed."""


def encode_message(name: str, msg_type: int, seqid: int) -> bytes:
    """Encode a mock strict Thrift message header (helper for tests)."""
    header = 0x80010000 | (msg_type & 0xFF)
    nb = name.encode("utf-8")
    return (struct.pack("!I", header) + struct.pack("!i", len(nb)) + nb
            + struct.pack("!i", seqid))


def parse_message(data: bytes) -> dict:
    """Parse a strict Thrift message header. Raises Proto37Error."""
    if len(data) < 12:
        raise Proto37Error("too short")
    (header,) = struct.unpack("!i", data[:4])
    if header & 0xFFFF0000 != 0x80010000:
        raise Proto37Error("not strict thrift")
    msg_type = header & 0xFF
    (nlen,) = struct.unpack("!i", data[4:8])
    if nlen < 0 or len(data) < 8 + nlen + 4:
        raise Proto37Error("truncated")
    name = data[8:8 + nlen].decode("utf-8", "replace")
    (seqid,) = struct.unpack("!i", data[8 + nlen:12 + nlen])
    return {"type": msg_type, "name": name, "seqid": seqid}


def validate_message(data: bytes) -> tuple:
    """Validate a Thrift message header. Returns (ok, reason)."""
    try:
        parse_message(data)
    except Proto37Error as exc:
        return False, str(exc)
    return True, "valid Thrift message"


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
    raw = encode_message("ping", 1, 42)
    p = parse_message(raw)
    assert p == {"type": 1, "name": "ping", "seqid": 42}
    ok, _ = validate_message(b"\x00" * 12)
    assert ok is False

    assert stdlib_only()
    print("proto-37 (thrift): OK")


if __name__ == "__main__":
    main()
