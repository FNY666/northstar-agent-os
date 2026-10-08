"""Mock AMQP parser: protocol header, frame type/channel/size.

What this IS: parser/validator for AMQP (mock).
Mock/simulation for agent-runtime gates -- not a full implementation.

What this IS NOT:
* Not a complete AMQP (mock) implementation.
* Host enforces real protocol behavior; this validates structure.
"""

from __future__ import annotations

import struct

#: Module version.
PROTO_33_VERSION = "proto-33-amqp.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.proto-33-amqp.v1"


class Proto33Error(Exception):
    """Fail-closed."""


_PROTOCOL_HEADER = b"AMQP\x00\x00\x09\x01"
_FRAME_TYPES = {1: "method", 2: "header", 3: "body", 8: "heartbeat"}


def parse_protocol_header(data: bytes) -> dict:
    """Validate the AMQP protocol header. Raises Proto33Error."""
    if len(data) < 8:
        raise Proto33Error("too short")
    if data[:8] != _PROTOCOL_HEADER:
        raise Proto33Error("bad AMQP protocol header")
    return {"ok": True}


def parse_frame(data: bytes) -> dict:
    """Parse an AMQP frame. Raises Proto33Error."""
    if len(data) < 8:
        raise Proto33Error("too short for AMQP frame")
    ftype, channel, size = struct.unpack("!BHI", data[:7])
    if ftype not in _FRAME_TYPES:
        raise Proto33Error("bad frame type %d" % ftype)
    if len(data) < 7 + size + 1:
        raise Proto33Error("truncated frame")
    if data[7 + size] != 0xCE:
        raise Proto33Error("bad frame end octet")
    return {"type": _FRAME_TYPES[ftype], "channel": channel, "size": size,
            "payload": data[7:7 + size]}


def validate_frame(data: bytes) -> tuple:
    """Validate an AMQP frame. Returns (ok, reason)."""
    try:
        parse_frame(data)
    except Proto33Error as exc:
        return False, str(exc)
    return True, "valid AMQP frame"


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
    assert parse_protocol_header(b"AMQP\x00\x00\x09\x01") == {"ok": True}
    frame = struct.pack("!BHI", 1, 3, 2) + b"ab" + bytes([0xCE])
    p = parse_frame(frame)
    assert p == {"type": "method", "channel": 3, "size": 2, "payload": b"ab"}
    ok, _ = validate_frame(b"AMQP\x00\x00\x09\x00extra")
    assert ok is False

    assert stdlib_only()
    print("proto-33 (amqp): OK")


if __name__ == "__main__":
    main()
