"""Mock HTTP/2 parser: 9-byte frame header, stream id, types.

What this IS: parser/validator for HTTP/2 (mock).
Mock/simulation for agent-runtime gates -- not a full implementation.

What this IS NOT:
* Not a complete HTTP/2 (mock) implementation.
* Host enforces real protocol behavior; this validates structure.
"""

from __future__ import annotations

import struct

#: Module version.
PROTO_29_VERSION = "proto-29-http2.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.proto-29-http2.v1"


class Proto29Error(Exception):
    """Fail-closed."""


_FRAME_TYPES = {0: "DATA", 1: "HEADERS", 2: "PRIORITY", 3: "RST_STREAM",
                4: "SETTINGS", 5: "PUSH_PROMISE", 6: "PING", 7: "GOAWAY",
                8: "WINDOW_UPDATE", 9: "CONTINUATION"}


def parse_frame(data: bytes) -> dict:
    """Parse an HTTP/2 frame header + payload. Raises Proto29Error."""
    if len(data) < 9:
        raise Proto29Error("too short for HTTP/2 frame header")
    length = int.from_bytes(data[0:3], "big")
    ftype = data[3]
    flags = data[4]
    stream_id = struct.unpack("!I", data[5:9])[0] & 0x7FFFFFFF
    if ftype not in _FRAME_TYPES:
        raise Proto29Error("unknown frame type %d" % ftype)
    if len(data) < 9 + length:
        raise Proto29Error("truncated payload")
    return {"length": length, "type": _FRAME_TYPES[ftype], "flags": flags,
            "stream_id": stream_id, "payload": data[9:9 + length]}


def validate_frame(data: bytes) -> tuple:
    """Validate an HTTP/2 frame. Returns (ok, reason)."""
    try:
        parse_frame(data)
    except Proto29Error as exc:
        return False, str(exc)
    return True, "valid HTTP/2 frame"


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
    frame = b"\x00\x00\x05" + bytes([4, 0]) + struct.pack("!I", 0) + b"hello"
    p = parse_frame(frame)
    assert p["type"] == "SETTINGS" and p["stream_id"] == 0
    assert p["payload"] == b"hello"
    ok, _ = validate_frame(b"\x00" * 8)
    assert ok is False

    assert stdlib_only()
    print("proto-29 (http2): OK")


if __name__ == "__main__":
    main()
