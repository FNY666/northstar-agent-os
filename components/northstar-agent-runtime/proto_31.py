"""Mock WebSocket parser: frame header, opcodes, masking.

What this IS: parser/validator for WebSocket (mock).
Mock/simulation for agent-runtime gates -- not a full implementation.

What this IS NOT:
* Not a complete WebSocket (mock) implementation.
* Host enforces real protocol behavior; this validates structure.
"""

from __future__ import annotations



#: Module version.
PROTO_31_VERSION = "proto-31-websocket.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.proto-31-websocket.v1"


class Proto31Error(Exception):
    """Fail-closed."""


_OPCODES = {0: "continuation", 1: "text", 2: "binary",
             8: "close", 9: "ping", 10: "pong"}


def parse_frame(data: bytes) -> dict:
    """Parse a WebSocket frame. Raises Proto31Error."""
    if len(data) < 2:
        raise Proto31Error("too short")
    b0, b1 = data[0], data[1]
    fin = bool(b0 & 0x80)
    if (b0 >> 4) & 0x07:
        raise Proto31Error("RSV bits must be 0")
    opcode = b0 & 0x0F
    if opcode not in _OPCODES:
        raise Proto31Error("bad opcode %d" % opcode)
    masked = bool(b1 & 0x80)
    length = b1 & 0x7F
    pos = 2
    if length == 126:
        if len(data) < pos + 2:
            raise Proto31Error("truncated extended length")
        length = int.from_bytes(data[pos:pos + 2], "big")
        pos += 2
    elif length == 127:
        if len(data) < pos + 8:
            raise Proto31Error("truncated extended length")
        length = int.from_bytes(data[pos:pos + 8], "big")
        pos += 8
    key = b""
    if masked:
        if len(data) < pos + 4:
            raise Proto31Error("truncated mask key")
        key = data[pos:pos + 4]
        pos += 4
    if len(data) < pos + length:
        raise Proto31Error("truncated payload")
    payload = data[pos:pos + length]
    if masked:
        payload = bytes(c ^ key[i % 4] for i, c in enumerate(payload))
    frame = {"fin": fin, "opcode": _OPCODES[opcode], "masked": masked,
             "length": length, "payload": payload}
    if _OPCODES[opcode] in ("close", "ping", "pong"):
        if not fin:
            raise Proto31Error("control frames must not be fragmented")
        if length > 125:
            raise Proto31Error("control frame too large")
    return frame


def validate_frame(data: bytes) -> tuple:
    """Validate a WebSocket frame. Returns (ok, reason)."""
    try:
        parse_frame(data)
    except Proto31Error as exc:
        return False, str(exc)
    return True, "valid WebSocket frame"


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
    p = parse_frame(bytes([0x81, 0x03]) + b"hey")
    assert p == {"fin": True, "opcode": "text", "masked": False, "length": 3, "payload": b"hey"}
    masked = bytes([0x82, 0x83]) + b"\x01\x02\x03\x04" + bytes([b ^ b"\x01\x02\x03\x04"[i % 4] for i, b in enumerate(b"bye")])
    assert parse_frame(masked)["payload"] == b"bye"
    ok, _ = validate_frame(bytes([0x83, 0x7E]))
    assert ok is False

    assert stdlib_only()
    print("proto-31 (websocket): OK")


if __name__ == "__main__":
    main()
