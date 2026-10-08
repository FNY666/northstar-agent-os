"""Mock CoAP parser: 4-byte header, version/type/token/message id.

What this IS: parser/validator for CoAP (mock).
Mock/simulation for agent-runtime gates -- not a full implementation.

What this IS NOT:
* Not a complete CoAP (mock) implementation.
* Host enforces real protocol behavior; this validates structure.
"""

from __future__ import annotations

import struct

#: Module version.
PROTO_35_VERSION = "proto-35-coap.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.proto-35-coap.v1"


class Proto35Error(Exception):
    """Fail-closed."""


_TYPES = {0: "CON", 1: "NON", 2: "ACK", 3: "RST"}


def parse_coap(data: bytes) -> dict:
    """Parse a CoAP header. Raises Proto35Error."""
    if len(data) < 4:
        raise Proto35Error("too short")
    b0, code, msgid = struct.unpack("!BBH", data[:4])
    version = b0 >> 6
    if version != 1:
        raise Proto35Error("bad CoAP version %d" % version)
    mtype = _TYPES[(b0 >> 4) & 0x03]
    tkl = b0 & 0x0F
    if tkl > 8:
        raise Proto35Error("token too long")
    if len(data) < 4 + tkl:
        raise Proto35Error("truncated token")
    token = data[4:4 + tkl]
    return {"version": version, "type": mtype, "code": code,
            "message_id": msgid, "token": token.hex()}


def validate_coap(data: bytes) -> tuple:
    """Validate a CoAP header. Returns (ok, reason)."""
    try:
        parse_coap(data)
    except Proto35Error as exc:
        return False, str(exc)
    return True, "valid CoAP header"


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
    hdr = struct.pack("!BBH", 0x42, 0x01, 0x1234) + b"\xAA\xBB"
    p = parse_coap(hdr)
    assert p == {"version": 1, "type": "CON", "code": 1, "message_id": 0x1234, "token": "aabb"}
    ok, _ = validate_coap(struct.pack("!BBH", 0x82, 0x01, 1))
    assert ok is False

    assert stdlib_only()
    print("proto-35 (coap): OK")


if __name__ == "__main__":
    main()
