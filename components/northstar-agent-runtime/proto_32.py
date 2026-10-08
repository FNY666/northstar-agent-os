"""Mock MQTT parser: fixed header, remaining length, CONNECT.

What this IS: parser/validator for MQTT (mock).
Mock/simulation for agent-runtime gates -- not a full implementation.

What this IS NOT:
* Not a complete MQTT (mock) implementation.
* Host enforces real protocol behavior; this validates structure.
"""

from __future__ import annotations

import struct

#: Module version.
PROTO_32_VERSION = "proto-32-mqtt.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.proto-32-mqtt.v1"


class Proto32Error(Exception):
    """Fail-closed."""


_PACKET_TYPES = {1: "CONNECT", 2: "CONNACK", 3: "PUBLISH", 4: "PUBACK",
                5: "PUBREC", 6: "PUBREL", 7: "PUBCOMP", 8: "SUBSCRIBE",
                9: "SUBACK", 10: "UNSUBSCRIBE", 11: "UNSUBACK", 12: "PINGREQ",
                13: "PINGRESP", 14: "DISCONNECT"}


def _read_remaining(data: bytes, pos: int):
    mult = 1
    value = 0
    for _ in range(4):
        if pos >= len(data):
            raise Proto32Error("truncated remaining length")
        b = data[pos]
        pos += 1
        value += (b & 0x7F) * mult
        if not b & 0x80:
            return value, pos
        mult *= 128
    raise Proto32Error("malformed remaining length")


def parse_fixed_header(data: bytes) -> dict:
    """Parse the MQTT fixed header. Raises Proto32Error."""
    if not data:
        raise Proto32Error("empty")
    ptype = data[0] >> 4
    if ptype not in _PACKET_TYPES:
        raise Proto32Error("bad packet type %d" % ptype)
    remaining, pos = _read_remaining(data, 1)
    return {"type": _PACKET_TYPES[ptype], "flags": data[0] & 0x0F,
            "remaining": remaining, "header_len": pos}


def parse_connect(data: bytes) -> dict:
    """Parse an MQTT CONNECT packet. Raises Proto32Error."""
    hdr = parse_fixed_header(data)
    if hdr["type"] != "CONNECT":
        raise Proto32Error("not a CONNECT packet")
    pos = hdr["header_len"]
    if len(data) < pos + 2:
        raise Proto32Error("truncated protocol name")
    (nlen,) = struct.unpack("!H", data[pos:pos + 2])
    pos += 2
    name = data[pos:pos + nlen].decode("ascii")
    pos += nlen
    if name != "MQTT":
        raise Proto32Error("bad protocol name " + name)
    level = data[pos]
    pos += 1
    flags = data[pos]
    pos += 1
    (keepalive,) = struct.unpack("!H", data[pos:pos + 2])
    return {"protocol": name, "level": level, "flags": flags,
            "keepalive": keepalive}


def validate_fixed_header(data: bytes) -> tuple:
    """Validate an MQTT fixed header. Returns (ok, reason)."""
    try:
        parse_fixed_header(data)
    except Proto32Error as exc:
        return False, str(exc)
    return True, "valid MQTT header"


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
    body = struct.pack("!H", 4) + b"MQTT" + bytes([4, 0x02]) + struct.pack("!H", 60)
    pkt = bytes([0x10, len(body)]) + body
    c = parse_connect(pkt)
    assert c == {"protocol": "MQTT", "level": 4, "flags": 2, "keepalive": 60}
    ok, _ = validate_fixed_header(bytes([0xF0, 0x00]))
    assert ok is False

    assert stdlib_only()
    print("proto-32 (mqtt): OK")


if __name__ == "__main__":
    main()
