"""Mock DHCP parser: fixed header fields, magic cookie, options TLV.

What this IS: parser/validator for DHCP (mock).
Mock/simulation for agent-runtime gates -- not a full implementation.

What this IS NOT:
* Not a complete DHCP (mock) implementation.
* Host enforces real protocol behavior; this validates structure.
"""

from __future__ import annotations

import struct

#: Module version.
PROTO_19_VERSION = "proto-19-dhcp.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.proto-19-dhcp.v1"


class Proto19Error(Exception):
    """Fail-closed."""


_COOKIE = b"\x63\x82\x53\x63"

_MSG_TYPES = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE",
              5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM"}


def parse_dhcp(data: bytes) -> dict:
    """Parse a mock DHCP packet. Raises Proto19Error."""
    if len(data) < 240:
        raise Proto19Error("DHCP packet must be >= 240 bytes")
    op, htype, hlen, hops, xid = struct.unpack("!BBBBI", data[:8])
    chaddr = data[28:44]
    if data[236:240] != _COOKIE:
        raise Proto19Error("missing DHCP magic cookie")
    options = {}
    pos = 240
    while pos < len(data):
        code = data[pos]
        pos += 1
        if code == 255:
            break
        if code == 0:
            continue
        if pos >= len(data):
            raise Proto19Error("truncated option")
        ln = data[pos]
        pos += 1
        options[code] = data[pos:pos + ln]
        pos += ln
    return {"op": op, "htype": htype, "hlen": hlen, "hops": hops,
            "xid": xid, "chaddr": chaddr.hex(),
            "options": {k: v.hex() for k, v in options.items()}}


def dhcp_message_type(data: bytes):
    """Return the DHCP message type name (option 53), or None."""
    options = parse_dhcp(data)["options"]
    if 53 in options:
        code = int(options[53], 16)
        return _MSG_TYPES.get(code, "UNKNOWN(%d)" % code)
    return None


def validate_dhcp(data: bytes) -> tuple:
    """Validate a mock DHCP packet. Returns (ok, reason)."""
    try:
        parse_dhcp(data)
    except Proto19Error as exc:
        return False, str(exc)
    return True, "valid mock DHCP"


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
    pkt = (struct.pack("!BBBBI", 1, 1, 6, 0, 0x3903F326) + bytes(228)
           + b"\x63\x82\x53\x63" + bytes([53, 1, 1, 255]))
    parsed = parse_dhcp(pkt)
    assert parsed["op"] == 1 and parsed["xid"] == 0x3903F326
    assert dhcp_message_type(pkt) == "DISCOVER"
    ok, _ = validate_dhcp(b"\x00" * 240)
    assert ok is False

    assert stdlib_only()
    print("proto-19 (dhcp): OK")


if __name__ == "__main__":
    main()
