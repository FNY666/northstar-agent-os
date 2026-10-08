"""Mock NTP parser: 48-byte packet via struct, version check.

What this IS: parser/validator for NTP (mock).
Mock/simulation for agent-runtime gates -- not a full implementation.

What this IS NOT:
* Not a complete NTP (mock) implementation.
* Host enforces real protocol behavior; this validates structure.
"""

from __future__ import annotations

import struct

#: Module version.
PROTO_20_VERSION = "proto-20-ntp.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.proto-20-ntp.v1"


class Proto20Error(Exception):
    """Fail-closed."""


def parse_ntp(data: bytes) -> dict:
    """Parse a 48-byte NTP packet. Raises Proto20Error."""
    if len(data) != 48:
        raise Proto20Error("NTP packet must be 48 bytes, got %d" % len(data))
    (b0, stratum, poll, precision, _delay, _disp, _refid,
     _refts, _origts, _recvts, txts) = struct.unpack("!BBbbIIIQQQQ", data)
    version = (b0 >> 3) & 0x07
    mode = b0 & 0x07
    if version not in (3, 4):
        raise Proto20Error("bad NTP version %d" % version)
    return {"version": version, "mode": mode, "stratum": stratum,
            "poll": poll, "precision": precision, "tx_timestamp": txts}


def validate_ntp(data: bytes) -> tuple:
    """Validate an NTP packet. Returns (ok, reason)."""
    try:
        parse_ntp(data)
    except Proto20Error as exc:
        return False, str(exc)
    return True, "valid NTP packet"


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
    pkt = struct.pack("!BBbbIIIQQQQ", 0x23, 2, 6, -20, 0, 0, 0, 0, 0, 0, 0x1234)
    parsed = parse_ntp(pkt)
    assert parsed["version"] == 4 and parsed["mode"] == 3
    assert parsed["stratum"] == 2 and parsed["tx_timestamp"] == 0x1234
    ok, _ = validate_ntp(b"\x00" * 47)
    assert ok is False

    assert stdlib_only()
    print("proto-20 (ntp): OK")


if __name__ == "__main__":
    main()
