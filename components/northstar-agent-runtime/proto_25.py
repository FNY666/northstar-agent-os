"""Mock SSH parser: version exchange line, binary packet header.

What this IS: parser/validator for SSH (mock).
Mock/simulation for agent-runtime gates -- not a full implementation.

What this IS NOT:
* Not a complete SSH (mock) implementation.
* Host enforces real protocol behavior; this validates structure.
"""

from __future__ import annotations

import re
import struct

#: Module version.
PROTO_25_VERSION = "proto-25-ssh.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.proto-25-ssh.v1"


class Proto25Error(Exception):
    """Fail-closed."""


_VERSION_RE = re.compile(r"^SSH-2\.0-(\S+?)(?:\s|$)")


def parse_version_line(line: str) -> dict:
    """Parse the SSH version exchange line. Raises Proto25Error."""
    m = _VERSION_RE.match(line.strip())
    if not m:
        raise Proto25Error("bad SSH version line")
    return {"version": "2.0", "software": m.group(1)}


def parse_binary_packet(data: bytes) -> dict:
    """Parse an SSH binary packet header + payload. Raises Proto25Error."""
    if len(data) < 5:
        raise Proto25Error("too short")
    (packet_length,) = struct.unpack("!I", data[:4])
    if len(data) < 4 + packet_length:
        raise Proto25Error("truncated packet")
    padding_length = data[4]
    payload = data[5:4 + packet_length - padding_length]
    return {"packet_length": packet_length,
            "padding_length": padding_length, "payload": payload}


def validate_binary_packet(data: bytes) -> tuple:
    """Validate an SSH binary packet. Returns (ok, reason)."""
    try:
        parse_binary_packet(data)
    except Proto25Error as exc:
        return False, str(exc)
    return True, "valid SSH packet"


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import ast
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "re", "struct", "typing"}
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
    v = parse_version_line("SSH-2.0-OpenSSH_9.0\r\n")
    assert v == {"version": "2.0", "software": "OpenSSH_9.0"}
    pkt = struct.pack("!I", 13) + bytes([4]) + b"payload!" + bytes(4)
    p = parse_binary_packet(pkt)
    assert p["payload"] == b"payload!" and p["padding_length"] == 4
    ok, _ = validate_binary_packet(b"\x00" * 3)
    assert ok is False

    assert stdlib_only()
    print("proto-25 (ssh): OK")


if __name__ == "__main__":
    main()
