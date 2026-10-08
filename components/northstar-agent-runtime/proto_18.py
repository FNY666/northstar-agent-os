"""Mock DNS query parser: 12-byte header + QNAME/QTYPE/QCLASS.

What this IS: parser/validator for DNS (mock).
Mock/simulation for agent-runtime gates -- not a full implementation.

What this IS NOT:
* Not a complete DNS (mock) implementation.
* Host enforces real protocol behavior; this validates structure.
"""

from __future__ import annotations

import struct

#: Module version.
PROTO_18_VERSION = "proto-18-dns.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.proto-18-dns.v1"


class Proto18Error(Exception):
    """Fail-closed."""


def encode_query(qid: int, name: str, qtype: int = 1) -> bytes:
    """Encode a mock DNS query (helper for tests)."""
    header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(
        bytes([len(part)]) + part.encode("ascii") for part in name.split(".")
    ) + b"\x00"
    return header + qname + struct.pack("!HH", qtype, 1)


def parse_query(data: bytes) -> dict:
    """Parse a mock DNS query. Raises Proto18Error."""
    if len(data) < 12:
        raise Proto18Error("too short for DNS header")
    qid, flags, qd, _an, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
    if qd != 1:
        raise Proto18Error("mock parser expects exactly 1 question")
    pos = 12
    labels = []
    while True:
        if pos >= len(data):
            raise Proto18Error("truncated QNAME")
        ln = data[pos]
        pos += 1
        if ln == 0:
            break
        if ln & 0xC0:
            raise Proto18Error("compression not supported in mock")
        if pos + ln > len(data):
            raise Proto18Error("truncated label")
        labels.append(data[pos:pos + ln].decode("ascii", "replace"))
        pos += ln
    if pos + 4 > len(data):
        raise Proto18Error("truncated QTYPE/QCLASS")
    qtype, qclass = struct.unpack("!HH", data[pos:pos + 4])
    return {"id": qid, "flags": flags, "name": ".".join(labels),
            "qtype": qtype, "qclass": qclass}


def validate_query(data: bytes) -> tuple:
    """Validate a mock DNS query. Returns (ok, reason)."""
    try:
        parse_query(data)
    except Proto18Error as exc:
        return False, str(exc)
    return True, "valid mock DNS query"


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
    q = encode_query(0x1234, "example.com")
    parsed = parse_query(q)
    assert parsed["id"] == 0x1234 and parsed["name"] == "example.com"
    assert parsed["qtype"] == 1 and parsed["qclass"] == 1
    ok, _ = validate_query(b"short")
    assert ok is False

    assert stdlib_only()
    print("proto-18 (dns): OK")


if __name__ == "__main__":
    main()
