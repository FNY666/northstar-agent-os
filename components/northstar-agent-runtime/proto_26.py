"""Mock TLS parser: record header (type/version/length).

What this IS: parser/validator for TLS (mock).
Mock/simulation for agent-runtime gates -- not a full implementation.

What this IS NOT:
* Not a complete TLS (mock) implementation.
* Host enforces real protocol behavior; this validates structure.
"""

from __future__ import annotations

import struct

#: Module version.
PROTO_26_VERSION = "proto-26-tls.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.proto-26-tls.v1"


class Proto26Error(Exception):
    """Fail-closed."""


_CONTENT_TYPES = {20: "change_cipher_spec", 21: "alert",
                  22: "handshake", 23: "application_data"}


def parse_record(data: bytes) -> dict:
    """Parse a TLS record header + fragment. Raises Proto26Error."""
    if len(data) < 5:
        raise Proto26Error("too short for TLS record")
    ctype, major, minor, length = struct.unpack("!BBBH", data[:5])
    if ctype not in _CONTENT_TYPES:
        raise Proto26Error("unknown content type %d" % ctype)
    if len(data) < 5 + length:
        raise Proto26Error("truncated record")
    return {"type": _CONTENT_TYPES[ctype], "version": (major, minor),
            "length": length, "fragment": data[5:5 + length]}


def validate_record(data: bytes) -> tuple:
    """Validate a TLS record. Returns (ok, reason)."""
    try:
        parse_record(data)
    except Proto26Error as exc:
        return False, str(exc)
    return True, "valid TLS record"


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
    rec = struct.pack("!BBBH", 22, 3, 3, 4) + b"data"
    p = parse_record(rec)
    assert p["type"] == "handshake" and p["version"] == (3, 3)
    assert p["fragment"] == b"data"
    ok, _ = validate_record(struct.pack("!BBBH", 99, 3, 3, 0))
    assert ok is False

    assert stdlib_only()
    print("proto-26 (tls): OK")


if __name__ == "__main__":
    main()
