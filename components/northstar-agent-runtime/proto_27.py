"""Mock DTLS parser: 13-byte record header with epoch/sequence.

What this IS: parser/validator for DTLS (mock).
Mock/simulation for agent-runtime gates -- not a full implementation.

What this IS NOT:
* Not a complete DTLS (mock) implementation.
* Host enforces real protocol behavior; this validates structure.
"""

from __future__ import annotations

import struct

#: Module version.
PROTO_27_VERSION = "proto-27-dtls.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.proto-27-dtls.v1"


class Proto27Error(Exception):
    """Fail-closed."""


_CONTENT_TYPES = {20: "change_cipher_spec", 21: "alert",
                  22: "handshake", 23: "application_data"}


def parse_dtls_record(data: bytes) -> dict:
    """Parse a DTLS record header + fragment. Raises Proto27Error."""
    if len(data) < 13:
        raise Proto27Error("too short for DTLS record")
    ctype, major, minor, epoch, seq, length = struct.unpack("!BBBH6sH", data[:13])
    if ctype not in _CONTENT_TYPES:
        raise Proto27Error("unknown content type %d" % ctype)
    if len(data) < 13 + length:
        raise Proto27Error("truncated record")
    return {"type": _CONTENT_TYPES[ctype], "version": (major, minor),
            "epoch": epoch, "sequence": int.from_bytes(seq, "big"),
            "length": length, "fragment": data[13:13 + length]}


def validate_dtls_record(data: bytes) -> tuple:
    """Validate a DTLS record. Returns (ok, reason)."""
    try:
        parse_dtls_record(data)
    except Proto27Error as exc:
        return False, str(exc)
    return True, "valid DTLS record"


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
    rec = struct.pack("!BBBH6sH", 22, 254, 253, 1, b"\x00" * 5 + b"\x07", 3) + b"abc"
    p = parse_dtls_record(rec)
    assert p["epoch"] == 1 and p["sequence"] == 7 and p["fragment"] == b"abc"
    ok, _ = validate_dtls_record(b"\x00" * 12)
    assert ok is False

    assert stdlib_only()
    print("proto-27 (dtls): OK")


if __name__ == "__main__":
    main()
