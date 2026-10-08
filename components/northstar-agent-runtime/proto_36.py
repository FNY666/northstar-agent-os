"""Mock gRPC parser: 5-byte length-prefix message framing.

What this IS: parser/validator for gRPC (mock).
Mock/simulation for agent-runtime gates -- not a full implementation.

What this IS NOT:
* Not a complete gRPC (mock) implementation.
* Host enforces real protocol behavior; this validates structure.
"""

from __future__ import annotations

import struct

#: Module version.
PROTO_36_VERSION = "proto-36-grpc.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.proto-36-grpc.v1"


class Proto36Error(Exception):
    """Fail-closed."""


def parse_grpc_message(data: bytes) -> dict:
    """Parse a gRPC length-prefixed message. Raises Proto36Error."""
    if len(data) < 5:
        raise Proto36Error("too short for gRPC prefix")
    compressed = data[0]
    if compressed not in (0, 1):
        raise Proto36Error("bad compressed flag %d" % compressed)
    (length,) = struct.unpack("!I", data[1:5])
    if len(data) < 5 + length:
        raise Proto36Error("truncated message")
    return {"compressed": bool(compressed), "length": length,
            "payload": data[5:5 + length]}


def validate_grpc_message(data: bytes) -> tuple:
    """Validate a gRPC message. Returns (ok, reason)."""
    try:
        parse_grpc_message(data)
    except Proto36Error as exc:
        return False, str(exc)
    return True, "valid gRPC message"


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
    msg = bytes([0]) + struct.pack("!I", 4) + b"data"
    p = parse_grpc_message(msg)
    assert p == {"compressed": False, "length": 4, "payload": b"data"}
    ok, _ = validate_grpc_message(bytes([2]) + struct.pack("!I", 0))
    assert ok is False

    assert stdlib_only()
    print("proto-36 (grpc): OK")


if __name__ == "__main__":
    main()
