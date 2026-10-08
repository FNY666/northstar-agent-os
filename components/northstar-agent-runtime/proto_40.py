"""Mock ORC parser: trailing ORC magic, postscript length byte.

What this IS: parser/validator for ORC (mock).
Mock/simulation for agent-runtime gates -- not a full implementation.

What this IS NOT:
* Not a complete ORC (mock) implementation.
* Host enforces real protocol behavior; this validates structure.
"""

from __future__ import annotations



#: Module version.
PROTO_40_VERSION = "proto-40-orc.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.proto-40-orc.v1"


class Proto40Error(Exception):
    """Fail-closed."""


def parse_orc(data: bytes) -> dict:
    """Parse mock ORC framing. Raises Proto40Error."""
    if len(data) < 4:
        raise Proto40Error("too short")
    if data[-3:] != b"ORC":
        raise Proto40Error("missing ORC magic")
    ps_len = data[-4]
    if ps_len > len(data) - 4:
        raise Proto40Error("postscript length out of range")
    start = len(data) - 4 - ps_len
    return {"postscript_len": ps_len, "postscript": data[start:len(data) - 4]}


def validate_orc(data: bytes) -> tuple:
    """Validate mock ORC framing. Returns (ok, reason)."""
    try:
        parse_orc(data)
    except Proto40Error as exc:
        return False, str(exc)
    return True, "valid mock ORC"


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
    data = b"\x00" * 20 + b"PS" + bytes([2]) + b"ORC"
    p = parse_orc(data)
    assert p["postscript"] == b"PS"
    ok, _ = validate_orc(b"\x00" * 10)
    assert ok is False

    assert stdlib_only()
    print("proto-40 (orc): OK")


if __name__ == "__main__":
    main()
