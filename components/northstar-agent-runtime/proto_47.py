"""Mock CBOR parser: major types 0/1/3/4/5, small arguments.

What this IS: parser/validator for CBOR (mock).
Mock/simulation for agent-runtime gates -- not a full implementation.

What this IS NOT:
* Not a complete CBOR (mock) implementation.
* Host enforces real protocol behavior; this validates structure.
"""

from __future__ import annotations



#: Module version.
PROTO_47_VERSION = "proto-47-cbor.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.proto-47-cbor.v1"


class Proto47Error(Exception):
    """Fail-closed."""


def parse_cbor(data: bytes, pos: int = 0):
    """Parse one CBOR value. Returns (value, new_pos)."""
    if pos >= len(data):
        raise Proto47Error("truncated")
    ib = data[pos]
    major = ib >> 5
    ai = ib & 0x1F
    pos += 1

    def arg():
        nonlocal pos
        if ai < 24:
            return ai
        if ai == 24:
            if pos >= len(data):
                raise Proto47Error("truncated arg")
            v = data[pos]
            pos += 1
            return v
        if ai == 25:
            if pos + 2 > len(data):
                raise Proto47Error("truncated arg")
            v = int.from_bytes(data[pos:pos + 2], "big")
            pos += 2
            return v
        if ai == 26:
            if pos + 4 > len(data):
                raise Proto47Error("truncated arg")
            v = int.from_bytes(data[pos:pos + 4], "big")
            pos += 4
            return v
        raise Proto47Error("unsupported additional info %d" % ai)

    if major == 0:
        return arg(), pos
    if major == 1:
        return -1 - arg(), pos
    if major == 3:
        n = arg()
        if pos + n > len(data):
            raise Proto47Error("truncated text")
        return data[pos:pos + n].decode("utf-8", "replace"), pos + n
    if major == 4:
        n = arg()
        items = []
        for _ in range(n):
            v, pos = parse_cbor(data, pos)
            items.append(v)
        return items, pos
    if major == 5:
        n = arg()
        d = {}
        for _ in range(n):
            k, pos = parse_cbor(data, pos)
            v, pos = parse_cbor(data, pos)
            d[k] = v
        return d, pos
    raise Proto47Error("unsupported major type %d" % major)


def validate_cbor(data: bytes) -> tuple:
    """Validate mock CBOR. Returns (ok, reason)."""
    try:
        _, pos = parse_cbor(data, 0)
    except Proto47Error as exc:
        return False, str(exc)
    if pos != len(data):
        return False, "trailing bytes"
    return True, "valid mock CBOR"


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
    assert parse_cbor(bytes([0x18, 0x2A])) == (42, 2)
    assert parse_cbor(bytes([0x20])) == (-1, 1)
    assert parse_cbor(bytes([0x62]) + b"hi") == ("hi", 3)
    assert parse_cbor(bytes([0x82, 0x01, 0x02])) == ([1, 2], 3)
    ok, _ = validate_cbor(bytes([0x1F]))
    assert ok is False

    assert stdlib_only()
    print("proto-47 (cbor): OK")


if __name__ == "__main__":
    main()
