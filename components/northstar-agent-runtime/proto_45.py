"""Mock MessagePack parser: fixint/fixstr/fixarray/fixmap/nil/bool/str8.

What this IS: parser/validator for MessagePack (mock).
Mock/simulation for agent-runtime gates -- not a full implementation.

What this IS NOT:
* Not a complete MessagePack (mock) implementation.
* Host enforces real protocol behavior; this validates structure.
"""

from __future__ import annotations



#: Module version.
PROTO_45_VERSION = "proto-45-msgpack.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.proto-45-msgpack.v1"


class Proto45Error(Exception):
    """Fail-closed."""


def parse_msgpack(data: bytes, pos: int = 0):
    """Parse one MessagePack value. Returns (value, new_pos)."""
    if pos >= len(data):
        raise Proto45Error("truncated")
    b = data[pos]
    if b <= 0x7F:
        return b, pos + 1
    if b >= 0xE0:
        return b - 256, pos + 1
    if 0xA0 <= b <= 0xBF:
        n = b & 0x1F
        if pos + 1 + n > len(data):
            raise Proto45Error("truncated fixstr")
        return data[pos + 1:pos + 1 + n].decode("utf-8", "replace"), pos + 1 + n
    if 0x90 <= b <= 0x9F:
        n = b & 0x0F
        items = []
        p = pos + 1
        for _ in range(n):
            v, p = parse_msgpack(data, p)
            items.append(v)
        return items, p
    if 0x80 <= b <= 0x8F:
        n = b & 0x0F
        d = {}
        p = pos + 1
        for _ in range(n):
            k, p = parse_msgpack(data, p)
            v, p = parse_msgpack(data, p)
            d[k] = v
        return d, p
    if b == 0xC0:
        return None, pos + 1
    if b == 0xC2:
        return False, pos + 1
    if b == 0xC3:
        return True, pos + 1
    if b == 0xD9:
        if pos + 1 >= len(data):
            raise Proto45Error("truncated str8")
        n = data[pos + 1]
        if pos + 2 + n > len(data):
            raise Proto45Error("truncated str8")
        return data[pos + 2:pos + 2 + n].decode("utf-8", "replace"), pos + 2 + n
    raise Proto45Error("unsupported format byte 0x%02X" % b)


def validate_msgpack(data: bytes) -> tuple:
    """Validate mock MessagePack. Returns (ok, reason)."""
    try:
        _, pos = parse_msgpack(data, 0)
    except Proto45Error as exc:
        return False, str(exc)
    if pos != len(data):
        return False, "trailing bytes"
    return True, "valid mock MessagePack"


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
    assert parse_msgpack(bytes([0x2A])) == (42, 1)
    assert parse_msgpack(bytes([0xA3]) + b"hey") == ("hey", 4)
    assert parse_msgpack(bytes([0x92, 0x01, 0xC3])) == ([1, True], 3)
    assert parse_msgpack(bytes([0x81, 0xA1]) + b"k" + bytes([0xC0])) == ({"k": None}, 4)
    ok, _ = validate_msgpack(bytes([0xFF, 0x01]))
    assert ok is False

    assert stdlib_only()
    print("proto-45 (msgpack): OK")


if __name__ == "__main__":
    main()
