"""Mock Avro: zigzag varint long codec, schema JSON, datum validation.

What this IS: parser/validator for Avro (mock).
Mock/simulation for agent-runtime gates -- not a full implementation.

What this IS NOT:
* Not a complete Avro (mock) implementation.
* Host enforces real protocol behavior; this validates structure.
"""

from __future__ import annotations

import json

#: Module version.
PROTO_38_VERSION = "proto-38-avro.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.proto-38-avro.v1"


class Proto38Error(Exception):
    """Fail-closed."""


_PRIMITIVES = {"null", "boolean", "int", "long", "float", "double",
               "bytes", "string"}


def encode_zigzag(n: int) -> bytes:
    """Zigzag-encode a long."""
    v = (n << 1) ^ (n >> 63)
    out = bytearray()
    while v > 0x7F:
        out.append((v & 0x7F) | 0x80)
        v >>= 7
    out.append(v)
    return bytes(out)


def decode_zigzag(data: bytes, pos: int = 0):
    """Decode a zigzag long. Returns (value, new_pos)."""
    v = 0
    shift = 0
    while True:
        if pos >= len(data):
            raise Proto38Error("truncated")
        b = data[pos]
        pos += 1
        v |= (b & 0x7F) << shift
        if not b & 0x80:
            break
        shift += 7
    return (v >> 1) ^ -(v & 1), pos


def parse_schema(text: str) -> dict:
    """Parse an Avro schema JSON (mock subset). Raises Proto38Error."""
    try:
        schema = json.loads(text)
    except ValueError as exc:
        raise Proto38Error("bad schema JSON: %s" % exc)
    stype = schema if isinstance(schema, str) else schema.get("type")
    if stype not in _PRIMITIVES:
        raise Proto38Error("unsupported mock schema type %r" % (stype,))
    return {"type": stype, "raw": schema}


def validate_datum(schema_type: str, value) -> tuple:
    """Validate a datum against a primitive type. Returns (ok, reason)."""
    checks = {
        "null": lambda v: v is None,
        "boolean": lambda v: isinstance(v, bool),
        "int": lambda v: isinstance(v, int) and not isinstance(v, bool) and -(2 ** 31) <= v < 2 ** 31,
        "long": lambda v: isinstance(v, int) and not isinstance(v, bool),
        "string": lambda v: isinstance(v, str),
    }
    fn = checks.get(schema_type)
    if fn is None:
        return False, "unsupported type " + schema_type
    if fn(value):
        return True, "ok"
    return False, "value does not match " + schema_type


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import ast
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "json", "pathlib", "typing"}
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
    assert decode_zigzag(encode_zigzag(-300)) == (-300, len(encode_zigzag(-300)))
    s = parse_schema('"long"')
    assert s["type"] == "long"
    ok, _ = validate_datum("int", 2 ** 40)
    assert ok is False
    ok, _ = validate_datum("string", "hi")
    assert ok is True

    assert stdlib_only()
    print("proto-38 (avro): OK")


if __name__ == "__main__":
    main()
