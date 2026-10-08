"""Mock DER parser: tag-length-value with short/long form lengths.

What this IS: parser/validator for DER (mock).
Mock/simulation for agent-runtime gates -- not a full implementation.

What this IS NOT:
* Not a complete DER (mock) implementation.
* Host enforces real protocol behavior; this validates structure.
"""

from __future__ import annotations



#: Module version.
PROTO_13_VERSION = "proto-13-der.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.proto-13-der.v1"


class Proto13Error(Exception):
    """Fail-closed."""


_TAG_NAMES = {
    0x02: "INTEGER", 0x03: "BIT STRING", 0x04: "OCTET STRING",
    0x05: "NULL", 0x06: "OBJECT IDENTIFIER", 0x0C: "UTF8String",
    0x13: "PrintableString", 0x16: "IA5String", 0x17: "UTCTime",
    0x18: "GeneralizedTime", 0x30: "SEQUENCE", 0x31: "SET",
}


def parse_der(data: bytes) -> list:
    """Parse DER TLV items at one level. Returns [(tag, value)]."""
    if not isinstance(data, (bytes, bytearray)):
        raise Proto13Error("DER input must be bytes")
    items = []
    pos = 0
    while pos < len(data):
        if pos + 2 > len(data):
            raise Proto13Error("truncated tag/length")
        tag = data[pos]
        pos += 1
        first = data[pos]
        pos += 1
        if first & 0x80 == 0:
            length = first
        else:
            count = first & 0x7F
            if count == 0:
                raise Proto13Error("indefinite length not allowed in DER")
            if pos + count > len(data):
                raise Proto13Error("truncated length bytes")
            length = int.from_bytes(data[pos:pos + count], "big")
            pos += count
        if pos + length > len(data):
            raise Proto13Error("truncated value")
        items.append((tag, bytes(data[pos:pos + length])))
        pos += length
    return items


def der_tag_name(tag: int) -> str:
    """Human name for a DER tag byte."""
    return _TAG_NAMES.get(tag, "UNKNOWN(0x%02X)" % tag)


def validate_der(data: bytes) -> tuple:
    """Validate DER TLV structure. Returns (ok, reason)."""
    try:
        parse_der(data)
    except Proto13Error as exc:
        return False, str(exc)
    return True, "valid DER TLV"


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
    items = parse_der(b"\x02\x01\x05\x30\x03\x02\x01\x09")
    assert items == [(0x02, b"\x05"), (0x30, b"\x02\x01\x09")]
    assert der_tag_name(0x30) == "SEQUENCE"
    ok, _ = validate_der(b"\x02\x05\x05")
    assert ok is False

    assert stdlib_only()
    print("proto-13 (der): OK")


if __name__ == "__main__":
    main()
