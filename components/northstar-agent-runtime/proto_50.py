"""Ion binary parser: version marker, int/string type descriptors.

What this IS: parser/validator for Ion.
Mock/simulation for agent-runtime gates -- not a full implementation.

What this IS NOT:
* Not a complete Ion implementation.
* Host enforces real protocol behavior; this validates structure.
"""

from __future__ import annotations



#: Module version.
PROTO_50_VERSION = "proto-50-ion.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.proto-50-ion.v1"


class Proto50Error(Exception):
    """Fail-closed."""


_BVM = b"\xe0\x01\x00\xea"


def parse_ion(data: bytes) -> list:
    """Parse Ion binary values after the version marker. Mock subset."""
    if len(data) < 4 or data[:4] != _BVM:
        raise Proto50Error("missing Ion version marker")
    values = []
    pos = 4
    while pos < len(data):
        td = data[pos]
        pos += 1
        itype = td >> 4
        ln = td & 0x0F
        if ln == 14:
            raise Proto50Error("long form length not supported in mock")
        if ln == 15:
            raise Proto50Error("null value not supported in mock")
        if pos + ln > len(data):
            raise Proto50Error("truncated value")
        raw = data[pos:pos + ln]
        pos += ln
        if itype == 2:
            values.append(int.from_bytes(raw, "big", signed=True))
        elif itype == 8:
            values.append(raw.decode("utf-8", "replace"))
        else:
            raise Proto50Error("unsupported Ion type %d" % itype)
    return values


def validate_ion(data: bytes) -> tuple:
    """Validate Ion binary. Returns (ok, reason)."""
    try:
        parse_ion(data)
    except Proto50Error as exc:
        return False, str(exc)
    return True, "valid Ion"


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
    data = b"\xe0\x01\x00\xea" + bytes([0x21, 0x05]) + bytes([0x82]) + b"hi"
    assert parse_ion(data) == [5, "hi"]
    ok, _ = validate_ion(b"\x00\x01\x02\x03")
    assert ok is False

    assert stdlib_only()
    print("proto-50 (ion): OK")


if __name__ == "__main__":
    main()
