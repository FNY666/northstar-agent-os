"""Mock PKCS#7 envelope parser: 'PKCS7:<oid>:<base64>'.

What this IS: parser/validator for PKCS#7 (mock).
Mock/simulation for agent-runtime gates -- not a full implementation.

What this IS NOT:
* Not a complete PKCS#7 (mock) implementation.
* Host enforces real protocol behavior; this validates structure.
"""

from __future__ import annotations

import base64
import re

#: Module version.
PROTO_14_VERSION = "proto-14-pkcs7.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.proto-14-pkcs7.v1"


class Proto14Error(Exception):
    """Fail-closed."""


_PKCS7_OIDS = {
    "1.2.840.113549.1.7.1": "data",
    "1.2.840.113549.1.7.2": "signedData",
    "1.2.840.113549.1.7.3": "envelopedData",
    "1.2.840.113549.1.7.6": "encryptedData",
}


def parse_pkcs7(text: str) -> dict:
    """Parse mock PKCS#7 envelope. Mock: no crypto validation."""
    m = re.fullmatch(r"PKCS7:([0-9.]+):([A-Za-z0-9+/=]+)", text.strip())
    if not m:
        raise Proto14Error("bad PKCS7 envelope")
    oid, b64 = m.groups()
    if oid not in _PKCS7_OIDS:
        raise Proto14Error("unknown content type OID " + oid)
    try:
        der = base64.b64decode(b64)
    except (base64.binascii.Error, ValueError) as exc:
        raise Proto14Error("bad base64: %s" % exc)
    return {"content_type": _PKCS7_OIDS[oid], "oid": oid, "der": der}


def validate_pkcs7(text: str) -> tuple:
    """Validate mock PKCS#7. Returns (ok, reason)."""
    try:
        parse_pkcs7(text)
    except Proto14Error as exc:
        return False, str(exc)
    return True, "valid mock PKCS7"


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import ast
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "base64", "pathlib", "re", "typing"}
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
    body = base64.b64encode(b"der").decode()
    env = parse_pkcs7("PKCS7:1.2.840.113549.1.7.2:" + body)
    assert env["content_type"] == "signedData" and env["der"] == b"der"
    ok, _ = validate_pkcs7("PKCS7:9.9.9:" + body)
    assert ok is False

    assert stdlib_only()
    print("proto-14 (pkcs7): OK")


if __name__ == "__main__":
    main()
