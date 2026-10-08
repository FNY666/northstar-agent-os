"""Mock JWT parser: base64url segments, structure validation (no sig verify).

What this IS: parser/validator for JWT (mock).
Mock/simulation for agent-runtime gates -- not a full implementation.

What this IS NOT:
* Not a complete JWT (mock) implementation.
* Host enforces real protocol behavior; this validates structure.
"""

from __future__ import annotations

import base64
import json

#: Module version.
PROTO_11_VERSION = "proto-11-jwt.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.proto-11-jwt.v1"


class Proto11Error(Exception):
    """Fail-closed."""


def _b64url_decode(segment: str) -> bytes:
    pad = "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(segment + pad)
    except (base64.binascii.Error, ValueError) as exc:
        raise Proto11Error("bad base64url: %s" % exc)


def parse_jwt(token: str) -> tuple:
    """Parse a JWT into (header, payload, signature). Mock: no crypto."""
    parts = token.split(".")
    if len(parts) != 3:
        raise Proto11Error("JWT must have 3 segments")
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except ValueError as exc:
        raise Proto11Error("bad JWT JSON: %s" % exc)
    signature = _b64url_decode(parts[2])
    return header, payload, signature


def validate_jwt(token: str, require=("alg", "typ")) -> tuple:
    """Validate JWT structure. Mock: does NOT verify the signature."""
    try:
        header, _, signature = parse_jwt(token)
    except Proto11Error as exc:
        return False, str(exc)
    missing = [k for k in require if k not in header]
    if missing:
        return False, "header missing: " + ",".join(missing)
    if not signature:
        return False, "empty signature"
    return True, "valid JWT structure (signature NOT verified)"


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import ast
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "base64", "json", "pathlib", "typing"}
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
    def seg(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()
    sig = base64.urlsafe_b64encode(b"sig").rstrip(b"=").decode()
    token = seg({"alg": "HS256", "typ": "JWT"}) + "." + seg({"sub": "1"}) + "." + sig
    header, payload, signature = parse_jwt(token)
    assert header["alg"] == "HS256" and payload["sub"] == "1" and signature == b"sig"
    ok, _ = validate_jwt("a.b")
    assert ok is False

    assert stdlib_only()
    print("proto-11 (jwt): OK")


if __name__ == "__main__":
    main()
