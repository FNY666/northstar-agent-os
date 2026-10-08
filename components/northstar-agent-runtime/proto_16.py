"""Mock CRL parser: issuer, this_update, revoked serial list.

What this IS: parser/validator for CRL (mock).
Mock/simulation for agent-runtime gates -- not a full implementation.

What this IS NOT:
* Not a complete CRL (mock) implementation.
* Host enforces real protocol behavior; this validates structure.
"""

from __future__ import annotations

import datetime

#: Module version.
PROTO_16_VERSION = "proto-16-crl.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.proto-16-crl.v1"


class Proto16Error(Exception):
    """Fail-closed."""


def parse_crl(text: str) -> dict:
    """Parse a mock CRL. Mock: not real X.509 CRL."""
    lines = [ln.strip() for ln in text.strip().splitlines() if ln.strip()]
    if not lines or lines[0] != "CRL":
        raise Proto16Error("must start with CRL")
    crl = {}
    for line in lines[1:]:
        if ":" not in line:
            raise Proto16Error("bad line: " + line)
        k, _, v = line.partition(":")
        crl[k.strip()] = v.strip()
    for field in ("issuer", "this_update"):
        if field not in crl:
            raise Proto16Error("missing field " + field)
    try:
        crl["this_update_dt"] = datetime.date.fromisoformat(crl["this_update"])
    except ValueError as exc:
        raise Proto16Error("bad date: %s" % exc)
    revoked = crl.get("revoked", "")
    crl["revoked"] = [s.strip() for s in revoked.split(",") if s.strip()]
    return crl


def is_revoked(crl_text: str, serial: str) -> bool:
    """True if serial is on the mock revocation list."""
    return str(serial) in parse_crl(crl_text)["revoked"]


def validate_crl(text: str) -> tuple:
    """Validate mock CRL. Returns (ok, reason)."""
    try:
        parse_crl(text)
    except Proto16Error as exc:
        return False, str(exc)
    return True, "valid mock CRL"


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import ast
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "datetime", "pathlib", "typing"}
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
    text = "CRL\nissuer: CN=CA\nthis_update: 2026-02-01\nrevoked: 1001, 1002\n"
    crl = parse_crl(text)
    assert crl["revoked"] == ["1001", "1002"]
    assert is_revoked(text, "1001") is True
    assert is_revoked(text, "9999") is False

    assert stdlib_only()
    print("proto-16 (crl): OK")


if __name__ == "__main__":
    main()
