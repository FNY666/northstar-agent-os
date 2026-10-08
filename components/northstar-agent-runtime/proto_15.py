"""Mock X.509 certificate parser: CERT field block with validity dates.

What this IS: parser/validator for X.509 (mock).
Mock/simulation for agent-runtime gates -- not a full implementation.

What this IS NOT:
* Not a complete X.509 (mock) implementation.
* Host enforces real protocol behavior; this validates structure.
"""

from __future__ import annotations

import datetime
import re

#: Module version.
PROTO_15_VERSION = "proto-15-x509.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.proto-15-x509.v1"


class Proto15Error(Exception):
    """Fail-closed."""


_REQUIRED = ("serial", "issuer", "subject", "not_before", "not_after")


def parse_cert(text: str) -> dict:
    """Parse a mock certificate. Mock: not real X.509."""
    lines = [ln.strip() for ln in text.strip().splitlines() if ln.strip()]
    if not lines or lines[0] != "CERT":
        raise Proto15Error("must start with CERT")
    cert = {}
    for line in lines[1:]:
        if ":" not in line:
            raise Proto15Error("bad line: " + line)
        k, _, v = line.partition(":")
        cert[k.strip()] = v.strip()
    for field in _REQUIRED:
        if field not in cert:
            raise Proto15Error("missing field " + field)
    try:
        cert["not_before_dt"] = datetime.date.fromisoformat(cert["not_before"])
        cert["not_after_dt"] = datetime.date.fromisoformat(cert["not_after"])
    except ValueError as exc:
        raise Proto15Error("bad date: %s" % exc)
    if cert["not_after_dt"] <= cert["not_before_dt"]:
        raise Proto15Error("not_after must be after not_before")
    return cert


def validate_cert(text: str, today=None) -> tuple:
    """Validate mock cert incl. validity window. Returns (ok, reason)."""
    try:
        cert = parse_cert(text)
    except Proto15Error as exc:
        return False, str(exc)
    day = today or datetime.date.today()
    if not (cert["not_before_dt"] <= day <= cert["not_after_dt"]):
        return False, "certificate not valid on %s" % day
    return True, "valid mock certificate"


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import ast
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "datetime", "pathlib", "re", "typing"}
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
    text = "CERT\nserial: 1\nissuer: CN=CA\nsubject: CN=x\nnot_before: 2026-01-01\nnot_after: 2027-01-01\n"
    cert = parse_cert(text)
    assert cert["subject"] == "CN=x"
    ok, _ = validate_cert(text, today=datetime.date(2026, 6, 1))
    assert ok is True
    ok, _ = validate_cert(text, today=datetime.date(2028, 1, 1))
    assert ok is False

    assert stdlib_only()
    print("proto-15 (x509): OK")


if __name__ == "__main__":
    main()
