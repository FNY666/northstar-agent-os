"""Mock OCSP request/response parser: serial query, good/revoked/unknown.

What this IS: parser/validator for OCSP (mock).
Mock/simulation for agent-runtime gates -- not a full implementation.

What this IS NOT:
* Not a complete OCSP (mock) implementation.
* Host enforces real protocol behavior; this validates structure.
"""

from __future__ import annotations



#: Module version.
PROTO_17_VERSION = "proto-17-ocsp.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.proto-17-ocsp.v1"


class Proto17Error(Exception):
    """Fail-closed."""


_STATUSES = ("good", "revoked", "unknown")


def parse_ocsp_request(text: str) -> dict:
    """Parse a mock OCSP request. Mock: not real OCSP."""
    lines = [ln.strip() for ln in text.strip().splitlines() if ln.strip()]
    if not lines or lines[0] != "OCSP-REQ":
        raise Proto17Error("must start with OCSP-REQ")
    req = {}
    for line in lines[1:]:
        if ":" not in line:
            raise Proto17Error("bad line: " + line)
        k, _, v = line.partition(":")
        req[k.strip()] = v.strip()
    if "serial" not in req:
        raise Proto17Error("missing serial")
    return req


def parse_ocsp_response(text: str) -> dict:
    """Parse a mock OCSP response. Mock: not real OCSP."""
    lines = [ln.strip() for ln in text.strip().splitlines() if ln.strip()]
    if not lines or lines[0] != "OCSP-RESP":
        raise Proto17Error("must start with OCSP-RESP")
    resp = {}
    for line in lines[1:]:
        if ":" not in line:
            raise Proto17Error("bad line: " + line)
        k, _, v = line.partition(":")
        resp[k.strip()] = v.strip()
    if resp.get("status") not in _STATUSES:
        raise Proto17Error("bad status, want one of %s" % ",".join(_STATUSES))
    return resp


def validate_ocsp_response(text: str) -> tuple:
    """Validate mock OCSP response. Returns (ok, reason)."""
    try:
        resp = parse_ocsp_response(text)
    except Proto17Error as exc:
        return False, str(exc)
    if resp["status"] != "good":
        return False, "status is " + resp["status"]
    return True, "OCSP status good"


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
    req = parse_ocsp_request("OCSP-REQ\nserial: 42\n")
    assert req["serial"] == "42"
    resp = parse_ocsp_response("OCSP-RESP\nstatus: good\n")
    assert resp["status"] == "good"
    ok, _ = validate_ocsp_response("OCSP-RESP\nstatus: revoked\n")
    assert ok is False

    assert stdlib_only()
    print("proto-17 (ocsp): OK")


if __name__ == "__main__":
    main()
