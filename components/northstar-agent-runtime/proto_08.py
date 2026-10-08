"""HTTP start-line + header block parser/validator.

What this IS: parser/validator for HTTP headers.
Mock/simulation for agent-runtime gates -- not a full implementation.

What this IS NOT:
* Not a complete HTTP headers implementation.
* Host enforces real protocol behavior; this validates structure.
"""

from __future__ import annotations

import re

#: Module version.
PROTO_08_VERSION = "proto-08-http-headers.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.proto-08-http-headers.v1"


class Proto08Error(Exception):
    """Fail-closed."""


def parse_http_message(text: str) -> dict:
    """Parse an HTTP start-line + headers (+ optional body). Raises Proto08Error."""
    head, sep, body = text.partition("\r\n\r\n")
    if not sep:
        head, _, body = text.partition("\n\n")
    lines = head.replace("\r\n", "\n").split("\n")
    if not lines or not lines[0].strip():
        raise Proto08Error("empty start line")
    start = lines[0].strip()
    headers = {}
    for lineno, line in enumerate(lines[1:], 2):
        if not line.strip():
            continue
        if ":" not in line:
            raise Proto08Error("line %d: bad header" % lineno)
        name, _, value = line.partition(":")
        headers[name.strip().lower()] = value.strip()
    kind = "response" if start.upper().startswith("HTTP/") else "request"
    return {"kind": kind, "start_line": start, "headers": headers, "body": body}


def validate_headers(headers: dict, required=None) -> tuple:
    """Validate a header dict; optionally require names. Returns (ok, reason)."""
    if required:
        missing = [h for h in required if h.lower() not in headers]
        if missing:
            return False, "missing headers: " + ",".join(missing)
    return True, "headers ok"


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import ast
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "re", "typing"}
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
    msg = parse_http_message("GET /x HTTP/1.1\r\nHost: a.com\r\nX-A: 1\r\n\r\nbody")
    assert msg["kind"] == "request"
    assert msg["headers"] == {"host": "a.com", "x-a": "1"}
    assert msg["body"] == "body"
    resp = parse_http_message("HTTP/1.1 200 OK\nContent-Type: t\n\n")
    assert resp["kind"] == "response"

    assert stdlib_only()
    print("proto-08 (http-headers): OK")


if __name__ == "__main__":
    main()
