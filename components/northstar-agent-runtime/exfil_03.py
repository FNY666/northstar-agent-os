"""HTTP header smuggling detection (http-header-smuggle), Simulated.

Detects sensitive data smuggled in HTTP headers. Flags credentials in custom headers, CRLF injection, duplicate and oversized headers.

What this IS: an HTTP header content inspector.

What this IS NOT:
* Not an HTTP client -- inspects provided header dicts.
* Allowlisted auth headers (Authorization, Cookie) are not flagged.
"""

from __future__ import annotations

import ast
from typing import Any, Dict, List
import re

#: Module version.
EXFIL_03_VERSION = "exfil-03.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.exfil-03.v1"


class Exfil03Error(Exception):
    """Fail-closed."""


_SENSITIVE = re.compile(
    r"(api[_-]?key|secret|token|password|passwd|\bssn\b|credit[_-]?card)",
    re.IGNORECASE,
)
_ALLOWLIST = {"authorization", "cookie", "set-cookie", "proxy-authorization"}


def detect_header_smuggling(headers: Dict[str, str]) -> tuple:
    """Detect header smuggling. Returns (suspicious, reason)."""
    if not isinstance(headers, dict):
        raise Exfil03Error("headers must be dict")
    seen = set()
    for name, value in headers.items():
        lname = name.lower()
        if lname in seen:
            return True, "duplicate header: %s" % name
        seen.add(lname)
        if not isinstance(value, str):
            continue
        if "\r" in value or "\n" in value:
            return True, "CRLF in header %s" % name
        if len(value) > 4096:
            return True, "oversized header %s: %d" % (name, len(value))
        if lname not in _ALLOWLIST and _SENSITIVE.search(value):
            return True, "sensitive data in header %s" % name
    return False, "ok"

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "typing", "re"}
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
    ok, _ = detect_header_smuggling({"Content-Type": "text/html"})
    assert ok is False
    ok, _ = detect_header_smuggling({"X-Data": "api_key=sk-abc123"})
    assert ok is True
    ok, _ = detect_header_smuggling({"X-A": "a\r\nB: b"})
    assert ok is True
    assert stdlib_only()
    print("exfil-03 OK: header smuggling, fail-closed")


if __name__ == "__main__":
    main()
