"""Email header injection detection (email-header-inject), Simulated.

Detects CRLF header injection in email headers: injected Bcc/Cc/To/Subject lines smuggled via newline characters.

What this IS: an email header CRLF injection detector.

What this IS NOT:
* Inspects header values only, not the SMTP envelope.
* Does not send mail.
"""

from __future__ import annotations

import ast
from typing import Any, Dict, List
import re

#: Module version.
EXFIL_18_VERSION = "exfil-18.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.exfil-18.v1"


class Exfil18Error(Exception):
    """Fail-closed."""


def detect_email_header_injection(headers: Dict[str, str]) -> tuple:
    """Detect email header injection. Returns (suspicious, reason)."""
    if not isinstance(headers, dict):
        raise Exfil18Error("headers must be dict")
    for name, value in headers.items():
        if not isinstance(value, str):
            continue
        if re.search(r"[\r\n]\s*(bcc|cc|to|subject|from)\s*:", value, re.IGNORECASE):
            return True, "header injection in %s" % name
        if "\r" in value or "\n" in value:
            return True, "CRLF in header %s" % name
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
    ok, _ = detect_email_header_injection({"Subject": "hello"})
    assert ok is False
    ok, _ = detect_email_header_injection({"Subject": "hi\r\nBcc: evil@x.com"})
    assert ok is True
    assert stdlib_only()
    print("exfil-18 OK: email header injection, fail-closed")


if __name__ == "__main__":
    main()
