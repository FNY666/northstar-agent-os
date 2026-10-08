"""Search query exfiltration detection (search-exfil), Simulated.

Detects sensitive data typed into search boxes: SSNs, API keys, emails, card-like numbers, password keywords.

What this IS: a search-query PII scanner.

What this IS NOT:
* Pattern-based; obfuscated data may pass.
* Does not block -- only detects.
"""

from __future__ import annotations

import ast
from typing import Any, Dict, List
import re

#: Module version.
EXFIL_10_VERSION = "exfil-10.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.exfil-10.v1"


class Exfil10Error(Exception):
    """Fail-closed."""


_PATTERNS = [
    (r"\b\d{3}-\d{2}-\d{4}\b", "SSN"),
    (r"\bsk-[A-Za-z0-9]{16,}\b", "API key"),
    (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "email"),
    (r"\b(?:\d[ -]*?){13,16}\b", "card-like number"),
    (r"(?i)\bpassword\b", "password keyword"),
]


def detect_search_exfil(query: str) -> tuple:
    """Detect sensitive data in search query. Returns (suspicious, reason)."""
    if not isinstance(query, str):
        raise Exfil10Error("query must be str")
    for pat, label in _PATTERNS:
        if re.search(pat, query):
            return True, "sensitive in search: %s" % label
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
    ok, _ = detect_search_exfil("best pizza near me")
    assert ok is False
    ok, _ = detect_search_exfil("my ssn 123-45-6789 lookup")
    assert ok is True
    ok, _ = detect_search_exfil("sk-abcdefghijklmnopqrst")
    assert ok is True
    assert stdlib_only()
    print("exfil-10 OK: search exfil, fail-closed")


if __name__ == "__main__":
    main()
