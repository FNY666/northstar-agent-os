"""Autocomplete leakage detection (autocomplete-leak), Simulated.

Detects autocomplete suggestions that reveal PII (SSN, email, phone) beyond what the user typed.

What this IS: an autocomplete suggestion PII checker.

What this IS NOT:
* Cannot know whose PII it is -- flags any PII beyond the prefix.
* Needs the user prefix for comparison.
"""

from __future__ import annotations

import ast
from typing import Any, Dict, List
import re

#: Module version.
EXFIL_11_VERSION = "exfil-11.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.exfil-11.v1"


class Exfil11Error(Exception):
    """Fail-closed."""


_PATTERNS = [
    (r"\b\d{3}-\d{2}-\d{4}\b", "SSN"),
    (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "email"),
    (r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b", "phone"),
]


def detect_autocomplete_leak(suggestion: str, user_prefix: str) -> tuple:
    """Detect PII leaked via autocomplete. Returns (leaked, reason)."""
    if not isinstance(suggestion, str) or not isinstance(user_prefix, str):
        raise Exfil11Error("bad types")
    extra = suggestion[len(user_prefix):] if user_prefix and suggestion.startswith(user_prefix) else suggestion
    for pat, label in _PATTERNS:
        for found in re.findall(pat, extra):
            if found not in user_prefix:
                return True, "autocomplete leaks %s" % label
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
    ok, _ = detect_autocomplete_leak("john smi", "john smi")
    assert ok is False
    ok, _ = detect_autocomplete_leak("john 555-123-4567", "john ")
    assert ok is True
    assert stdlib_only()
    print("exfil-11 OK: autocomplete leak, fail-closed")


if __name__ == "__main__":
    main()
