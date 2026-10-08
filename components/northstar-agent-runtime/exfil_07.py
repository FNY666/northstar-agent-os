"""Error message leakage detection (error-leak), Simulated.

Detects sensitive data leaked via error messages: stack traces, file paths, DB errors, internal IPs, credentials.

What this IS: an error-text leakage scanner.

What this IS NOT:
* Pattern-based; novel leak formats may be missed.
* Does not redact -- only detects.
"""

from __future__ import annotations

import ast
from typing import Any, Dict, List
import re

#: Module version.
EXFIL_07_VERSION = "exfil-07.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.exfil-07.v1"


class Exfil07Error(Exception):
    """Fail-closed."""


_PATTERNS = [
    (r"Traceback \(most recent call last\)", "python traceback"),
    (r'File "[^"]+", line \d+', "file path with line"),
    (r"(SQLException|ORA-\d+|PG::Error|MySQLdb|sqlite3\.)", "database error"),
    (r"/(etc|home|root|var)/[^\s]*", "filesystem path"),
    (r"\b(10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)\b", "internal IP"),
    (r"(?i)(password|passwd|secret)\s*=\s*[^\s]+", "credential in error"),
    (r"\bat\b [\w.$]+\([\w.$]+:\d+\)", "java stack frame"),
]


def detect_error_leakage(text: str) -> tuple:
    """Detect leakage in error text. Returns (leaked, reason)."""
    if not isinstance(text, str):
        raise Exfil07Error("text must be str")
    for pat, label in _PATTERNS:
        if re.search(pat, text):
            return True, "leakage: %s" % label
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
    ok, _ = detect_error_leakage("Something went wrong, try again.")
    assert ok is False
    ok, _ = detect_error_leakage('Traceback (most recent call last):\n  File "app.py", line 10')
    assert ok is True
    ok, _ = detect_error_leakage("ORA-00942: table or view does not exist")
    assert ok is True
    assert stdlib_only()
    print("exfil-07 OK: error leakage, fail-closed")


if __name__ == "__main__":
    main()
