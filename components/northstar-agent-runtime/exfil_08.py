"""Log injection exfiltration detection (log-inject), Simulated.

Detects log injection: newlines/CRLF, ANSI escapes, and null bytes smuggled into log entries to forge lines or hide exfil.

What this IS: a log-entry injection scanner.

What this IS NOT:
* Inspects single entries, not log streams.
* Does not sanitize -- only detects.
"""

from __future__ import annotations

import ast
from typing import Any, Dict, List


#: Module version.
EXFIL_08_VERSION = "exfil-08.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.exfil-08.v1"


class Exfil08Error(Exception):
    """Fail-closed."""


def detect_log_injection(entry: str) -> tuple:
    """Detect log injection. Returns (suspicious, reason)."""
    if not isinstance(entry, str):
        raise Exfil08Error("entry must be str")
    if "\n" in entry or "\r" in entry:
        return True, "newline/CRLF in log entry"
    if "\x1b[" in entry:
        return True, "ANSI escape sequence"
    if "\x00" in entry:
        return True, "null byte"
    return False, "ok"

def stdlib_only() -> bool:
    """AST check: stdlib only."""
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
    ok, _ = detect_log_injection("2024-01-01 INFO user login ok")
    assert ok is False
    ok, _ = detect_log_injection("login ok\n2024-01-01 ERROR fake line")
    assert ok is True
    ok, _ = detect_log_injection("data \x1b[2K hidden")
    assert ok is True
    assert stdlib_only()
    print("exfil-08 OK: log injection, fail-closed")


if __name__ == "__main__":
    main()
