"""Clipboard hijacking detection (mock) (clipboard-mock), Simulated.

Mock detector for clipboard hijacking: programmatic writes without user gesture, and repeated programmatic reads.

What this IS: a mock clipboard event analyzer.

What this IS NOT:
* MOCK: analyzes provided event dicts, no OS hooks.
* Gesture flags are host-provided.
"""

from __future__ import annotations

import ast
from typing import Any, Dict, List


#: Module version.
EXFIL_12_VERSION = "exfil-12.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.exfil-12.v1"


class Exfil12Error(Exception):
    """Fail-closed."""


def detect_clipboard_hijack(events: List[Dict[str, Any]]) -> tuple:
    """Detect clipboard hijacking. events: [{action, user_gesture}]. Returns (suspicious, reason)."""
    if not isinstance(events, list):
        raise Exfil12Error("events must be list")
    for e in events:
        if e.get("action") == "write" and not e.get("user_gesture", False):
            return True, "programmatic clipboard write without gesture"
    reads = [e for e in events if e.get("action") == "read" and not e.get("user_gesture", False)]
    if len(reads) >= 3:
        return True, "%d programmatic clipboard reads" % len(reads)
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
    ok, _ = detect_clipboard_hijack([{"action": "write", "user_gesture": True}])
    assert ok is False
    ok, _ = detect_clipboard_hijack([{"action": "write", "user_gesture": False}])
    assert ok is True
    assert stdlib_only()
    print("exfil-12 OK: mock clipboard, fail-closed")


if __name__ == "__main__":
    main()
