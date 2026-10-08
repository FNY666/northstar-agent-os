"""WebSocket exfiltration detection (websocket-exfil), Simulated.

Detects data exfiltration over WebSocket. Flags bursts of large binary messages and excessive total transfer volume.

What this IS: a WebSocket traffic shape detector.

What this IS NOT:
* Not a WS proxy -- inspects provided message metadata.
* Cannot inspect encrypted (wss) payloads.
"""

from __future__ import annotations

import ast
from typing import Any, Dict, List


#: Module version.
EXFIL_04_VERSION = "exfil-04.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.exfil-04.v1"


class Exfil04Error(Exception):
    """Fail-closed."""


def detect_ws_exfil(messages: List[Dict[str, Any]]) -> tuple:
    """Detect WS exfiltration. messages: [{opcode, size}]. Returns (suspicious, reason)."""
    if not isinstance(messages, list):
        raise Exfil04Error("messages must be list")
    if len(messages) < 10:
        return False, "insufficient messages"
    large_binary = [
        x for x in messages
        if x.get("opcode") == 2 and x.get("size", 0) > 16384
    ]
    if len(large_binary) >= 5:
        return True, "%d large binary messages" % len(large_binary)
    total = sum(x.get("size", 0) for x in messages)
    if total > 10 * 1024 * 1024:
        return True, "total %d bytes exceeds 10MB" % total
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
    msgs = [{"opcode": 1, "size": 100}] * 12
    ok, _ = detect_ws_exfil(msgs)
    assert ok is False
    msgs = [{"opcode": 2, "size": 20000}] * 12
    ok, _ = detect_ws_exfil(msgs)
    assert ok is True
    assert stdlib_only()
    print("exfil-04 OK: websocket shapes, fail-closed")


if __name__ == "__main__":
    main()
