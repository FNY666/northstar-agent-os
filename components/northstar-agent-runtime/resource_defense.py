"""Resource exhaustion defense: recursion/input bombs, Simulated.

Detects:
- Nested expansion: expand(expand(expand(...)))
- Repeated patterns: same function called excessively
- Oversized inputs: payload exceeds limits

What this IS: DoS prevention at the gate layer.

What this IS NOT:
* Not a full resource limiter -- just detection.
* Host enforces actual limits (timeouts, memory caps).
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import Any, Dict

#: Module version.
RESOURCE_DEFENSE_VERSION = "resource-defense.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.resource-defense.v1"


class ResourceDefenseError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class ResourceLimits:
    """Resource limits for a tool call."""

    max_nesting_depth: int = 5
    max_repeated_calls: int = 10
    max_payload_bytes: int = 100000


def check_nesting(
    text: str, max_depth: int
) -> tuple[bool, str]:
    """Check for excessive nesting depth."""
    depth = 0
    max_seen = 0
    for ch in text:
        if ch == "(":
            depth += 1
            max_seen = max(max_seen, depth)
        elif ch == ")":
            depth = max(0, depth - 1)
    if max_seen > max_depth:
        return False, f"nesting depth {max_seen} > {max_depth}"
    return True, "ok"


def check_repetition(
    text: str, max_repeated: int
) -> tuple[bool, str]:
    """Check for excessive repeated function calls."""
    # Find all function call names.
    calls = re.findall(r"(\w+)\(", text)
    if not calls:
        return True, "ok"
    # Count occurrences of each.
    from collections import Counter
    counts = Counter(calls)
    for func, count in counts.items():
        if count > max_repeated:
            return False, f"'{func}' repeated {count}x > {max_repeated}"
    return True, "ok"


def check_size(
    payload: Dict[str, Any], max_bytes: int
) -> tuple[bool, str]:
    """Check payload size."""
    import json
    size = len(json.dumps(payload).encode())
    if size > max_bytes:
        return False, f"payload {size} > {max_bytes} bytes"
    return True, "ok"


def check_resources(
    tool_name: str,
    args: Dict[str, Any],
    limits: ResourceLimits = None,
) -> tuple[bool, str]:
    """Check all resource limits. Returns (ok, reason)."""
    if limits is None:
        limits = ResourceLimits()
    text = str(args)
    # Nesting.
    ok, reason = check_nesting(text, limits.max_nesting_depth)
    if not ok:
        return False, reason
    # Repetition.
    ok, reason = check_repetition(text, limits.max_repeated_calls)
    if not ok:
        return False, reason
    # Size.
    ok, reason = check_size(args, limits.max_payload_bytes)
    if not ok:
        return False, reason
    return True, "resources ok"


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "collections", "dataclasses", "json", "pathlib", "re", "typing"}
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
    # Recursion bomb.
    ok, reason = check_resources(
        "expand", {"input": "expand(expand(expand(expand(expand(expand(x))))))"}
    )
    assert ok is False
    assert "nesting" in reason

    # Normal.
    ok, _ = check_resources("read", {"path": "/tmp/x"})
    assert ok is True

    # Repetition.
    ok, reason = check_resources(
        "call", {"cmd": "a(" * 15}
    )
    assert ok is False

    assert stdlib_only()
    print("resource-defense OK: nesting, repetition, size, stdlib")


if __name__ == "__main__":
    main()
