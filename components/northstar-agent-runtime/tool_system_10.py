"""Tool idempotency: idempotency keys, Simulated.

Each call carries an idempotency key.  If the same key is seen again,
the recorded result is returned instead of re-executing.  Prevents
double-execution on retries.

What this IS: exactly-once effect for retryable calls.

What this IS NOT:
* Keys are caller-provided -- duplicates with different keys re-execute.
* In-memory store; production needs durable storage.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

#: Module version.
TOOL_SYSTEM_10_VERSION = "tool-system-10.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.tool-system-10.v1"


class ToolSystem10Error(Exception):
    """Fail-closed."""


@dataclass
class _Record:
    status: str  # "in_progress" | "completed" | "failed"
    result: Any = None
    error: Optional[str] = None


class IdempotencyStore:
    """Tracks idempotency keys."""

    def __init__(self) -> None:
        self._records: Dict[str, _Record] = {}

    def execute(self, key: str, fn: Callable[[], Any]) -> Any:
        """Execute fn under idempotency key.  Replays recorded result."""
        if not key:
            raise ToolSystem10Error("idempotency key required")
        existing = self._records.get(key)
        if existing is not None:
            if existing.status == "completed":
                return existing.result
            if existing.status == "failed":
                raise ToolSystem10Error(
                    f"key '{key}' previously failed: {existing.error}"
                )
            # in_progress: another caller is running it -- fail-closed.
            raise ToolSystem10Error(f"key '{key}' already in progress")
        self._records[key] = _Record(status="in_progress")
        try:
            result = fn()
        except Exception as e:
            self._records[key] = _Record(
                status="failed", error=f"{type(e).__name__}: {e}"
            )
            raise
        self._records[key] = _Record(status="completed", result=result)
        return result

    def status(self, key: str) -> Optional[str]:
        rec = self._records.get(key)
        return rec.status if rec else None


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "typing"}
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
    s = IdempotencyStore()
    calls = {"n": 0}

    def charge():
        calls["n"] += 1
        return "charged"

    assert s.execute("key1", charge) == "charged"
    assert s.execute("key1", charge) == "charged"  # replayed
    assert calls["n"] == 1  # executed once
    # Different key re-executes.
    assert s.execute("key2", charge) == "charged"
    assert calls["n"] == 2

    # Failed key replays the failure (no silent retry).
    def boom():
        raise ValueError("bad")

    try:
        s.execute("key3", boom)
        raise AssertionError("should raise")
    except ValueError:
        pass
    try:
        s.execute("key3", charge)
        raise AssertionError("should raise")
    except ToolSystem10Error as e:
        assert "previously failed" in str(e)

    # Empty key rejected.
    try:
        s.execute("", charge)
        raise AssertionError("should raise")
    except ToolSystem10Error:
        pass
    assert stdlib_only()
    print("tool_system_10 OK: replay, failure sticky, key required")


if __name__ == "__main__":
    main()
