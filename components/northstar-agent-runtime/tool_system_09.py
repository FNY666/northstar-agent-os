"""Tool caching: memoize results, Simulated.

Cache tool results keyed by (tool, canonical args).  Optional TTL.
Cache hits avoid re-execution.  Explicit invalidation supported.

What this IS: result memoization for pure-ish tools.

What this IS NOT:
* Only safe for deterministic tools -- caller decides.
* No size eviction except max_entries LRU-ish (insertion order).
"""

from __future__ import annotations

import ast
import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional, Tuple

#: Module version.
TOOL_SYSTEM_09_VERSION = "tool-system-09.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.tool-system-09.v1"


class ToolSystem09Error(Exception):
    """Fail-closed."""


@dataclass
class _Entry:
    value: Any
    expires_at: Optional[float]


class ToolCache:
    """Memoizing cache for tool results."""

    def __init__(self, max_entries: int = 1024) -> None:
        if max_entries <= 0:
            raise ToolSystem09Error("max_entries must be positive")
        self._store: Dict[str, _Entry] = {}
        self._max = max_entries
        self.hits = 0
        self.misses = 0

    @staticmethod
    def _key(tool: str, args: Dict[str, Any]) -> str:
        canonical = json.dumps(
            {"tool": tool, "args": args}, sort_keys=True, separators=(",", ":")
        )
        return hashlib.sha256(canonical.encode()).hexdigest()

    def get(self, tool: str, args: Dict[str, Any]) -> Tuple[bool, Any]:
        """Returns (hit, value)."""
        key = self._key(tool, args)
        entry = self._store.get(key)
        if entry is None:
            self.misses += 1
            return False, None
        if entry.expires_at is not None and time.time() > entry.expires_at:
            del self._store[key]
            self.misses += 1
            return False, None
        self.hits += 1
        return True, entry.value

    def put(
        self, tool: str, args: Dict[str, Any], value: Any,
        ttl: Optional[float] = None,
    ) -> None:
        if len(self._store) >= self._max:
            # Evict oldest (insertion order).
            oldest = next(iter(self._store))
            del self._store[oldest]
        key = self._key(tool, args)
        expires = time.time() + ttl if ttl else None
        self._store[key] = _Entry(value, expires)

    def invalidate(self, tool: str, args: Dict[str, Any]) -> bool:
        key = self._key(tool, args)
        return self._store.pop(key, None) is not None

    def clear(self) -> None:
        self._store.clear()


def cached_call(
    cache: ToolCache,
    tool: str,
    args: Dict[str, Any],
    fn: Callable[[], Any],
    ttl: Optional[float] = None,
) -> Any:
    """Call fn or return cached result."""
    hit, value = cache.get(tool, args)
    if hit:
        return value
    value = fn()
    cache.put(tool, args, value, ttl=ttl)
    return value


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {
        "__future__", "ast", "dataclasses", "hashlib",
        "json", "pathlib", "time", "typing",
    }
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
    c = ToolCache()
    calls = {"n": 0}

    def expensive():
        calls["n"] += 1
        return "result"

    assert cached_call(c, "t", {"a": 1}, expensive) == "result"
    assert cached_call(c, "t", {"a": 1}, expensive) == "result"
    assert calls["n"] == 1  # second was a cache hit
    assert c.hits == 1 and c.misses == 1
    # Different args miss.
    assert cached_call(c, "t", {"a": 2}, expensive) == "result"
    assert calls["n"] == 2
    # Invalidate.
    assert c.invalidate("t", {"a": 1}) is True
    assert cached_call(c, "t", {"a": 1}, expensive) == "result"
    assert calls["n"] == 3
    assert stdlib_only()
    print("tool_system_09 OK: memoize, TTL-free, invalidate")


if __name__ == "__main__":
    main()
