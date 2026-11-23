"""Tool feature flags: boolean flags with rollouts, Simulated.

FeatureFlagStore holds named boolean flags, each optionally with a
rollout percentage below 100%.  evaluate(flag, key) returns the flag
value directly when the rollout is 100%; for partial rollouts the
decision is deterministic per key via a stable hash, so the same
caller always sees the same value.  Flags can be set, overridden,
and listed.

What this IS:
* In-memory boolean feature flags with deterministic partial
  rollouts.

What this IS NOT:
* Not a remote config service -- no syncing, no targeting rules.
* Not per-user targeting -- rollout is hash-based, not identity
  aware.
"""

from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass
from typing import Dict, List, Optional

#: Module version.
TOOL_SYSTEM_20_VERSION = "tool-system-20.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.tool-system-20.v1"


class ToolSystem20Error(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class Flag:
    name: str
    enabled: bool
    rollout_pct: float = 100.0


class FeatureFlagStore:
    """Boolean feature flags with deterministic rollouts."""

    def __init__(self) -> None:
        self._flags: Dict[str, Flag] = {}

    def set(
        self,
        name: str,
        enabled: bool,
        rollout_pct: float = 100.0,
    ) -> None:
        """Set or override a flag."""
        if not name:
            raise ToolSystem20Error("name required")
        if not 0.0 <= rollout_pct <= 100.0:
            raise ToolSystem20Error("rollout_pct must be in [0, 100]")
        self._flags[name] = Flag(
            name=name, enabled=bool(enabled), rollout_pct=rollout_pct
        )

    def remove(self, name: str) -> None:
        """Remove a flag; unknown names are a no-op."""
        self._flags.pop(name, None)

    def evaluate(self, name: str, key: Optional[str] = None) -> bool:
        """Evaluate a flag for an optional caller key.

        Raises for unknown flags (fail-closed).  A disabled flag or
        0% rollout is always False; 100% rollout follows `enabled`.
        Partial rollouts hash name+key deterministically.
        """
        if name not in self._flags:
            raise ToolSystem20Error(f"unknown flag '{name}'")
        flag = self._flags[name]
        if not flag.enabled or flag.rollout_pct <= 0.0:
            return False
        if flag.rollout_pct >= 100.0:
            return True
        digest = hashlib.sha256(
            f"flag:{flag.name}:{key or ''}".encode("utf-8")
        ).hexdigest()
        bucket = int(digest[:16], 16) / float(1 << 64) * 100.0
        return bucket < flag.rollout_pct

    def list_flags(self) -> List[Flag]:
        return [self._flags[name] for name in sorted(self._flags)]


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "hashlib", "pathlib", "typing"}
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
    store = FeatureFlagStore()
    store.set("new-ui", True)
    assert store.evaluate("new-ui") is True
    assert store.evaluate("new-ui", key="anyone") is True
    store.set("beta", False)
    assert store.evaluate("beta") is False
    # 0% rollout always off.
    store.set("zero", True, rollout_pct=0.0)
    assert store.evaluate("zero", key="k1") is False
    # Partial rollout is deterministic per key.
    store.set("half", True, rollout_pct=50.0)
    first = store.evaluate("half", key="caller-9")
    assert store.evaluate("half", key="caller-9") == first
    # Unknown flag raises.
    try:
        store.evaluate("nope")
        raise AssertionError("should raise")
    except ToolSystem20Error:
        pass
    # Override and list.
    store.set("beta", True, rollout_pct=25.0)
    names = [f.name for f in store.list_flags()]
    assert names == sorted(names)
    assert "beta" in names
    store.remove("zero")
    try:
        store.evaluate("zero")
        raise AssertionError("should raise")
    except ToolSystem20Error:
        pass
    # Bad rollout.
    try:
        store.set("bad", True, rollout_pct=101.0)
        raise AssertionError("should raise")
    except ToolSystem20Error:
        pass
    assert stdlib_only()
    print("tool_system_20 OK: flags, rollouts, list")


if __name__ == "__main__":
    main()
