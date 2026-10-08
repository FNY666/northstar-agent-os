"""Tool A/B testing (mock): deterministic variant bucketing, Simulated.

Experiment assigns callers to variant "A" or "B" via a stable hash
of the experiment name plus the caller's key, so the same caller
always lands in the same variant.  The split ratio is configurable.
Outcomes are recorded per variant and the winner is picked by raw
success rate (with call counts reported; ties need the minimum
sample size to count).

What this IS:
* Deterministic A/B bucketing plus success-rate comparison.

What this IS NOT:
* Not real statistics -- no significance tests, no confidence
  intervals, no sample-size powering.  "Winner" is descriptive
  only.
* Not persistent -- all state lives in memory.
"""

from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

#: Module version.
TOOL_SYSTEM_19_VERSION = "tool-system-19.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.tool-system-19.v1"

#: Minimum samples per variant before a winner is declared.
MIN_SAMPLES = 10


class ToolSystem19Error(Exception):
    """Fail-closed."""


@dataclass
class _VariantStats:
    calls: int = 0
    successes: int = 0

    @property
    def success_rate(self) -> float:
        return self.successes / self.calls if self.calls else 0.0


class Experiment:
    """One A/B experiment with stable hashed bucketing."""

    def __init__(
        self,
        name: str,
        split_a: float = 0.5,
        min_samples: int = MIN_SAMPLES,
    ) -> None:
        if not name:
            raise ToolSystem19Error("name required")
        if not 0.0 < split_a < 1.0:
            raise ToolSystem19Error("split_a must be in (0, 1)")
        if min_samples <= 0:
            raise ToolSystem19Error("min_samples must be positive")
        self._name = name
        self._split_a = split_a
        self._min_samples = min_samples
        self._variants: Dict[str, _VariantStats] = {
            "A": _VariantStats(),
            "B": _VariantStats(),
        }

    @property
    def name(self) -> str:
        return self._name

    def assign(self, key: Optional[str] = None) -> str:
        """Deterministically assign a caller to variant A or B."""
        digest = hashlib.sha256(
            f"{self._name}:{key or ''}".encode("utf-8")
        ).hexdigest()
        bucket = int(digest[:16], 16) / float(1 << 64)
        return "A" if bucket < self._split_a else "B"

    def record_outcome(self, variant: str, success: bool) -> None:
        """Record an outcome for a variant."""
        if variant not in self._variants:
            raise ToolSystem19Error(f"unknown variant '{variant}'")
        stats = self._variants[variant]
        stats.calls += 1
        if success:
            stats.successes += 1

    def rates(self) -> Dict[str, Tuple[int, float]]:
        """variant -> (calls, success_rate)."""
        return {
            v: (s.calls, s.success_rate)
            for v, s in self._variants.items()
        }

    def winner(self) -> Optional[str]:
        """Variant with the higher success rate, or None if undecided.

        Undecided when a variant is below min_samples or rates tie.
        """
        stats = self._variants
        if any(s.calls < self._min_samples for s in stats.values()):
            return None
        if stats["A"].success_rate == stats["B"].success_rate:
            return None
        return "A" if stats["A"].success_rate > stats["B"].success_rate else "B"


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
    exp = Experiment("prompt-style", split_a=0.5, min_samples=4)
    # Stable assignment: same key always maps to the same variant.
    a1 = exp.assign("user-123")
    assert exp.assign("user-123") == a1
    assert a1 in ("A", "B")
    # Too few samples -> undecided.
    exp.record_outcome("A", True)
    exp.record_outcome("B", True)
    assert exp.winner() is None
    # Clear winner: A 4/4, B 1/4.
    for _ in range(3):
        exp.record_outcome("A", True)
    for _ in range(3):
        exp.record_outcome("B", False)
    assert exp.winner() == "A"
    rates = exp.rates()
    assert rates["A"] == (4, 1.0)
    assert rates["B"] == (4, 0.25)
    # Bad variant.
    try:
        exp.record_outcome("C", True)
        raise AssertionError("should raise")
    except ToolSystem19Error:
        pass
    # Bad split.
    try:
        Experiment("bad", split_a=1.0)
        raise AssertionError("should raise")
    except ToolSystem19Error:
        pass
    assert stdlib_only()
    print("tool_system_19 OK: bucketing, outcomes, winner")


if __name__ == "__main__":
    main()
