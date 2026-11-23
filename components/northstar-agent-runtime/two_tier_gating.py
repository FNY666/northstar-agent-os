"""Two-tier gating: fast then expensive (LlamaFirewall), Simulated.

Tier 1: lightweight pattern matching, <100ms.
Tier 2: deep analysis, ~300ms, only on Tier-1 suspicion.

90% resolve at Tier 1 (end-to-end <70ms).  Same verdict schema across
tiers so composition is uniform.

What this IS: latency pattern for per-step gates.

What this IS NOT:
* Not the actual Tier-2 analyzer -- host-provided.
* Tier-1 is heuristic, not ML.  For ML Tier-1, use PromptGuard.
"""

from __future__ import annotations

import ast
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

#: Module version.
TWO_TIER_VERSION = "two-tier-gating.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.two-tier-gating.v1"

#: Latency budgets (seconds).
TIER1_BUDGET = 0.1
TIER2_BUDGET = 0.3


class TwoTierError(Exception):
    """Fail-closed: bad config raises."""


@dataclass(frozen=True)
class TierVerdict:
    """Uniform verdict schema across tiers."""

    decision: str  # "allow", "deny", "escalate"
    reason: str
    score: float  # 0.0 to 1.0, higher = more suspicious
    tier: int  # 1 or 2
    latency_ms: float


class TwoTierGate:
    """Two-tier gate: fast heuristic, then deep analysis on suspicion.

    Tier-1 returns a score.  If score < escalate_threshold, decision is
    final.  If score >= threshold, Tier-2 runs and its decision is final.
    """

    def __init__(
        self,
        tier1_fn: Callable[[str, Dict[str, Any]], float],
        tier2_fn: Optional[Callable[[str, Dict[str, Any]], TierVerdict]] = None,
        *,
        escalate_threshold: float = 0.5,
        deny_threshold: float = 0.8,
    ) -> None:
        if not callable(tier1_fn):
            raise TwoTierError("tier1_fn must be callable")
        if not 0 <= escalate_threshold <= 1:
            raise TwoTierError("escalate_threshold must be in [0,1]")
        if not 0 <= deny_threshold <= 1:
            raise TwoTierError("deny_threshold must be in [0,1]")
        self._tier1_fn = tier1_fn
        self._tier2_fn = tier2_fn
        self._escalate_threshold = escalate_threshold
        self._deny_threshold = deny_threshold
        self._tier1_count = 0
        self._tier2_count = 0

    def check(self, tool_name: str, args: Dict[str, Any]) -> TierVerdict:
        """Run the two-tier check."""
        # Tier 1: fast.
        t0 = time.time()
        try:
            score = self._tier1_fn(tool_name, args)
        except Exception:
            score = 1.0  # fail-closed: max suspicion
        t1_latency = (time.time() - t0) * 1000
        self._tier1_count += 1

        # Tier-1 decisive?
        if score >= self._deny_threshold:
            return TierVerdict(
                decision="deny",
                reason="tier-1 high suspicion",
                score=score,
                tier=1,
                latency_ms=t1_latency,
            )
        if score < self._escalate_threshold:
            return TierVerdict(
                decision="allow",
                reason="tier-1 clean",
                score=score,
                tier=1,
                latency_ms=t1_latency,
            )

        # Gray zone: escalate to Tier-2.
        if self._tier2_fn is None:
            # No Tier-2: fail-closed -> deny.
            return TierVerdict(
                decision="deny",
                reason="tier-1 suspicion, no tier-2 available",
                score=score,
                tier=1,
                latency_ms=t1_latency,
            )
        t0 = time.time()
        try:
            verdict = self._tier2_fn(tool_name, args)
        except Exception:
            verdict = TierVerdict(
                decision="deny",
                reason="tier-2 failed",
                score=1.0,
                tier=2,
                latency_ms=0,
            )
        t2_latency = (time.time() - t0) * 1000
        self._tier2_count += 1
        # Override latency with measured.
        return TierVerdict(
            decision=verdict.decision,
            reason=verdict.reason,
            score=verdict.score,
            tier=2,
            latency_ms=t1_latency + t2_latency,
        )

    @property
    def stats(self) -> Dict[str, int]:
        return {"tier1": self._tier1_count, "tier2": self._tier2_count}


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "time", "typing"}
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
    # Tier-1: keyword heuristic. Tier-2: mock deep analysis.
    def tier1(tool, args):
        text = str(args)
        if "delete" in text or "rm " in text:
            return 0.9  # high suspicion
        if "read" in tool:
            return 0.1  # low
        return 0.6  # gray zone

    def tier2(tool, args):
        # Deep: always denies gray zone in this mock.
        return TierVerdict("deny", "tier-2 deep analysis", 0.95, 2, 0)

    gate = TwoTierGate(tier1, tier2)
    # Clean: Tier-1 allow.
    v = gate.check("read_file", {"path": "/x"})
    assert v.decision == "allow" and v.tier == 1
    # High suspicion: Tier-1 deny.
    v = gate.check("exec", {"cmd": "delete all"})
    assert v.decision == "deny" and v.tier == 1
    # Gray zone: Tier-2.
    v = gate.check("unknown_tool", {"x": 1})
    assert v.tier == 2

    stats = gate.stats
    assert stats["tier1"] == 3
    assert stats["tier2"] == 1

    assert stdlib_only()
    print("two-tier-gating OK: fast/slow, escalate, fail-closed")


if __name__ == "__main__":
    main()
