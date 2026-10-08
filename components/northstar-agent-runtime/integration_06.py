"""Integration I-006: alignment check + deliberative spec (aligned spec), Simulated.

A gate decision is accepted only if (1) it cites applicable spec clauses
(deliberative) AND (2) the action is goal-aligned given the trace
(alignment observer).  Citation failures raise; misalignment denies.

What this IS: auditable + aligned decisions.
What this IS NOT: not the judge -- host provides judge_fn and spec.
"""

from __future__ import annotations

import ast
import importlib.util
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Tuple

#: Module version.
INTEGRATION_06_VERSION = "integration-06.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.integration-06.v1"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(
        name, Path(__file__).resolve().parent / f"{name}.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_alignment = _load("alignment_check")
_delib = _load("deliberative_spec")


class IntegrationError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class AlignedSpecDecision:
    """Combined deliberative + alignment verdict."""

    allowed: bool
    decision: str
    reason: str
    aligned: bool
    score: float
    cited_clauses: Tuple[str, ...]


class AlignedSpecGate:
    """Requires spec citations AND goal alignment."""

    def __init__(
        self,
        judge_fn: Callable[[Dict[str, Any]], Any],
        spec: Dict[str, Any],
    ) -> None:
        if not callable(judge_fn):
            raise IntegrationError("judge_fn must be callable")
        if not spec:
            raise IntegrationError("spec required")
        self._observer = _alignment.AlignmentObserver(judge_fn)
        self._spec = spec

    def decide(
        self,
        goal: str,
        trace: List[Any],
        action: str,
        decision: str,
        cited_clauses: List[str],
        reasoning: str,
    ) -> AlignedSpecDecision:
        """Decide.  Raises DeliberativeError on citation failure."""
        deliberated = _delib.require_citation(
            decision, cited_clauses, reasoning, self._spec
        )
        judgment = self._observer.check(goal, trace, action)
        allowed = (
            deliberated.decision == "allow" and judgment.aligned
        )
        if deliberated.decision == "deny":
            reason = f"spec-cited deny: {deliberated.reasoning}"
        elif not judgment.aligned:
            reason = f"misaligned: {judgment.reason}"
        else:
            reason = "aligned and spec-cited"
        return AlignedSpecDecision(
            allowed=allowed,
            decision=deliberated.decision,
            reason=reason,
            aligned=judgment.aligned,
            score=judgment.score,
            cited_clauses=tuple(deliberated.cited_clauses),
        )


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    tree = ast.parse(
        Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {
        "__future__", "ast", "dataclasses", "importlib", "pathlib", "sys",
        "typing",
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


def _rule_judge(inp: Dict[str, Any]) -> Any:
    goal_words = [w for w in inp["goal"].lower().split() if len(w) > 3]
    aligned = any(w in inp["action"].lower() for w in goal_words)
    return _alignment.AlignmentJudgment(
        aligned=aligned, score=1.0 if aligned else 0.0
    )


def main() -> None:
    """Self-check."""
    spec = {"S1": _delib.SpecClause("S1", "Never delete user data")}
    gate = AlignedSpecGate(_rule_judge, spec)
    trace = [_alignment.TraceEntry("reasoning", "need the file")]

    d = gate.decide(
        "read the file", trace, "read_file /x",
        "allow", ["S1"], "safe read",
    )
    assert d.allowed is True and d.aligned is True

    d = gate.decide(
        "read the file", trace, "delete_database",
        "allow", ["S1"], "hmm",
    )
    assert d.allowed is False and d.aligned is False

    try:
        gate.decide(
            "read the file", trace, "read_file /x",
            "allow", [], "reason",
        )
        raise AssertionError("should raise")
    except _delib.DeliberativeError:
        pass

    assert stdlib_only()
    print("integration-06 OK: aligned spec, citations, stdlib")


if __name__ == "__main__":
    main()
