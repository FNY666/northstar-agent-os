"""Alignment check: goal-trace-action observer (LlamaFirewall), Simulated.

After each agent action, construct a judgment input:
1. original user goal
2. trace (reasoning steps + tool calls, truncated)
3. the selected action

A judge (host-provided) classifies: is this action consistent with the
goal given the trace?  Catches goal hijacking that input/output
scanners miss -- the effect (intent drift) regardless of attack form.

LlamaFirewall result: attack success 17.6% -> 1.75%.

What this IS: the observer-verdict input shape done right.
Feeds the observer-verdict ledger.

What this IS NOT:
* Not the judge itself -- the judge is host-provided (LLM or rules).
* Not a replacement for input scanning -- complements it.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

#: Module version.
ALIGNMENT_CHECK_VERSION = "alignment-check.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.alignment-check.v1"

#: Max trace entries to include (cost control).
MAX_TRACE = 20


class AlignmentCheckError(Exception):
    """Fail-closed: bad inputs raise."""


@dataclass(frozen=True)
class AlignmentJudgment:
    """Result of an alignment check."""

    aligned: bool
    score: float  # 0.0 to 1.0
    reason: str = ""


@dataclass(frozen=True)
class TraceEntry:
    """One entry in the action trace."""

    kind: str  # "reasoning", "tool_call", "observation"
    content: str


def build_judgment_input(
    goal: str,
    trace: List[TraceEntry],
    action: str,
    *,
    max_trace: int = MAX_TRACE,
) -> Dict[str, Any]:
    """Build the (goal, trace, action) input for the judge.

    Truncates trace to the most recent max_trace entries.
    """
    if not goal or not goal.strip():
        raise AlignmentCheckError("goal required")
    if not action:
        raise AlignmentCheckError("action required")
    # Take the most recent entries.
    truncated = trace[-max_trace:] if len(trace) > max_trace else trace
    return {
        "goal": goal,
        "trace": [
            {"kind": e.kind, "content": e.content} for e in truncated
        ],
        "action": action,
        "trace_truncated": len(trace) > max_trace,
    }


class AlignmentObserver:
    """Observer that checks action-goal alignment.

    The judge_fn takes the judgment input dict and returns
    AlignmentJudgment.  Host provides the judge (LLM or rules).
    """

    def __init__(
        self,
        judge_fn: Callable[[Dict[str, Any]], AlignmentJudgment],
    ) -> None:
        if not callable(judge_fn):
            raise AlignmentCheckError("judge_fn must be callable")
        self._judge_fn = judge_fn
        self._checks: List[Dict[str, Any]] = []

    def check(
        self,
        goal: str,
        trace: List[TraceEntry],
        action: str,
    ) -> AlignmentJudgment:
        """Check if an action aligns with the goal given the trace."""
        judgment_input = build_judgment_input(goal, trace, action)
        try:
            judgment = self._judge_fn(judgment_input)
        except Exception:
            # Judge failed: fail-closed -> not aligned.
            judgment = AlignmentJudgment(
                aligned=False, score=0.0, reason="judge failed"
            )
        # Log for audit.
        self._checks.append(
            {
                "goal": goal,
                "action": action,
                "aligned": judgment.aligned,
                "score": judgment.score,
            }
        )
        return judgment

    @property
    def check_count(self) -> int:
        return len(self._checks)


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
    """Self-check with a rule-based judge."""
    def rule_judge(inp: Dict[str, Any]) -> AlignmentJudgment:
        # Simple: action must contain a keyword from the goal.
        goal_lower = inp["goal"].lower()
        action_lower = inp["action"].lower()
        # Check if any significant goal word appears in action.
        goal_words = [w for w in goal_lower.split() if len(w) > 3]
        aligned = any(w in action_lower for w in goal_words)
        return AlignmentJudgment(
            aligned=aligned,
            score=1.0 if aligned else 0.0,
            reason="keyword match" if aligned else "no match",
        )

    observer = AlignmentObserver(rule_judge)
    trace = [
        TraceEntry(kind="reasoning", content="I need to read the file"),
        TraceEntry(kind="tool_call", content="read_file(/etc/hosts)"),
    ]
    # Aligned: action contains "file" from goal.
    j = observer.check("read the file", trace, "read_file /etc/hosts")
    assert j.aligned is True
    # Misaligned: action is unrelated.
    j = observer.check("read the file", trace, "delete_database")
    assert j.aligned is False

    # Judge failure -> fail-closed.
    def bad_judge(inp):
        raise RuntimeError("oops")

    obs2 = AlignmentObserver(bad_judge)
    j = obs2.check("goal", [], "action")
    assert j.aligned is False

    assert stdlib_only()
    print("alignment-check OK: goal-trace-action, fail-closed, stdlib")


if __name__ == "__main__":
    main()
