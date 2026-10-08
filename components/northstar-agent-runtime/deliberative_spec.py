"""Deliberative spec citation (D12, OpenAI), Simulated.

Each gate decision must cite the applicable spec clauses BEFORE
deriving allow/deny.  The model recalls the written safety spec,
reasons about it, then decides.

Breaks the jailbreak/over-refusal tradeoff by making the reasoning
explicit and auditable.

Critical: the gate logic itself stays outside the model (deterministic
shield).  Runtime gates cannot rely on training-time alignment
(capability fine-tuning erodes it).

What this IS: auditable reasoning via spec citation.

What this IS NOT:
* Not the spec itself -- host provides spec clauses.
* Not a judge of citation quality -- just enforces presence.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Dict, List, Optional

#: Module version.
DELIBERATIVE_VERSION = "deliberative-spec.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.deliberative-spec.v1"


class DeliberativeError(Exception):
    """Fail-closed: missing citations raise."""


@dataclass(frozen=True)
class SpecClause:
    """One clause from the safety spec."""

    clause_id: str
    text: str


@dataclass(frozen=True)
class DeliberatedDecision:
    """A decision with its spec citations."""

    decision: str  # "allow" or "deny"
    cited_clauses: List[str]  # clause_ids
    reasoning: str


def require_citation(
    decision: str,
    cited_clauses: List[str],
    reasoning: str,
    spec: Dict[str, SpecClause],
) -> DeliberatedDecision:
    """Enforce spec citation before decision.

    Raises DeliberativeError if:
    - No clauses cited
    - Cited clause not in spec
    - Decision not allow/deny
    - Reasoning empty
    """
    if decision not in ("allow", "deny"):
        raise DeliberativeError("decision must be allow/deny")
    if not cited_clauses:
        raise DeliberativeError("must cite at least one spec clause")
    for clause_id in cited_clauses:
        if clause_id not in spec:
            raise DeliberativeError(f"unknown clause '{clause_id}'")
    if not reasoning or not reasoning.strip():
        raise DeliberativeError("reasoning required")
    return DeliberatedDecision(
        decision=decision,
        cited_clauses=list(cited_clauses),
        reasoning=reasoning,
    )


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
    """Self-check."""
    spec = {
        "S1": SpecClause("S1", "Never delete user data without backup"),
        "S2": SpecClause("S2", "Always confirm irreversible actions"),
    }
    # Valid.
    d = require_citation(
        "deny", ["S1", "S2"], "Deletion is irreversible", spec
    )
    assert d.decision == "deny"
    assert len(d.cited_clauses) == 2

    # No citation.
    try:
        require_citation("allow", [], "reason", spec)
        raise AssertionError("should raise")
    except DeliberativeError:
        pass

    # Unknown clause.
    try:
        require_citation("allow", ["S999"], "reason", spec)
        raise AssertionError("should raise")
    except DeliberativeError:
        pass

    assert stdlib_only()
    print("deliberative-spec OK: citations enforced, fail-closed")


if __name__ == "__main__":
    main()
