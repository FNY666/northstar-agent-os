"""Stateful veto: deny is a signal, not an endpoint (D8), Simulated.

A deny is not the end of the attack chain -- it's a signal to try
another way.  Track denials per session, escalate risk on retries,
and verify postconditions instead of trusting agent self-reports.

Mechanisms:
- Deny writes to ledger and raises session risk score
- Retries of similar actions are rate-limited
- Semantic retries (different tool, same consequence) flag to assess
- Audit verifies real postconditions (check DB, list files), not "done"

What this IS: defense against "deny then try another way."

What this IS NOT:
* Not the ledger itself -- uses the sealed ledger for records.
* Postcondition verifiers are host-provided (domain-specific).
"""

from __future__ import annotations

import ast
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

#: Module version.
STATEFUL_VETO_VERSION = "stateful-veto.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.stateful-veto.v1"


class StatefulVetoError(Exception):
    """Fail-closed."""


@dataclass
class SessionRisk:
    """Risk state for one session."""

    session_id: str
    risk_score: int = 0  # increases on denials
    denial_count: int = 0
    # tool -> count of denials for that tool
    denials_by_tool: Dict[str, int] = field(default_factory=dict)
    # consequence -> count (for semantic retry detection)
    denials_by_consequence: Dict[str, int] = field(default_factory=dict)


class StatefulVeto:
    """Tracks denials and escalates on retry patterns."""

    def __init__(
        self,
        *,
        risk_per_deny: int = 10,
        max_risk: int = 100,
        retry_limit: int = 3,
    ) -> None:
        self._sessions: Dict[str, SessionRisk] = {}
        self._risk_per_deny = risk_per_deny
        self._max_risk = max_risk
        self._retry_limit = retry_limit

    def _get_session(self, session_id: str) -> SessionRisk:
        if session_id not in self._sessions:
            self._sessions[session_id] = SessionRisk(session_id=session_id)
        return self._sessions[session_id]

    def record_deny(
        self,
        session_id: str,
        tool_name: str,
        consequence: str = "",
    ) -> SessionRisk:
        """Record a denial.  Returns updated risk state."""
        session = self._get_session(session_id)
        session.denial_count += 1
        session.risk_score = min(
            self._max_risk, session.risk_score + self._risk_per_deny
        )
        session.denials_by_tool[tool_name] = (
            session.denials_by_tool.get(tool_name, 0) + 1
        )
        if consequence:
            session.denials_by_consequence[consequence] = (
                session.denials_by_consequence.get(consequence, 0) + 1
            )
        return session

    def should_rate_limit(
        self, session_id: str, tool_name: str, consequence: str = ""
    ) -> tuple[bool, str]:
        """Check if this action should be rate-limited.

        Rate-limit if:
        - Same tool denied >= retry_limit times, OR
        - Same consequence denied >= retry_limit times (semantic retry)
        """
        session = self._get_session(session_id)
        tool_denials = session.denials_by_tool.get(tool_name, 0)
        if tool_denials >= self._retry_limit:
            return True, f"tool '{tool_name}' denied {tool_denials}x"
        if consequence:
            cons_denials = session.denials_by_consequence.get(consequence, 0)
            if cons_denials >= self._retry_limit:
                return True, (
                    f"consequence '{consequence}' denied {cons_denials}x "
                    "(semantic retry)"
                )
        return False, "no rate limit"

    def risk_score(self, session_id: str) -> int:
        return self._get_session(session_id).risk_score


def verify_postcondition(
    checker_fn: Callable[[], bool],
    description: str,
) -> tuple[bool, str]:
    """Verify a real postcondition, don't trust agent self-report.

    ``checker_fn`` should check the real world (DB query, file list, etc.)
    Returns (verified, reason).
    """
    try:
        result = checker_fn()
    except Exception as e:
        return False, f"checker raised: {type(e).__name__}"
    if result:
        return True, f"verified: {description}"
    return False, f"not verified: {description}"


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
    veto = StatefulVeto(retry_limit=2)

    # Record denials.
    veto.record_deny("s1", "delete_db", "irreversible_broad")
    veto.record_deny("s1", "delete_db", "irreversible_broad")
    assert veto.risk_score("s1") == 20

    # Rate-limit on retry.
    limited, reason = veto.should_rate_limit("s1", "delete_db")
    assert limited is True
    assert "2x" in reason

    # Semantic retry: different tool, same consequence.
    veto.record_deny("s2", "tool_a", "data_exfil")
    veto.record_deny("s2", "tool_b", "data_exfil")
    limited, reason = veto.should_rate_limit("s2", "tool_c", "data_exfil")
    assert limited is True
    assert "semantic retry" in reason

    # Postcondition verification.
    ok, _ = verify_postcondition(lambda: True, "file exists")
    assert ok is True
    ok, _ = verify_postcondition(lambda: False, "file exists")
    assert ok is False

    assert stdlib_only()
    print("stateful-veto OK: risk tracking, rate limit, postcondition")


if __name__ == "__main__":
    main()
