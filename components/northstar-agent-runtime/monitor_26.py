"""Takedown automation: mock abuse-case workflow, Simulated.

Case states: reported -> submitted -> in_review -> taken_down
                                        |-> rejected |-> failed
Transitions are validated; evidence bundle sha256 recorded on
take_down; per-case SLA deadline; audit trail of transitions.
Timestamps are host-supplied (deterministic).

What this IS: state machine + SLA bookkeeping.

What this IS NOT:
* Not registrar/API integration -- the host drives transitions.
"""

from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional

#: Module version.
MONITOR_26_VERSION = "monitor-26.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.monitor-26.v1"

_TRANSITIONS = {
    "reported": {"submitted"},
    "submitted": {"in_review", "rejected"},
    "in_review": {"taken_down", "rejected", "failed"},
    "taken_down": set(),
    "rejected": set(),
    "failed": set(),
}
_TERMINAL = frozenset({"taken_down", "rejected", "failed"})


class TakedownError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class Transition:
    frm: str
    to: str
    ts: float
    note: str = ""


@dataclass
class TakedownCase:
    case_id: str
    target: str
    kind: str  # phishing_url, fake_domain, impersonation, malware_host
    created_ts: float
    sla_s: float
    state: str = "reported"
    evidence_hash: Optional[str] = None
    history: List[Transition] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.case_id or not self.target or not self.kind:
            raise TakedownError("case_id/target/kind required")
        if self.created_ts < 0 or self.sla_s <= 0:
            raise TakedownError("bad created_ts/sla_s")


class TakedownBoard:
    """Mock takedown workflow board."""

    def __init__(self) -> None:
        self._cases: Dict[str, TakedownCase] = {}
        self._next = 1

    def report(self, target: str, kind: str, ts: float, sla_s: float = 86400.0) -> str:
        if not target or not kind:
            raise TakedownError("target/kind required")
        if ts < 0:
            raise TakedownError("ts must be >= 0")
        case_id = f"TD-{self._next:04d}"
        self._next += 1
        self._cases[case_id] = TakedownCase(case_id, target, kind, ts, sla_s)
        return case_id

    def _get(self, case_id: str) -> TakedownCase:
        case = self._cases.get(case_id)
        if case is None:
            raise TakedownError(f"unknown case {case_id!r}")
        return case

    def transition(
        self, case_id: str, to: str, ts: float, note: str = "",
        evidence: Optional[bytes] = None,
    ) -> None:
        case = self._get(case_id)
        if to not in _TRANSITIONS[case.state]:
            raise TakedownError(f"illegal {case.state} -> {to}")
        if ts < 0:
            raise TakedownError("ts must be >= 0")
        if to == "taken_down":
            if evidence is None:
                raise TakedownError("evidence required for taken_down")
            case.evidence_hash = "sha256:" + hashlib.sha256(evidence).hexdigest()
        case.history.append(Transition(case.state, to, ts, note))
        case.state = to

    def sla_breached(self, case_id: str, now_ts: float) -> bool:
        case = self._get(case_id)
        if case.state in _TERMINAL:
            return False
        return now_ts > case.created_ts + case.sla_s

    def get(self, case_id: str) -> TakedownCase:
        return self._get(case_id)


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
    """Self-check."""
    b = TakedownBoard()
    cid = b.report("evil.tk/login", "phishing_url", ts=100.0, sla_s=1000.0)
    assert b.get(cid).state == "reported"
    b.transition(cid, "submitted", ts=110.0)
    b.transition(cid, "in_review", ts=120.0)
    assert b.sla_breached(cid, 500.0) is False
    assert b.sla_breached(cid, 2000.0) is True
    b.transition(cid, "taken_down", ts=130.0, evidence=b"screenshot-bytes")
    case = b.get(cid)
    assert case.state == "taken_down"
    assert case.evidence_hash and case.evidence_hash.startswith("sha256:")
    assert len(case.history) == 3
    assert b.sla_breached(cid, 99999.0) is False  # terminal: no breach

    cid2 = b.report("x.com", "fake_domain", ts=0.0)
    for bad in (
        lambda: b.transition(cid, "in_review", ts=140.0),  # terminal
        lambda: b.transition(cid2, "in_review", ts=10.0),  # skip submitted
        lambda: b.transition("TD-9999", "submitted", ts=1.0),
        lambda: b.report("", "phishing_url", ts=1.0),
        lambda: b.transition(cid2, "submitted", ts=-1.0),
    ):
        try:
            bad()
            raise AssertionError("should raise")
        except TakedownError:
            pass
    # taken_down without evidence.
    b.transition(cid2, "submitted", ts=20.0)
    b.transition(cid2, "in_review", ts=30.0)
    try:
        b.transition(cid2, "taken_down", ts=40.0)
        raise AssertionError("should raise")
    except TakedownError:
        pass
    assert stdlib_only()
    print("monitor-26 OK: workflow, evidence hash, SLA, audit, fail-closed, stdlib")


if __name__ == "__main__":
    main()
