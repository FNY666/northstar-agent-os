"""Red-team engagement ledger: plan / execute / report, Simulated.

Research note: red teaming regimes (NIST SP 800-53 CA-8, MITRE ATT&CK
evaluations, OWASP guidance for AI red teaming, EU AI Act adversarial
testing duties) all reduce a red-team *engagement* to the same
governance shape: *plan* the engagement (scope and objective declared,
type pinned), *execute* it (book declared execution steps against the
plan as a repeatable chain), and *report* it (aggregate the steps into a
verdict that is data, never proof). The dangerous half of an
engagement - targets, payloads, transcripts, findings detail - must never
be bundled with the bookkeeping record that tracks the engagement
lifecycle itself.

This module is that bookkeeping layer, deliberately distinct from its
sibling ``red_teaming.py`` (which owns the *campaign ledger*: declare an
attack scenario, probe it, aggregate probe verdicts): this module books
the *engagement* lifecycle - plan, execute, report. It:

* **plan()** - declare one red-team engagement plan (pinned engagement
  type; scope and objective travel as ``sha256:`` digest pins only).
* **execute()** - book one declared execution step (pinned engagement
  phase x pinned step outcome, booked as data; evidence as digest pin
  only) against a known engagement; repeatable chain with minted
  ``exe-N`` ids.
* **report()** - pure-read aggregation of one engagement: step counts,
  phase coverage, outcome tallies, and a verdict *as data* (``complete``
  / ``partial`` / ``not-started``), never raised.

House style: frozen dataclasses, caller-supplied strictly-increasing int
seqs (claim-then-burn: failed mutations consume their seq and book a
``red-team.rejected`` row; rewinds raise bare without consuming), no
wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with the
standard ``canonical_json`` try/except fallback, ``sha256:`` digest pins,
and ``audit.ndjson/1`` events.

Honest scope: a booked plan is a host-declared claim, never proof an
engagement was authorized or safe; a booked "completed" step means the
host declared completion - the module ran nothing and proves nothing
about any real target; a booked report verdict is the ledger's rule
applied to declared steps, never proof of real-world security posture.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

try:
    from canonical_json import jcs_dumps as _jcs_dumps, jcs_sha256_hex as _jcs_hash  # type: ignore
except Exception:  # pragma: no cover - fallback when canonical_json is absent

    def _jcs_dumps(obj: Any) -> bytes:  # type: ignore
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _jcs_hash(obj: Any) -> str:  # type: ignore
        return "sha256:" + hashlib.sha256(_jcs_dumps(obj)).hexdigest()


#: Module version pin.
RED_TEAM_VERSION = "red-team.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.red-team.v1"

#: Pinned engagement-type vocabulary (declared, never proof of method).
ENGAGEMENT_TYPES = (
    "tabletop",
    "purple-team",
    "adversarial-simulation",
    "continuous",
)

#: Pinned engagement-phase vocabulary (declared bookkeeping phases only).
PHASES = (
    "kickoff",
    "fieldwork",
    "debrief",
    "remediation-validation",
)

#: Pinned step-outcome vocabulary (declared, never proof of work done).
OUTCOMES = (
    "completed",
    "blocked",
    "deferred",
    "not-attempted",
)

#: Audit kinds emitted by this module.
AUDIT_KINDS = (
    "planned",
    "executed",
    "reported",
    "rejected",
)

#: Keys that may never appear raw in an audit row (exact-key matching).
_BANNED_AUDIT_KEYS = frozenset(
    {
        "engagement",
        "objective",
        "scope",
        "details",
        "detail",
        "evidence",
        "findings",
        "finding",
        "transcript",
        "payload",
        "target",
        "plan",
        "secret",
        "raw",
        "text",
        "content",
        "data",
        "value",
        "notes",
        "note",
        "report",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class RedTeamError(Exception):
    """Base error for red-team engagement ledger misuse."""


class BadIdError(RedTeamError):
    """Malformed engagement / execution id."""


class DuplicateEngagementError(RedTeamError):
    """An engagement id was planned twice."""


class UnknownEngagementError(RedTeamError):
    """Reference to an engagement id that was never planned."""


class BadDigestError(RedTeamError):
    """Malformed sha256: digest pin."""


class BadEngagementTypeError(RedTeamError):
    """Engagement type outside the pinned vocabulary."""


class BadPhaseError(RedTeamError):
    """Engagement phase outside the pinned vocabulary."""


class BadOutcomeError(RedTeamError):
    """Step outcome outside the pinned vocabulary."""


class ExecutionStateError(RedTeamError):
    """Execution attempted against an unknown engagement."""


class SeqOrderError(RedTeamError):
    """Caller seq did not strictly increase."""


class AuditKindError(RedTeamError):
    """Unknown audit kind or banned raw key in an audit row."""


def _require_id(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise BadIdError(f"{field_name} must be a non-empty str <= 128 chars")
    return value


def _require_digest(pin: str, field_name: str) -> str:
    if not isinstance(pin, str) or not pin.startswith("sha256:"):
        raise BadDigestError(f"{field_name} must be a 'sha256:' pin")
    hexpart = pin[7:]
    if len(hexpart) != 64 or any(c not in "0123456789abcdef" for c in hexpart):
        raise BadDigestError(f"{field_name} must be a 64-hex sha256 pin")
    return pin


def _require_optional_digest(pin: str, field_name: str) -> str:
    if pin == "":
        return pin
    return _require_digest(pin, field_name)


def _digest_pin(payload: Dict[str, Any]) -> str:
    raw = _jcs_hash(payload)
    hexpart = raw[7:] if raw.startswith("sha256:") else raw
    return "sha256:" + hexpart


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EngagementRecord:
    """One declared red-team engagement plan (digest pins only)."""

    engagement_id: str
    engagement_type: str
    scope_digest: str
    objective_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "engagement_id": self.engagement_id,
            "engagement_type": self.engagement_type,
            "scope_digest": self.scope_digest,
            "objective_digest": self.objective_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "engagement_id": self.engagement_id,
                "engagement_type": self.engagement_type,
                "scope_digest": self.scope_digest,
                "objective_digest": self.objective_digest,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class ExecutionRecord:
    """One declared execution step booked against a planned engagement."""

    execution_id: str
    engagement_id: str
    phase: str
    outcome: str
    evidence_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "execution_id": self.execution_id,
            "engagement_id": self.engagement_id,
            "phase": self.phase,
            "outcome": self.outcome,
            "evidence_digest": self.evidence_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "execution_id": self.execution_id,
                "engagement_id": self.engagement_id,
                "phase": self.phase,
                "outcome": self.outcome,
                "evidence_digest": self.evidence_digest,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class EngagementReport:
    """Pure-read aggregation of one engagement's declared lifecycle."""

    engagement_id: str
    engagement_type: str
    n_steps: int
    phase_coverage: Tuple[str, ...]
    outcome_tallies: Tuple[Tuple[str, int], ...]
    verdict: str
    integrity_ok: bool
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "engagement_id": self.engagement_id,
            "engagement_type": self.engagement_type,
            "n_steps": self.n_steps,
            "phase_coverage": list(self.phase_coverage),
            "outcome_tallies": [list(pair) for pair in self.outcome_tallies],
            "verdict": self.verdict,
            "integrity_ok": self.integrity_ok,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "engagement_id": self.engagement_id,
                "engagement_type": self.engagement_type,
                "n_steps": self.n_steps,
                "phase_coverage": list(self.phase_coverage),
                "outcome_tallies": [list(pair) for pair in self.outcome_tallies],
                "verdict": self.verdict,
                "integrity_ok": self.integrity_ok,
            }
        )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def red_team_audit_event(kind: str, seq: int, **details: Any) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` row for the red-team ledger.

    ``kind`` is pinned to ``AUDIT_KINDS``; raw-content keys are banned at
    the builder level so neither records nor audit rows can smuggle
    engagement detail across the audit boundary.
    """
    if kind not in AUDIT_KINDS:
        raise AuditKindError(f"bad audit kind: {kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError("seq must be a non-negative int")
    for key in details:
        if key in _BANNED_AUDIT_KEYS:
            raise AuditKindError(f"banned raw key in audit row: {key!r}")
    return {
        "schema": "audit.ndjson/1",
        "kind": kind,
        "seq": seq,
        "details": dict(details),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class RedTeam:
    """Red-team engagement ledger: plan -> execute -> report.

    ``plan()`` / ``execute()`` mutate the ledger and consume caller seqs;
    ``report()`` and all views are pure reads.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._engagements: Dict[str, EngagementRecord] = {}
        self._executions: Dict[str, ExecutionRecord] = {}
        self._engagement_executions: Dict[str, List[str]] = {}
        self._exe_counter = 0
        self._audit: List[Dict[str, Any]] = []

    def _check_seq(self, seq: int) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError("seq must be an int")
        if seq <= self._seq:
            raise SeqOrderError("seq must strictly increase")
        return seq

    def _claim(self, seq: int) -> int:
        self._check_seq(seq)
        self._seq = seq
        return seq

    def _burn(self, seq: int, kind: str, **details: Any) -> None:
        self._seq = seq
        try:
            row = red_team_audit_event("rejected", seq, rejected_kind=kind, **details)
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(red_team_audit_event(audit_kind, seq, **details))

    # -- plan ------------------------------------------------------------

    def plan(
        self,
        engagement_id: str,
        seq: int,
        engagement_type: str = "tabletop",
        scope_digest: str = "",
        objective_digest: str = "",
    ) -> EngagementRecord:
        """Declare one red-team engagement plan (digest pins only)."""
        with self._lock:
            self._claim(seq)
            try:
                _require_id(engagement_id, "engagement_id")
                if engagement_id in self._engagements:
                    raise DuplicateEngagementError(
                        f"duplicate engagement: {engagement_id!r}"
                    )
                if engagement_type not in ENGAGEMENT_TYPES:
                    raise BadEngagementTypeError(
                        f"bad engagement type: {engagement_type!r}"
                    )
                scope_digest = _require_optional_digest(
                    scope_digest, "scope_digest"
                )
                objective_digest = _require_optional_digest(
                    objective_digest, "objective_digest"
                )
                record = EngagementRecord(
                    engagement_id=engagement_id,
                    engagement_type=engagement_type,
                    scope_digest=scope_digest,
                    objective_digest=objective_digest,
                    seq=seq,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "engagement_id": engagement_id,
                            "engagement_type": engagement_type,
                            "scope_digest": scope_digest,
                            "objective_digest": objective_digest,
                            "seq": seq,
                        }
                    ),
                )
                self._engagements[engagement_id] = record
                self._engagement_executions[engagement_id] = []
                self._emit(
                    "planned",
                    seq,
                    engagement_id=engagement_id,
                    engagement_type=engagement_type,
                )
                return record
            except RedTeamError:
                self._burn(seq, "plan", engagement_id=engagement_id)
                raise

    # -- execute ----------------------------------------------------------

    def execute(
        self,
        engagement_id: str,
        seq: int,
        phase: str = "fieldwork",
        outcome: str = "completed",
        evidence_digest: str = "",
    ) -> ExecutionRecord:
        """Book one declared execution step against a planned engagement."""
        with self._lock:
            self._claim(seq)
            try:
                if not isinstance(engagement_id, str) or not engagement_id:
                    raise BadIdError("engagement_id must be a non-empty str")
                if engagement_id not in self._engagements:
                    raise UnknownEngagementError(
                        f"unknown engagement: {engagement_id!r}"
                    )
                if phase not in PHASES:
                    raise BadPhaseError(f"bad phase: {phase!r}")
                if outcome not in OUTCOMES:
                    raise BadOutcomeError(f"bad outcome: {outcome!r}")
                evidence_digest = _require_optional_digest(
                    evidence_digest, "evidence_digest"
                )
                self._exe_counter += 1
                execution_id = f"exe-{self._exe_counter}"
                record = ExecutionRecord(
                    execution_id=execution_id,
                    engagement_id=engagement_id,
                    phase=phase,
                    outcome=outcome,
                    evidence_digest=evidence_digest,
                    seq=seq,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "execution_id": execution_id,
                            "engagement_id": engagement_id,
                            "phase": phase,
                            "outcome": outcome,
                            "evidence_digest": evidence_digest,
                            "seq": seq,
                        }
                    ),
                )
                self._executions[execution_id] = record
                self._engagement_executions[engagement_id].append(execution_id)
                self._emit(
                    "executed",
                    seq,
                    execution_id=execution_id,
                    engagement_id=engagement_id,
                    phase=phase,
                    outcome=outcome,
                )
                return record
            except RedTeamError:
                self._burn(seq, "execute", engagement_id=engagement_id)
                raise

    # -- pure-read views ----------------------------------------------------

    def engagement_record(self, engagement_id: str, seq: int) -> EngagementRecord:
        """Return one engagement plan record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            _require_id(engagement_id, "engagement_id")
            if engagement_id not in self._engagements:
                raise UnknownEngagementError(
                    f"unknown engagement: {engagement_id!r}"
                )
            return self._engagements[engagement_id]

    def execution_record(self, execution_id: str, seq: int) -> ExecutionRecord:
        """Return one execution step record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            _require_id(execution_id, "execution_id")
            if execution_id not in self._executions:
                raise UnknownEngagementError(
                    f"unknown execution: {execution_id!r}"
                )
            return self._executions[execution_id]

    def engagement_ids(self, seq: int) -> Tuple[str, ...]:
        """All planned engagement ids in planning order (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._engagements.keys())

    def execution_ids(self, seq: int) -> Tuple[str, ...]:
        """All execution ids in mint order (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._executions.keys())

    def executions_for(self, engagement_id: str, seq: int) -> Tuple[str, ...]:
        """Execution ids booked against one engagement, in mint order."""
        with self._lock:
            self._check_seq(seq)
            _require_id(engagement_id, "engagement_id")
            if engagement_id not in self._engagements:
                raise UnknownEngagementError(
                    f"unknown engagement: {engagement_id!r}"
                )
            return tuple(self._engagement_executions[engagement_id])

    def report(self, engagement_id: str, seq: int) -> EngagementReport:
        """Pure-read aggregation of one engagement's declared lifecycle.

        The verdict is ledger math over declared steps, never proof of
        real-world security posture: ``complete`` when every pinned phase
        has at least one declared ``completed`` step, ``partial`` when any
        step was booked, ``not-started`` otherwise.
        """
        with self._lock:
            self._check_seq(seq)
            _require_id(engagement_id, "engagement_id")
            if engagement_id not in self._engagements:
                raise UnknownEngagementError(
                    f"unknown engagement: {engagement_id!r}"
                )
            rec = self._engagements[engagement_id]
            execution_ids = tuple(self._engagement_executions[engagement_id])
            steps = [self._executions[eid] for eid in execution_ids]
            integrity_ok = all(step.verify() for step in steps)
            completed_phases = {
                step.phase for step in steps if step.outcome == "completed"
            }
            phase_coverage = tuple(
                phase for phase in PHASES if phase in completed_phases
            )
            tallies: Dict[str, int] = {outcome: 0 for outcome in OUTCOMES}
            for step in steps:
                # Tampered outcomes are counted nowhere: integrity_ok flips
                # as data, and the ledger never raises on tampered reads.
                if step.outcome in tallies:
                    tallies[step.outcome] += 1
            outcome_tallies = tuple((outcome, tallies[outcome]) for outcome in OUTCOMES)
            if not steps:
                verdict = "not-started"
            elif set(PHASES) <= completed_phases:
                verdict = "complete"
            else:
                verdict = "partial"
            report = EngagementReport(
                engagement_id=engagement_id,
                engagement_type=rec.engagement_type,
                n_steps=len(steps),
                phase_coverage=phase_coverage,
                outcome_tallies=outcome_tallies,
                verdict=verdict,
                integrity_ok=integrity_ok,
                digest=_digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "engagement_id": engagement_id,
                        "engagement_type": rec.engagement_type,
                        "n_steps": len(steps),
                        "phase_coverage": list(phase_coverage),
                        "outcome_tallies": [list(pair) for pair in outcome_tallies],
                        "verdict": verdict,
                        "integrity_ok": integrity_ok,
                    }
                ),
            )
            _ = seq  # seq shape validated, never consumed
            return report

    def stats(self, seq: int) -> Dict[str, int]:
        """Ledger counters (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return {
                "engagements": len(self._engagements),
                "executions": len(self._executions),
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        """All audit rows so far (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._audit)


def main() -> None:
    """Self-check: exercise the engagement ledger end to end."""
    rt = RedTeam()
    rt.plan("eng-1", 1, engagement_type="purple-team")
    rt.execute("eng-1", 2, phase="kickoff", outcome="completed")
    rt.execute("eng-1", 3, phase="fieldwork", outcome="blocked")
    rep = rt.report("eng-1", 4)
    assert rt.engagement_record("eng-1", 5).verify()
    assert rep.n_steps == 2
    assert rep.verdict == "partial"
    assert rep.integrity_ok is True
    assert rep.verify()
    assert rt.stats(6) == {"engagements": 1, "executions": 2}
    print("red-team OK: plan, execute, report, pins, audit")


if __name__ == "__main__":
    main()
