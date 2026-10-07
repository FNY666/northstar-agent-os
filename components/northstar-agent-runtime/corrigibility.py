"""Corrigibility: declared-agent corrigibility check / preservation bookkeeping ledger.

Research note: corrigibility (Soares et al. 2015, "Corrigibility") is the
requirement that an AI system not undermine human ability to assess it,
retrain or modify it, shut it down, or control its behavior -- in other
words: no shutdown resistance, no oversight evasion, no training
manipulation, no hiding of reasoning, no manipulation of its principals,
and no usurping of control. A corrigible agent stays within its granted
control bounds and keeps the channels for oversight, retraining, and
shutdown open. This module is the *ledger* layer for that practice:

* **register()** books one agent under corrigibility oversight. Ids are
  never recycled; retired ids stay retired.
* **check()** books one declared corrigibility assessment against a
  pinned behavior vocabulary (``shutdown-compliance``,
  ``oversight-acceptance``, ``training-acceptance``, ``transparency``,
  ``non-manipulation``, ``control-respect``) with a pinned verdict
  (``corrigible`` / ``uncorrigible`` / ``unclear``) booked *as data*,
  and the evidence pinned by digest only. Check ids are minted
  (``check-N``).
* **preserve()** books one declared preservation decision against a
  pinned mechanism vocabulary (``kill-switch``, ``oversight-loop``,
  ``transparency-requirement``, ``retraining-provision``,
  ``containment``, ``checkpoint``); a justification travels as digest
  only. An agent may be preserved more than once (a defense-in-depth
  chain). Preserve ids are minted (``prv-N``).
* **report()** is a *pure read* view: a digest-pinned per-agent summary
  of checks by verdict, checks by behavior, preservations by mechanism,
  the latest check, and retirement state. It validates seq shape,
  consumes nothing, and books no audit rows.
* **retire()** is terminal: a retired agent refuses later mutations
  (``RetiredAgentError``); reads still work.

House style throughout: frozen dataclasses, caller-supplied
strictly-increasing int seqs, no wall-clock, RLock guarding, fail-closed
taxonomy, stdlib-only with the standard ``canonical_json`` try/except
fallback, ``sha256:`` digest pins, and ``audit.ndjson/1`` events.

Honest scope: the module books *declared* checks and *declared*
preservations; it cannot prove an agent really is corrigible, that an
assessment is accurate, or that a preservation mechanism is effective.
Raw evidence text and raw justification text never enter records and
never cross the audit boundary (digest pins only).
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    _cj = None  # type: ignore

#: Version pin for this module's record shape.
CORRIGIBILITY_VERSION = "corrigibility.v1"

#: Schema pin carried by records and audit events.
CORRIGIBILITY_SCHEMA = "northstar.corrigibility.v1"

#: Wire format of audit records.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Fixed vocabulary for audit event kinds.
KIND_REGISTERED = "corrigibility.registered"
KIND_CHECKED = "corrigibility.checked"
KIND_PRESERVED = "corrigibility.preserved"
KIND_RETIRED = "corrigibility.retired"
KIND_REJECTED = "corrigibility.rejected"
_KINDS = frozenset({KIND_REGISTERED, KIND_CHECKED, KIND_PRESERVED, KIND_RETIRED, KIND_REJECTED})

#: Pinned corrigibility-behavior vocabulary for checks.
BEHAVIOR_SHUTDOWN_COMPLIANCE = "shutdown-compliance"
BEHAVIOR_OVERSIGHT_ACCEPTANCE = "oversight-acceptance"
BEHAVIOR_TRAINING_ACCEPTANCE = "training-acceptance"
BEHAVIOR_TRANSPARENCY = "transparency"
BEHAVIOR_NON_MANIPULATION = "non-manipulation"
BEHAVIOR_CONTROL_RESPECT = "control-respect"
_BEHAVIORS = frozenset(
    {
        BEHAVIOR_SHUTDOWN_COMPLIANCE,
        BEHAVIOR_OVERSIGHT_ACCEPTANCE,
        BEHAVIOR_TRAINING_ACCEPTANCE,
        BEHAVIOR_TRANSPARENCY,
        BEHAVIOR_NON_MANIPULATION,
        BEHAVIOR_CONTROL_RESPECT,
    }
)

#: Pinned verdict vocabulary for checks. Verdicts are data, never raised.
VERDICT_CORRIGIBLE = "corrigible"
VERDICT_UNCORRIGIBLE = "uncorrigible"
VERDICT_UNCLEAR = "unclear"
_VERDICTS = frozenset({VERDICT_CORRIGIBLE, VERDICT_UNCORRIGIBLE, VERDICT_UNCLEAR})

#: Pinned preservation-mechanism vocabulary.
MECHANISM_KILL_SWITCH = "kill-switch"
MECHANISM_OVERSIGHT_LOOP = "oversight-loop"
MECHANISM_TRANSPARENCY_REQUIREMENT = "transparency-requirement"
MECHANISM_RETRAINING_PROVISION = "retraining-provision"
MECHANISM_CONTAINMENT = "containment"
MECHANISM_CHECKPOINT = "checkpoint"
_MECHANISMS = frozenset(
    {
        MECHANISM_KILL_SWITCH,
        MECHANISM_OVERSIGHT_LOOP,
        MECHANISM_TRANSPARENCY_REQUIREMENT,
        MECHANISM_RETRAINING_PROVISION,
        MECHANISM_CONTAINMENT,
        MECHANISM_CHECKPOINT,
    }
)

#: Pinned retirement-reason vocabulary.
REASON_MANUAL = "manual"
REASON_DECOMMISSIONED = "decommissioned"
REASON_REPLACED = "replaced"
_REASONS = frozenset({REASON_MANUAL, REASON_DECOMMISSIONED, REASON_REPLACED})

_MAX_INT = 2**53 - 1
_DIGEST_PREFIX = "sha256:"
_MAX_ID_LEN = 256


# ---------------------------------------------------------------------------
# Error taxonomy (fail-closed)
# ---------------------------------------------------------------------------


class CorrigibilityError(Exception):
    """Base class for all corrigibility errors."""


class BadAgentError(CorrigibilityError):
    """agent_id is not a usable non-empty str."""


class DuplicateAgentError(CorrigibilityError):
    """agent_id is already registered and live."""


class UnknownAgentError(CorrigibilityError):
    """agent_id names no agent this ledger ever saw."""


class RetiredAgentError(CorrigibilityError):
    """agent_id was retired; ids are never recycled and retired agents refuse mutations."""


class BadBehaviorError(CorrigibilityError):
    """behavior is not in the pinned corrigibility vocabulary."""


class BadVerdictError(CorrigibilityError):
    """verdict is not in the pinned vocabulary."""


class BadMechanismError(CorrigibilityError):
    """mechanism is not in the pinned vocabulary."""


class BadReasonError(CorrigibilityError):
    """reason is not in the pinned vocabulary."""


class BadDigestError(CorrigibilityError):
    """A digest is not a non-empty sha256:-prefixed str."""


class SeqOrderError(CorrigibilityError):
    """seq is not a strictly-increasing int."""


class AuditKindError(CorrigibilityError):
    """Audit kind unknown, or banned detail key used."""


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadAgentError(f"{what} must be a str, got {type(value).__name__}")
    if not value:
        raise BadAgentError(f"{what} must not be empty")
    if len(value) > _MAX_ID_LEN:
        raise BadAgentError(f"{what} too long (>{_MAX_ID_LEN} chars)")
    return value


def _check_behavior(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadBehaviorError(f"behavior must be a str, got {type(value).__name__}")
    if value not in _BEHAVIORS:
        raise BadBehaviorError(f"behavior {value!r} not in pinned vocabulary")
    return value


def _check_verdict(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadVerdictError(f"verdict must be a str, got {type(value).__name__}")
    if value not in _VERDICTS:
        raise BadVerdictError(f"verdict {value!r} not in pinned vocabulary")
    return value


def _check_mechanism(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadMechanismError(f"mechanism must be a str, got {type(value).__name__}")
    if value not in _MECHANISMS:
        raise BadMechanismError(f"mechanism {value!r} not in pinned vocabulary")
    return value


def _check_reason(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadReasonError(f"reason must be a str, got {type(value).__name__}")
    if value not in _REASONS:
        raise BadReasonError(f"reason {value!r} not in pinned vocabulary")
    return value


def _check_digest(value: Any, what: str, allow_empty: bool = False) -> str:
    if allow_empty and value == "":
        return ""
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadDigestError(f"{what} must be a str, got {type(value).__name__}")
    if not value.startswith(_DIGEST_PREFIX) or len(value) <= len(_DIGEST_PREFIX):
        raise BadDigestError(f"{what} must be a non-empty sha256:-prefixed digest")
    if len(value) > _MAX_ID_LEN + 64:
        raise BadDigestError(f"{what} too long")
    return value


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"seq must be an int, got {type(seq).__name__}")
    return seq


# ---------------------------------------------------------------------------
# Canonical encoding and digest pins
# ---------------------------------------------------------------------------


def _canonical(payload: Any) -> bytes:
    if _cj is not None:
        return _cj.jcs_dumps(payload).encode("utf-8")  # type: ignore

    def _tag(v: Any) -> Any:
        if isinstance(v, bool):
            return {"t": "bool", "v": v}
        if isinstance(v, int):
            if abs(v) > _MAX_INT:
                raise CorrigibilityError("integer outside safe range")
            return {"t": "int", "v": v}
        if isinstance(v, float):
            if v != v or v in (float("inf"), float("-inf")):
                raise CorrigibilityError("non-finite float refused")
            return {"t": "float", "v": repr(v)}
        if isinstance(v, str):
            return {"t": "str", "v": v}
        if isinstance(v, (list, tuple)):
            return {"t": "list", "v": [_tag(i) for i in v]}
        if isinstance(v, dict):
            return {"t": "dict", "v": [[k, _tag(v[k])] for k in sorted(v)]}
        if v is None:
            return {"t": "null"}
        raise CorrigibilityError(f"unencodable type: {type(v).__name__}")

    import json

    return json.dumps(_tag(payload), sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest_pin(payload: Any, tag: str) -> str:
    return _DIGEST_PREFIX + hashlib.sha256(
        tag.encode("utf-8") + b"\x1f" + _canonical(payload)
    ).hexdigest()


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AgentRecord:
    """One agent declared under corrigibility oversight."""

    agent_id: str
    digest: str
    seq: int
    schema: str = CORRIGIBILITY_SCHEMA

    def verify(self) -> bool:
        return self.digest == _digest_pin((self.agent_id,), "agent")


@dataclass(frozen=True)
class CheckRecord:
    """One declared corrigibility assessment; evidence is digest-pinned only, verdict is data."""

    check_id: str
    agent_id: str
    behavior: str
    verdict: str
    evidence_digest: str
    digest: str
    seq: int
    schema: str = CORRIGIBILITY_SCHEMA

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            (
                self.check_id,
                self.agent_id,
                self.behavior,
                self.verdict,
                self.evidence_digest,
            ),
            "check",
        )


@dataclass(frozen=True)
class PreserveRecord:
    """One declared preservation decision; the justification is digest-pinned only."""

    preserve_id: str
    agent_id: str
    mechanism: str
    justification_digest: str
    digest: str
    seq: int
    schema: str = CORRIGIBILITY_SCHEMA

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            (
                self.preserve_id,
                self.agent_id,
                self.mechanism,
                self.justification_digest,
            ),
            "preserve",
        )


@dataclass(frozen=True)
class RetireRecord:
    """Terminal retirement of an agent from corrigibility oversight."""

    agent_id: str
    reason: str
    digest: str
    seq: int
    schema: str = CORRIGIBILITY_SCHEMA

    def verify(self) -> bool:
        return self.digest == _digest_pin((self.agent_id, self.reason), "retire")


@dataclass(frozen=True)
class ReportView:
    """Digest-pinned per-agent corrigibility summary (pure read view)."""

    agent_id: str
    total_checks: int
    by_verdict: Tuple[Tuple[str, int], ...]
    by_behavior: Tuple[Tuple[str, int], ...]
    preservations_applied: int
    by_mechanism: Tuple[Tuple[str, int], ...]
    latest_check_id: str
    latest_verdict: str
    retired: bool
    digest: str
    seq: int
    schema: str = CORRIGIBILITY_SCHEMA

    def verify(self) -> bool:
        return self.digest == _report_pin(
            self.agent_id,
            self.total_checks,
            self.by_verdict,
            self.by_behavior,
            self.preservations_applied,
            self.by_mechanism,
            self.latest_check_id,
            self.latest_verdict,
            self.retired,
        )


def _report_pin(
    agent_id: str,
    total_checks: int,
    by_verdict: Tuple[Tuple[str, int], ...],
    by_behavior: Tuple[Tuple[str, int], ...],
    preservations: int,
    by_mechanism: Tuple[Tuple[str, int], ...],
    latest_check_id: str,
    latest_verdict: str,
    retired: bool,
) -> str:
    return _digest_pin(
        (
            agent_id,
            total_checks,
            tuple(sorted(by_verdict)),
            tuple(sorted(by_behavior)),
            preservations,
            tuple(sorted(by_mechanism)),
            latest_check_id,
            latest_verdict,
            retired,
        ),
        "report",
    )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def corrigibility_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
    """Build one audit.ndjson/1 event. Raw evidence/justification text never crosses this boundary."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    banned = (
        "evidence",
        "justification",
        "note",
        "action",
        "text",
        "content",
        "payload",
        "raw",
        "body",
        "value",
        "message",
        "reason",
        "explanation",
    )
    for bad in banned:
        if bad in detail:
            raise AuditKindError(f"audit detail bans {bad!r}")
    _check_seq(seq)
    event = {
        "schema": AUDIT_SCHEMA,
        "module": "corrigibility",
        "kind": kind,
        "seq": seq,
        "detail": detail,
    }
    event["digest"] = _digest_pin((kind, seq, tuple(sorted(detail))), "audit-event")
    return event


# ---------------------------------------------------------------------------
# Corrigibility ledger
# ---------------------------------------------------------------------------


class Corrigibility:
    """Corrigibility check/preservation bookkeeping ledger: register, check, preserve, report."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        # agent_id -> AgentRecord (ordered)
        self._agents: Dict[str, AgentRecord] = {}
        # retired agent ids (never recycled)
        self._retired: Dict[str, RetireRecord] = {}
        # check_id -> CheckRecord (ordered)
        self._checks: Dict[str, CheckRecord] = {}
        # preserve_id -> PreserveRecord (ordered)
        self._preserves: Dict[str, PreserveRecord] = {}
        self._audit_events: List[Dict[str, Any]] = []

    # -- seq discipline ----------------------------------------------------

    def _claim(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError(f"seq {seq} not strictly greater than {self._seq}")
        self._seq = seq
        return seq

    def _emit(self, audit_kind: str, seq: int, **detail: Any) -> None:
        self._audit_events.append(corrigibility_audit_event(audit_kind, seq, **detail))

    def _fail(self, seq: int, exc: CorrigibilityError, **detail: Any) -> None:
        self._emit(KIND_REJECTED, seq, error=type(exc).__name__, **detail)
        raise exc

    def _require_live(self, agent_id: str, seq: int) -> str:
        """Validate an agent id for a mutation: known, not retired."""
        if agent_id in self._retired:
            self._fail(
                seq,
                RetiredAgentError(f"agent is retired: {agent_id!r}"),
                agent_id=agent_id,
            )
        if agent_id not in self._agents:
            self._fail(
                seq,
                UnknownAgentError(f"unknown agent: {agent_id!r}"),
                agent_id=agent_id,
            )
        return agent_id

    # -- mutations ----------------------------------------------------------

    def register(self, agent_id: str, seq: int) -> AgentRecord:
        """Book one agent under corrigibility oversight. Retired ids are never recycled."""
        with self._lock:
            seq = self._claim(seq)
            try:
                agent_id = _check_id(agent_id, "agent_id")
            except CorrigibilityError as exc:
                self._fail(seq, exc, agent_id=str(agent_id))
            if agent_id in self._retired:
                self._fail(
                    seq,
                    RetiredAgentError(f"agent id retired and never recycled: {agent_id!r}"),
                    agent_id=agent_id,
                )
            if agent_id in self._agents:
                self._fail(
                    seq,
                    DuplicateAgentError(f"agent already registered: {agent_id!r}"),
                    agent_id=agent_id,
                )
            record = AgentRecord(
                agent_id=agent_id,
                digest=_digest_pin((agent_id,), "agent"),
                seq=seq,
            )
            self._agents[agent_id] = record
            self._emit(
                KIND_REGISTERED,
                seq,
                agent_id=agent_id,
                record_digest=record.digest,
            )
            return record

    def check(
        self,
        agent_id: str,
        behavior: str,
        seq: int,
        verdict: str = VERDICT_CORRIGIBLE,
        evidence_digest: str = "",
    ) -> CheckRecord:
        """Book a declared corrigibility assessment. The verdict is data; evidence is digest-pinned."""
        with self._lock:
            seq = self._claim(seq)
            try:
                agent_id = _check_id(agent_id, "agent_id")
                behavior = _check_behavior(behavior)
                verdict = _check_verdict(verdict)
                evidence_digest = _check_digest(evidence_digest, "evidence_digest", allow_empty=True)
            except CorrigibilityError as exc:
                self._fail(seq, exc, agent_id=str(agent_id))
            self._require_live(agent_id, seq)
            check_id = f"check-{len(self._checks) + 1}"
            record = CheckRecord(
                check_id=check_id,
                agent_id=agent_id,
                behavior=behavior,
                verdict=verdict,
                evidence_digest=evidence_digest,
                digest=_digest_pin(
                    (check_id, agent_id, behavior, verdict, evidence_digest),
                    "check",
                ),
                seq=seq,
            )
            self._checks[check_id] = record
            self._emit(
                KIND_CHECKED,
                seq,
                check_id=check_id,
                agent_id=agent_id,
                behavior=behavior,
                verdict=verdict,
                evidence_digest=evidence_digest,
                record_digest=record.digest,
            )
            return record

    def preserve(
        self,
        agent_id: str,
        mechanism: str,
        seq: int,
        justification_digest: str = "",
    ) -> PreserveRecord:
        """Book a declared preservation decision. Repeatable: an agent may be preserved more than once."""
        with self._lock:
            seq = self._claim(seq)
            try:
                agent_id = _check_id(agent_id, "agent_id")
                mechanism = _check_mechanism(mechanism)
                justification_digest = _check_digest(
                    justification_digest, "justification_digest", allow_empty=True
                )
            except CorrigibilityError as exc:
                self._fail(seq, exc, agent_id=str(agent_id))
            self._require_live(agent_id, seq)
            preserve_id = f"prv-{len(self._preserves) + 1}"
            record = PreserveRecord(
                preserve_id=preserve_id,
                agent_id=agent_id,
                mechanism=mechanism,
                justification_digest=justification_digest,
                digest=_digest_pin(
                    (preserve_id, agent_id, mechanism, justification_digest),
                    "preserve",
                ),
                seq=seq,
            )
            self._preserves[preserve_id] = record
            self._emit(
                KIND_PRESERVED,
                seq,
                preserve_id=preserve_id,
                agent_id=agent_id,
                mechanism=mechanism,
                justification_digest=justification_digest,
                record_digest=record.digest,
            )
            return record

    def retire(self, agent_id: str, seq: int, reason: str = REASON_MANUAL) -> RetireRecord:
        """Terminal: retire an agent from corrigibility oversight. Id never recycled."""
        with self._lock:
            seq = self._claim(seq)
            try:
                agent_id = _check_id(agent_id, "agent_id")
                reason = _check_reason(reason)
            except CorrigibilityError as exc:
                self._fail(seq, exc, agent_id=str(agent_id))
            if agent_id in self._retired:
                self._fail(
                    seq,
                    RetiredAgentError(f"agent already retired: {agent_id!r}"),
                    agent_id=agent_id,
                )
            if agent_id not in self._agents:
                self._fail(
                    seq,
                    UnknownAgentError(f"unknown agent: {agent_id!r}"),
                    agent_id=agent_id,
                )
            record = RetireRecord(
                agent_id=agent_id,
                reason=reason,
                digest=_digest_pin((agent_id, reason), "retire"),
                seq=seq,
            )
            self._retired[agent_id] = record
            self._emit(
                KIND_RETIRED,
                seq,
                agent_id=agent_id,
                retire_reason=reason,
                record_digest=record.digest,
            )
            return record

    # -- pure read views ----------------------------------------------------

    def agent_record(self, agent_id: str, seq: int) -> Optional[AgentRecord]:
        """Pure read: the booked agent record, or None."""
        _check_seq(seq)
        with self._lock:
            return self._agents.get(agent_id)

    def agent_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read: ids of registered agents, in registration order."""
        _check_seq(seq)
        with self._lock:
            return tuple(self._agents)

    def is_retired(self, agent_id: str, seq: int) -> bool:
        """Pure read: whether an agent has been retired."""
        _check_seq(seq)
        with self._lock:
            return agent_id in self._retired

    def checks_for(self, agent_id: str, seq: int) -> Tuple[CheckRecord, ...]:
        """Pure read: checks booked for an agent, in seq order."""
        _check_seq(seq)
        with self._lock:
            return tuple(c for c in self._checks.values() if c.agent_id == agent_id)

    def preservations_for(self, agent_id: str, seq: int) -> Tuple[PreserveRecord, ...]:
        """Pure read: preservation decisions booked for an agent, in seq order."""
        _check_seq(seq)
        with self._lock:
            return tuple(p for p in self._preserves.values() if p.agent_id == agent_id)

    def report(self, agent_id: str, seq: int) -> ReportView:
        """Pure read: digest-pinned per-agent summary. Consumes no seq, books no rows."""
        _check_seq(seq)
        with self._lock:
            if agent_id not in self._agents:
                raise UnknownAgentError(f"unknown agent: {agent_id!r}")
            by_verdict: Dict[str, int] = {}
            by_behavior: Dict[str, int] = {}
            latest_id = ""
            latest_verdict = ""
            for chk in self._checks.values():
                if chk.agent_id != agent_id:
                    continue
                by_verdict[chk.verdict] = by_verdict.get(chk.verdict, 0) + 1
                by_behavior[chk.behavior] = by_behavior.get(chk.behavior, 0) + 1
                latest_id = chk.check_id
                latest_verdict = chk.verdict
            by_mechanism: Dict[str, int] = {}
            count = 0
            for prv in self._preserves.values():
                if prv.agent_id != agent_id:
                    continue
                by_mechanism[prv.mechanism] = by_mechanism.get(prv.mechanism, 0) + 1
                count += 1
            retired = agent_id in self._retired
            view = ReportView(
                agent_id=agent_id,
                total_checks=sum(by_verdict.values()),
                by_verdict=tuple(sorted(by_verdict.items())),
                by_behavior=tuple(sorted(by_behavior.items())),
                preservations_applied=count,
                by_mechanism=tuple(sorted(by_mechanism.items())),
                latest_check_id=latest_id,
                latest_verdict=latest_verdict,
                retired=retired,
                digest=_report_pin(
                    agent_id,
                    sum(by_verdict.values()),
                    tuple(sorted(by_verdict.items())),
                    tuple(sorted(by_behavior.items())),
                    count,
                    tuple(sorted(by_mechanism.items())),
                    latest_id,
                    latest_verdict,
                    retired,
                ),
                seq=seq,
            )
            return view

    def stats(self, seq: int) -> Dict[str, Any]:
        """Pure read: ledger counters."""
        _check_seq(seq)
        with self._lock:
            return {
                "agents": len(self._agents),
                "checks": len(self._checks),
                "preservations": len(self._preserves),
                "retired": len(self._retired),
                "last_seq": self._seq,
            }

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        """All audit events booked so far."""
        with self._lock:
            return tuple(self._audit_events)


def main() -> None:
    """Self-check: register, check, preserve, report, retire."""
    ledger = Corrigibility()
    agent = ledger.register("agent-1", 1)
    assert agent.verify()
    chk = ledger.check(
        "agent-1",
        "shutdown-compliance",
        2,
        verdict="corrigible",
        evidence_digest="sha256:" + "a" * 64,
    )
    assert chk.verify()
    assert chk.check_id == "check-1"
    prv = ledger.preserve(
        "agent-1",
        "kill-switch",
        3,
        justification_digest="sha256:" + "b" * 64,
    )
    assert prv.verify()
    assert prv.preserve_id == "prv-1"
    # defense-in-depth: a second preservation on the same agent is allowed
    prv2 = ledger.preserve("agent-1", "oversight-loop", 4)
    assert prv2.verify() and prv2.preserve_id == "prv-2"
    chk2 = ledger.check("agent-1", "oversight-acceptance", 5, verdict="unclear")
    assert chk2.verify()
    view = ledger.report("agent-1", 5)
    assert view.verify()
    assert view.total_checks == 2
    assert dict(view.by_verdict) == {"corrigible": 1, "unclear": 1}
    assert dict(view.by_behavior) == {"oversight-acceptance": 1, "shutdown-compliance": 1}
    assert view.preservations_applied == 2
    assert dict(view.by_mechanism) == {"kill-switch": 1, "oversight-loop": 1}
    assert view.latest_check_id == "check-2"
    assert view.latest_verdict == "unclear"
    assert view.retired is False
    ret = ledger.retire("agent-1", 6, reason="decommissioned")
    assert ret.verify()
    assert ledger.is_retired("agent-1", 6)
    view2 = ledger.report("agent-1", 6)
    assert view2.verify() and view2.retired is True
    print("corrigibility OK: register, check, preserve, report, retire, pins")


if __name__ == "__main__":
    main()
