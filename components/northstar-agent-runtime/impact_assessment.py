"""AI Impact Assessment (AIA) lifecycle decision ledger.

Distinct from siblings: ``risk_assessment`` scores risk factors for
individual risks; ``compliance.py`` owns the framework control
check-remediate-attest cycle; ``ai_act.py`` classifies systems under the
EU AI Act; and ``model_card.py``/``system_card.py`` document model/system
factsheets. This module is the *impact-assessment* workflow layer none
of them own - it books declared assessment scopes, declared impact
evaluations across pinned impact domains, and declared mitigation
decisions as a deterministic single-host decision ledger.

* **Scoping** - ``scope()`` declares one assessment scope for a system:
  deployment context, affected groups, and impact domains to assess.
  Duplicates and retired ids refused fail-closed.
* **Evaluation** - ``evaluate()`` books one declared impact evaluation
  (minted ``evl-N``) against a live scope: an impact domain pinned to
  the vocabulary (``fairness`` / ``safety`` / ``privacy`` /
  ``security`` / ``labor`` / ``environment`` / ``autonomy`` /
  ``accessibility``) plus a host-declared severity (``low`` /
  ``medium`` / ``high`` / ``critical``), booked as data.
* **Mitigation** - ``mitigate()`` books one declared mitigation
  (minted ``mit-N``) over the pinned strategy vocabulary (``avoid`` /
  ``reduce`` / ``transfer`` / ``accept`` / ``monitor``); refused
  fail-closed on unassessed scopes and on closed (retired) systems.
  Repeatable as a decision chain.
* **Reporting** - ``report()`` is a pure read view deriving a frozen
  ``ImpactReport``: severity tallies, open impacts, mitigation counts,
  and an ``acceptable`` posture as data - never proof of real-world
  acceptability.

Design (deterministic single-host ledger):
1. Frozen dataclasses, caller int seqs strictly increasing
   (claim-then-burn: failed mutations consume their seq + book
   ``impact-assessment.rejected``; rewinds raise bare), no wall-clock,
   RLock-guarded, fail-closed taxonomy.
2. stdlib-only + the single ``canonical_json`` try/except fallback;
   ``sha256:`` digest pins with ``verify()``; ``audit.ndjson/1``
   events; version pin ``impact-assessment.v1``; schema pin
   ``northstar.impact-assessment.v1``.

Honest scope:
- This module books *declared* impact-assessment decisions - it runs
  no evaluation, measures no real-world impact, and remediates nothing.
- A booked ``critical`` evaluation means "the host declared a severe
  impact", never "the impact exists". A booked mitigation means "the
  host declared an action", never "the impact was reduced".
- An ``acceptable`` report means the ledger's booked records satisfy
  the ledger rule (no unmitigated high/critical impacts), never that
  the system is safe or lawful.
- Digest pins prove ledger integrity and ordering, never the truth of
  the declared decisions.
- No persistence: the ledger is in-memory.
"""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


VERSION = "impact-assessment.v1"
SCHEMA = "northstar.impact-assessment.v1"

KIND_SCOPED = "scoped"
KIND_EVALUATED = "evaluated"
KIND_MITIGATED = "mitigated"
KIND_RETIRED = "retired"
KIND_REJECTED = "impact-assessment.rejected"

_IMPACT_DOMAINS = frozenset({
    "fairness", "safety", "privacy", "security", "labor",
    "environment", "autonomy", "accessibility",
})
_SEVERITIES = ("low", "medium", "high", "critical")
_STRATEGIES = frozenset({"avoid", "reduce", "transfer", "accept", "monitor"})
_AUDIT_KINDS = frozenset(
    {KIND_SCOPED, KIND_EVALUATED, KIND_MITIGATED, KIND_RETIRED, KIND_REJECTED})
_BANNED_AUDIT_KEYS = frozenset({
    "description", "rationale", "notes", "summary", "findings",
    "evidence", "details", "content", "text", "justification",
    "affected", "group", "impact", "harm", "scenario",
})

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


class ImpactAssessmentError(Exception):
    """Base error for impact-assessment ledger misuse."""


class BadIdError(ImpactAssessmentError):
    """system_id / scope_id malformed or wrong type."""


class DuplicateScopeError(ImpactAssessmentError):
    """system already has a live scope."""


class UnknownSystemError(ImpactAssessmentError):
    """system has no live scope."""


class RetiredSystemError(ImpactAssessmentError):
    """system was retired; ids are never recycled."""


class BadDomainError(ImpactAssessmentError):
    """impact domain outside the pinned vocabulary."""


class BadSeverityError(ImpactAssessmentError):
    """severity outside the pinned vocabulary."""


class BadStrategyError(ImpactAssessmentError):
    """mitigation strategy outside the pinned vocabulary."""


class BadDigestError(ImpactAssessmentError):
    """digest pin malformed (must be ``sha256:<64hex>`` or empty)."""


class UnknownEvaluationError(ImpactAssessmentError):
    """evaluation id unknown."""


class AlreadyMitigatedError(ImpactAssessmentError):
    """evaluation already has a booked mitigation."""


class SeqOrderError(ImpactAssessmentError):
    """seq not strictly increasing."""


class AuditKindError(ImpactAssessmentError):
    """unknown audit kind."""


def _check_seq(seq: object) -> int:
    """Validate seq is a strictly-positive int (bool refused)."""
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
        raise SeqOrderError(f"seq must be a positive int, got {seq!r}")
    return seq


def _check_id(value: object, name: str) -> str:
    """Validate an identifier string."""
    if not isinstance(value, str) or not _ID_RE.match(value):
        raise BadIdError(f"{name} must match [A-Za-z0-9][A-Za-z0-9._:-]{{0,63}}, got {value!r}")
    return value


def _check_digest(value: object, name: str) -> str:
    """Validate a ``sha256:<64hex>`` pin or the empty pin."""
    if not isinstance(value, str):
        raise BadDigestError(f"{name} must be a sha256 pin or '', got {value!r}")
    if value == "":
        return value
    body = value[len("sha256:"):] if value.startswith("sha256:") else value
    if not _HEX64_RE.match(body):
        raise BadDigestError(f"{name} must be 'sha256:<64hex>' or '', got {value!r}")
    return "sha256:" + body


def _record_digest(kind: str, payload: Dict[str, Any]) -> str:
    """Deterministic digest pin for a record."""
    return "sha256:" + jcs_sha256_hex({"kind": kind, "v": VERSION, **payload})


def impact_assessment_audit_event(audit_kind: str,
                                 detail: Dict[str, Any],
                                 seq: int) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event for this module.

    Raw free-text keys are banned from the audit boundary (exact-key
    match) so declared narrative content can never leak into the
    audit log; pinned vocabulary values remain emittable as data.
    """
    if audit_kind not in _AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {audit_kind!r}")
    if not isinstance(detail, dict):
        raise AuditKindError("detail must be a dict")
    leaked = _BANNED_AUDIT_KEYS.intersection(detail.keys())
    if leaked:
        raise AuditKindError(f"audit detail leaks raw content: {sorted(leaked)}")
    return {
        "audit": "audit.ndjson/1",
        "kind": audit_kind,
        "seq": seq,
        "detail": dict(detail),
    }


@dataclass(frozen=True)
class ScopeRecord:
    """Declared assessment scope for one system."""
    system_id: str
    context: str
    domains: Tuple[str, ...]
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "system_id": self.system_id,
            "context": self.context,
            "domains": list(self.domains),
            "digest": self.digest,
        }

    def verify(self) -> bool:
        expect = _record_digest("scope", {
            "system_id": self.system_id,
            "context": self.context,
            "domains": list(self.domains),
        })
        return expect == self.digest


@dataclass(frozen=True)
class EvaluationRecord:
    """One declared impact evaluation (minted ``evl-N``)."""
    evaluation_id: str
    system_id: str
    domain: str
    severity: str
    evidence_pin: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "evaluation_id": self.evaluation_id,
            "system_id": self.system_id,
            "domain": self.domain,
            "severity": self.severity,
            "evidence_pin": self.evidence_pin,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        expect = _record_digest("evaluation", {
            "evaluation_id": self.evaluation_id,
            "system_id": self.system_id,
            "domain": self.domain,
            "severity": self.severity,
            "evidence_pin": self.evidence_pin,
        })
        return expect == self.digest


@dataclass(frozen=True)
class MitigationRecord:
    """One declared mitigation decision (minted ``mit-N``)."""
    mitigation_id: str
    evaluation_id: str
    system_id: str
    strategy: str
    plan_pin: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "mitigation_id": self.mitigation_id,
            "evaluation_id": self.evaluation_id,
            "system_id": self.system_id,
            "strategy": self.strategy,
            "plan_pin": self.plan_pin,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        expect = _record_digest("mitigation", {
            "mitigation_id": self.mitigation_id,
            "evaluation_id": self.evaluation_id,
            "system_id": self.system_id,
            "strategy": self.strategy,
            "plan_pin": self.plan_pin,
        })
        return expect == self.digest


@dataclass(frozen=True)
class ImpactReport:
    """Derived posture for one system (pure read view)."""
    system_id: str
    n_evaluations: int
    severities: Tuple[Tuple[str, int], ...]
    open_high_impacts: int
    mitigated_ids: Tuple[str, ...]
    acceptable: bool
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "system_id": self.system_id,
            "n_evaluations": self.n_evaluations,
            "severities": [
                {"severity": s, "count": c} for s, c in self.severities],
            "open_high_impacts": self.open_high_impacts,
            "mitigated_ids": list(self.mitigated_ids),
            "acceptable": self.acceptable,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        expect = _record_digest("report", {
            "system_id": self.system_id,
            "n_evaluations": self.n_evaluations,
            "severities": [
                {"severity": s, "count": c} for s, c in self.severities],
            "open_high_impacts": self.open_high_impacts,
            "mitigated_ids": list(self.mitigated_ids),
            "acceptable": self.acceptable,
        })
        return expect == self.digest


@dataclass(frozen=True)
class RetireRecord:
    """Terminal retirement of one system's assessment lifecycle."""
    system_id: str
    reason: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "system_id": self.system_id,
            "reason": self.reason,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        expect = _record_digest("retire", {
            "system_id": self.system_id,
            "reason": self.reason,
        })
        return expect == self.digest


_RETIRE_REASONS = frozenset({"manual", "superseded", "withdrawn", "invalidated"})


class ImpactAssessment:
    """AI Impact Assessment lifecycle decision ledger."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._scopes: Dict[str, ScopeRecord] = {}
        self._evaluations: Dict[str, EvaluationRecord] = {}
        self._mitigations: Dict[str, MitigationRecord] = {}
        self._mitigation_for: Dict[str, str] = {}  # evaluation_id -> mitigation_id
        self._retired: Dict[str, RetireRecord] = {}
        self._evl_counter = 0
        self._mit_counter = 0
        self._audit: List[Dict[str, Any]] = []
        self._rejected = 0

    # -- internal helpers -------------------------------------------------

    def _claim_seq(self, seq_v: int) -> None:
        """Claim a strictly increasing seq; rewinds raise bare."""
        if seq_v <= self._seq:
            raise SeqOrderError(
                f"seq must be strictly increasing, got {seq_v} after {self._seq}")
        self._seq = seq_v

    def _burn(self, seq_v: int, method: str, exc: ImpactAssessmentError) -> None:
        """Book a failed mutation: seq consumed, rejected row appended."""
        self._rejected += 1
        self._audit.append(impact_assessment_audit_event(
            KIND_REJECTED,
            {"method": method, "error": type(exc).__name__,
             "error_detail": str(exc)},
            seq_v))

    def _emit(self, audit_kind: str, detail: Dict[str, Any], seq_v: int) -> None:
        self._audit.append(impact_assessment_audit_event(audit_kind, detail, seq_v))

    def _check_live(self, system_id: str) -> ScopeRecord:
        if system_id in self._retired:
            raise RetiredSystemError(f"system retired: {system_id!r}")
        if system_id not in self._scopes:
            raise UnknownSystemError(f"system has no live scope: {system_id!r}")
        return self._scopes[system_id]

    # -- mutations --------------------------------------------------------

    def scope(self, system_id: object, context: object, domains: object,
              seq: object, scope_digest: object = "") -> ScopeRecord:
        """Declare one assessment scope for a system."""
        with self._lock:
            seq_v = _check_seq(seq)
            self._claim_seq(seq_v)
            try:
                sid = _check_id(system_id, "system_id")
                if sid in self._retired:
                    raise RetiredSystemError(f"system retired: {sid!r}")
                if sid in self._scopes:
                    raise DuplicateScopeError(f"system already scoped: {sid!r}")
                if not isinstance(context, str) or not context.strip() \
                        or len(context) > 128:
                    raise BadIdError(f"context must be a 1..128-char string, got {context!r}")
                if not isinstance(domains, (tuple, list)) or not domains:
                    raise BadDomainError("domains must be a non-empty sequence")
                dom_list = []
                for d in domains:
                    if not isinstance(d, str) or d not in _IMPACT_DOMAINS:
                        raise BadDomainError(
                            f"domain must be one of {sorted(_IMPACT_DOMAINS)}, got {d!r}")
                    if d not in dom_list:
                        dom_list.append(d)
                _check_digest(scope_digest, "scope_digest")
                rec = ScopeRecord(
                    system_id=sid, context=context.strip(),
                    domains=tuple(dom_list),
                    digest=_record_digest("scope", {
                        "system_id": sid,
                        "context": context.strip(),
                        "domains": dom_list}))
                self._scopes[sid] = rec
                self._emit(KIND_SCOPED,
                           {"system_id": sid, "context": context.strip(),
                            "domains": dom_list},
                           seq_v)
                return rec
            except ImpactAssessmentError as exc:
                self._burn(seq_v, "scope", exc)
                raise

    def evaluate(self, system_id: object, domain: object, severity: object,
                 seq: object, evidence_digest: object = "") -> EvaluationRecord:
        """Book one declared impact evaluation (minted ``evl-N``)."""
        with self._lock:
            seq_v = _check_seq(seq)
            self._claim_seq(seq_v)
            try:
                sid = _check_id(system_id, "system_id")
                scope = self._check_live(sid)
                if not isinstance(domain, str) or domain not in _IMPACT_DOMAINS:
                    raise BadDomainError(
                        f"domain must be one of {sorted(_IMPACT_DOMAINS)}, got {domain!r}")
                if domain not in scope.domains:
                    raise BadDomainError(
                        f"domain {domain!r} not in scope {sorted(scope.domains)!r}")
                if not isinstance(severity, str) or severity not in _SEVERITIES:
                    raise BadSeverityError(
                        f"severity must be one of {_SEVERITIES}, got {severity!r}")
                pin = _check_digest(evidence_digest, "evidence_digest")
                self._evl_counter += 1
                eid = f"evl-{self._evl_counter}"
                rec = EvaluationRecord(
                    evaluation_id=eid, system_id=sid, domain=domain,
                    severity=severity, evidence_pin=pin,
                    digest=_record_digest("evaluation", {
                        "evaluation_id": eid, "system_id": sid,
                        "domain": domain, "severity": severity,
                        "evidence_pin": pin}))
                self._evaluations[eid] = rec
                self._emit(KIND_EVALUATED,
                           {"evaluation_id": eid, "system_id": sid,
                            "domain": domain, "severity": severity},
                           seq_v)
                return rec
            except ImpactAssessmentError as exc:
                self._burn(seq_v, "evaluate", exc)
                raise

    def mitigate(self, evaluation_id: object, strategy: object, seq: object,
                 plan_digest: object = "") -> MitigationRecord:
        """Book one declared mitigation decision (minted ``mit-N``)."""
        with self._lock:
            seq_v = _check_seq(seq)
            self._claim_seq(seq_v)
            try:
                evid = _check_id(evaluation_id, "evaluation_id")
                if evid not in self._evaluations:
                    raise UnknownEvaluationError(
                        f"unknown evaluation: {evid!r}")
                ev = self._evaluations[evid]
                if ev.system_id in self._retired:
                    raise RetiredSystemError(
                        f"system retired: {ev.system_id!r}")
                if not isinstance(strategy, str) or strategy not in _STRATEGIES:
                    raise BadStrategyError(
                        f"strategy must be one of {sorted(_STRATEGIES)}, got {strategy!r}")
                if evid in self._mitigation_for:
                    raise AlreadyMitigatedError(
                        f"evaluation already mitigated: {evid!r}")
                pin = _check_digest(plan_digest, "plan_digest")
                self._mit_counter += 1
                mid = f"mit-{self._mit_counter}"
                rec = MitigationRecord(
                    mitigation_id=mid, evaluation_id=evid,
                    system_id=ev.system_id, strategy=strategy,
                    plan_pin=pin,
                    digest=_record_digest("mitigation", {
                        "mitigation_id": mid, "evaluation_id": evid,
                        "system_id": ev.system_id, "strategy": strategy,
                        "plan_pin": pin}))
                self._mitigations[mid] = rec
                self._mitigation_for[evid] = mid
                self._emit(KIND_MITIGATED,
                           {"mitigation_id": mid, "evaluation_id": evid,
                            "system_id": ev.system_id, "strategy": strategy},
                           seq_v)
                return rec
            except ImpactAssessmentError as exc:
                self._burn(seq_v, "mitigate", exc)
                raise

    def retire(self, system_id: object, seq: object,
               reason: object = "manual") -> RetireRecord:
        """Terminally retire one system's assessment lifecycle."""
        with self._lock:
            seq_v = _check_seq(seq)
            self._claim_seq(seq_v)
            try:
                sid = _check_id(system_id, "system_id")
                if sid in self._retired:
                    raise RetiredSystemError(f"system retired: {sid!r}")
                if sid not in self._scopes:
                    raise UnknownSystemError(
                        f"system has no live scope: {sid!r}")
                if not isinstance(reason, str) or reason not in _RETIRE_REASONS:
                    raise BadIdError(
                        f"reason must be one of {sorted(_RETIRE_REASONS)}, got {reason!r}")
                rec = RetireRecord(
                    system_id=sid, reason=reason,
                    digest=_record_digest("retire", {
                        "system_id": sid, "reason": reason}))
                self._retired[sid] = rec
                self._emit(KIND_RETIRED,
                           {"system_id": sid, "reason": reason},
                           seq_v)
                return rec
            except ImpactAssessmentError as exc:
                self._burn(seq_v, "retire", exc)
                raise

    # -- pure-read views ---------------------------------------------------

    def report(self, system_id: object, seq: object) -> ImpactReport:
        """Derive an impact report for one system (pure read).

        Ledger rule: ``acceptable`` iff at least one evaluation is
        booked and every high/critical impact has a booked mitigation.
        """
        with self._lock:
            seq_v = _check_seq(seq)
            sid = _check_id(system_id, "system_id")
            if sid in self._retired:
                raise RetiredSystemError(f"system retired: {sid!r}")
            if sid not in self._scopes:
                raise UnknownSystemError(
                    f"system has no live scope: {sid!r}")
            relevant = [e for e in self._evaluations.values()
                        if e.system_id == sid]
            tally: Dict[str, int] = {}
            open_high = 0
            mitigated: List[str] = []
            for e in relevant:
                tally[e.severity] = tally.get(e.severity, 0) + 1
                if e.evaluation_id in self._mitigation_for:
                    mitigated.append(e.evaluation_id)
                elif e.severity in ("high", "critical"):
                    open_high += 1
            severities = tuple(sorted(tally.items()))
            mitigated_t = tuple(sorted(mitigated))
            acceptable = bool(relevant) and open_high == 0
            report = ImpactReport(
                system_id=sid, n_evaluations=len(relevant),
                severities=severities, open_high_impacts=open_high,
                mitigated_ids=mitigated_t, acceptable=acceptable,
                digest=_record_digest("report", {
                    "system_id": sid, "n_evaluations": len(relevant),
                    "severities": [
                        {"severity": s, "count": c}
                        for s, c in severities],
                    "open_high_impacts": open_high,
                    "mitigated_ids": sorted(mitigated),
                    "acceptable": acceptable}))
            _ = seq_v  # seq shape validated, never consumed
            return report

    def scope_record(self, system_id: object, seq: object) -> ScopeRecord:
        """Return one scope record (pure read)."""
        with self._lock:
            _check_seq(seq)
            sid = _check_id(system_id, "system_id")
            if sid not in self._scopes:
                raise UnknownSystemError(
                    f"system has no live scope: {sid!r}")
            return self._scopes[sid]

    def evaluation_record(self, evaluation_id: object,
                          seq: object) -> EvaluationRecord:
        """Return one evaluation record (pure read)."""
        with self._lock:
            _check_seq(seq)
            eid = _check_id(evaluation_id, "evaluation_id")
            if eid not in self._evaluations:
                raise UnknownEvaluationError(f"unknown evaluation: {eid!r}")
            return self._evaluations[eid]

    def mitigation_record(self, mitigation_id: object,
                          seq: object) -> MitigationRecord:
        """Return one mitigation record (pure read)."""
        with self._lock:
            _check_seq(seq)
            mid = _check_id(mitigation_id, "mitigation_id")
            if mid not in self._mitigations:
                raise UnknownEvaluationError(f"unknown mitigation: {mid!r}")
            return self._mitigations[mid]

    def system_ids(self, seq: object) -> Tuple[str, ...]:
        """All scoped system ids in scope order."""
        with self._lock:
            _check_seq(seq)
            return tuple(self._scopes.keys())

    def evaluations_for(self, system_id: object,
                        seq: object) -> Tuple[str, ...]:
        """Evaluation ids booked for one system (mint order)."""
        with self._lock:
            _check_seq(seq)
            sid = _check_id(system_id, "system_id")
            if sid not in self._scopes:
                raise UnknownSystemError(
                    f"system has no live scope: {sid!r}")
            return tuple(e.evaluation_id
                         for e in self._evaluations.values()
                         if e.system_id == sid)

    def mitigations_for(self, evaluation_id: object,
                        seq: object) -> Tuple[str, ...]:
        """Mitigation ids booked for one evaluation."""
        with self._lock:
            _check_seq(seq)
            eid = _check_id(evaluation_id, "evaluation_id")
            if eid not in self._evaluations:
                raise UnknownEvaluationError(f"unknown evaluation: {eid!r}")
            mid = self._mitigation_for.get(eid)
            return (mid,) if mid else ()

    def retired_ids(self, seq: object) -> Tuple[str, ...]:
        """All retired system ids (retire order)."""
        with self._lock:
            _check_seq(seq)
            return tuple(self._retired.keys())

    def audit_log(self, seq: object) -> Tuple[Dict[str, Any], ...]:
        """All audit rows so far (pure read)."""
        with self._lock:
            _check_seq(seq)
            return tuple(self._audit)

    def stats(self, seq: object) -> Dict[str, int]:
        """Ledger counters (pure read)."""
        with self._lock:
            _check_seq(seq)
            return {
                "scopes": len(self._scopes),
                "evaluations": len(self._evaluations),
                "mitigations": len(self._mitigations),
                "retired": len(self._retired),
                "rejected": self._rejected,
            }


def main() -> None:
    """Self-check: exercise the ledger end to end."""
    a = ImpactAssessment()
    a.scope("sys-1", "candidate-screening", ("fairness", "privacy"), 1)
    e1 = a.evaluate("sys-1", "fairness", "high", 2)
    a.evaluate("sys-1", "privacy", "low", 3)
    a.mitigate(e1.evaluation_id, "reduce", 4)
    rep = a.report("sys-1", 5)
    assert rep.verify()
    assert rep.acceptable is True
    assert rep.n_evaluations == 2
    assert a.stats(6) == {"scopes": 1, "evaluations": 2,
                          "mitigations": 1, "retired": 0, "rejected": 0}
    print("impact-assessment OK: scope, evaluate, mitigate, report, pins, audit")


if __name__ == "__main__":
    main()
