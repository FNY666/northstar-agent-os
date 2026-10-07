"""ResponsibleAI: responsible-AI governance decision ledger for agent systems.

Research note: responsible-AI practice (OECD AI Principles; EU AI Act
risk-based duties; NIST AI RMF functions Govern/Map/Measure/Manage)
decomposes governance into *assess* (judging a system against named
responsible-AI dimensions), *verify* (checking the integrity of a
booked assessment), and *evaluate* (deriving a ledger-level posture
from booked assessments). This module is the *ledger* layer for that
practice:

* **assess()** books one declared responsible-AI assessment against a
  pinned 8-term dimension vocabulary (safety / fairness / privacy /
  transparency / accountability / human-oversight / robustness /
  sustainability) and a pinned 6-term finding vocabulary
  (meets-requirements / gap-identified / noncompliant / mitigated /
  in-progress / not-assessed). Findings are booked as data, never
  proof. Assessment ids are minted (``asm-N``). The raw assessment
  material (criteria, evidence, rationale) travels as digest pins only
  and never enters records.
* **verify()** is a *pure read*: it re-derives the digest pin of a
  booked assessment and returns a ``VerificationReport`` whose verdict
  is ``verified`` or ``tampered`` as data (tamper is reported, never
  raised). It validates seq shape, consumes nothing, and books no
  audit rows.
* **evaluate()** is a *pure read*: a digest-pinned ``EvaluationReport``
  deriving posture as data by ledger rule -- ``unassessed`` (nothing
  booked, or all findings ``not-assessed``) -> ``noncompliant`` (any
  ``noncompliant``) -> ``gap-open`` (any ``gap-identified``) ->
  ``in-progress`` (any ``in-progress``) -> ``meets-requirements``
  (all other findings ``meets-requirements`` / ``mitigated``) -- plus
  per-dimension and per-finding tallies and ``integrity_ok`` (re-derived
  as data). It validates seq shape, consumes nothing, and books no
  audit rows. Scoped to one system, or to the whole ledger.

House style throughout: frozen dataclasses, caller-supplied
strictly-increasing int seqs (failed mutations consume the seq and
book a ``rejected`` audit row; rewinds raise bare), no wall-clock,
RLock guarding, fail-closed taxonomy, stdlib-only with the standard
``canonical_json`` try/except fallback, ``sha256:`` digest pins, and
``audit.ndjson/1`` events.

Honest scope: the module books *declared* assessments, *declared*
verifications, and *derived* postures; it cannot prove a system is
really safe, fair, or compliant. Raw criteria/evidence/rationale text
never enters records and never crosses the audit boundary (digest
pins only).
"""

from __future__ import annotations

import ast
import hashlib
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    _cj = None  # type: ignore

#: Version pin for this module's record shape.
RESPONSIBLE_AI_VERSION = "responsible-ai.v1"

#: Schema pin carried by records and audit events.
RESPONSIBLE_AI_SCHEMA = "northstar.responsible-ai.v1"

#: Wire format of audit records.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Fixed vocabulary for audit event kinds.
KIND_ASSESSED = "responsible-ai.assessed"
KIND_REJECTED = "responsible-ai.rejected"
_KINDS = frozenset({KIND_ASSESSED, KIND_REJECTED})

#: Pinned dimension vocabulary (OECD / EU AI Act / NIST AI RMF shaped).
DIM_SAFETY = "safety"
DIM_FAIRNESS = "fairness"
DIM_PRIVACY = "privacy"
DIM_TRANSPARENCY = "transparency"
DIM_ACCOUNTABILITY = "accountability"
DIM_HUMAN_OVERSIGHT = "human-oversight"
DIM_ROBUSTNESS = "robustness"
DIM_SUSTAINABILITY = "sustainability"
_DIMENSIONS = frozenset(
    {
        DIM_SAFETY,
        DIM_FAIRNESS,
        DIM_PRIVACY,
        DIM_TRANSPARENCY,
        DIM_ACCOUNTABILITY,
        DIM_HUMAN_OVERSIGHT,
        DIM_ROBUSTNESS,
        DIM_SUSTAINABILITY,
    }
)

#: Pinned finding vocabulary. Findings are data, never proof.
FINDING_MEETS = "meets-requirements"
FINDING_GAP = "gap-identified"
FINDING_NONCOMPLIANT = "noncompliant"
FINDING_MITIGATED = "mitigated"
FINDING_IN_PROGRESS = "in-progress"
FINDING_NOT_ASSESSED = "not-assessed"
_FINDINGS = frozenset(
    {
        FINDING_MEETS,
        FINDING_GAP,
        FINDING_NONCOMPLIANT,
        FINDING_MITIGATED,
        FINDING_IN_PROGRESS,
        FINDING_NOT_ASSESSED,
    }
)

#: Pinned posture vocabulary (ledger-rule derivation order: top outranks below).
POSTURE_UNASSESSED = "unassessed"
POSTURE_NONCOMPLIANT = "noncompliant"
POSTURE_GAP_OPEN = "gap-open"
POSTURE_IN_PROGRESS = "in-progress"
POSTURE_MEETS = "meets-requirements"

#: Pinned verify verdicts (reported as data, never raised).
VERDICT_VERIFIED = "verified"
VERDICT_TAMPERED = "tampered"

_DIGEST_PREFIX = "sha256:"
_MAX_ID_LEN = 256
_MAX_INT = 2**53 - 1


# ---------------------------------------------------------------------------
# Error taxonomy (fail-closed)
# ---------------------------------------------------------------------------


class ResponsibleAIError(Exception):
    """Base class for all responsible-AI errors."""


class BadSystemError(ResponsibleAIError):
    """A system id is not a usable non-empty str."""


class BadDimensionError(ResponsibleAIError):
    """dimension is not in the pinned vocabulary."""


class BadFindingError(ResponsibleAIError):
    """finding is not in the pinned vocabulary."""


class BadDigestError(ResponsibleAIError):
    """A digest is not a non-empty sha256:-prefixed str."""


class UnknownSystemError(ResponsibleAIError):
    """system_id names no system this ledger ever saw."""


class UnknownAssessmentError(ResponsibleAIError):
    """assessment_id names no assessment this ledger ever saw."""


class SeqOrderError(ResponsibleAIError):
    """seq is not a usable int, or not strictly increasing for mutations."""


class AuditKindError(ResponsibleAIError):
    """Audit kind unknown, or banned detail key used."""


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadSystemError(f"{what} must be a str, got {type(value).__name__}")
    if not value:
        raise BadSystemError(f"{what} must not be empty")
    if len(value) > _MAX_ID_LEN:
        raise BadSystemError(f"{what} too long (>{_MAX_ID_LEN} chars)")
    return value


def _check_dimension(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadDimensionError(f"dimension must be a str, got {type(value).__name__}")
    if value not in _DIMENSIONS:
        raise BadDimensionError(f"dimension {value!r} not in pinned vocabulary")
    return value


def _check_finding(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadFindingError(f"finding must be a str, got {type(value).__name__}")
    if value not in _FINDINGS:
        raise BadFindingError(f"finding {value!r} not in pinned vocabulary")
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
        result = _cj.jcs_dumps(payload)  # type: ignore
        return result.encode("utf-8") if isinstance(result, str) else bytes(result)

    def _tag(v: Any) -> Any:
        if isinstance(v, bool):
            return {"t": "bool", "v": v}
        if isinstance(v, int):
            if abs(v) > _MAX_INT:
                raise ResponsibleAIError("integer outside safe range")
            return {"t": "int", "v": v}
        if isinstance(v, float):
            if v != v or v in (float("inf"), float("-inf")):
                raise ResponsibleAIError("non-finite float refused")
            return {"t": "float", "v": repr(v)}
        if isinstance(v, str):
            return {"t": "str", "v": v}
        if isinstance(v, (list, tuple)):
            return {"t": "list", "v": [_tag(i) for i in v]}
        if isinstance(v, dict):
            return {"t": "dict", "v": [[k, _tag(v[k])] for k in sorted(v)]}
        if v is None:
            return {"t": "null"}
        raise ResponsibleAIError(f"unencodable type: {type(v).__name__}")

    import json

    return json.dumps(_tag(payload), sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest_pin(payload: Any, tag: str) -> str:
    return _DIGEST_PREFIX + hashlib.sha256(
        tag.encode("utf-8") + b"\x1f" + _canonical(payload)
    ).hexdigest()


def stdlib_only() -> bool:
    """AST self-check: the module imports only the stdlib (+ canonical_json)."""
    allowed = {
        "__future__",
        "ast",
        "canonical_json",
        "dataclasses",
        "hashlib",
        "json",
        "pathlib",
        "threading",
        "typing",
    }
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    raise ResponsibleAIError(f"non-stdlib import: {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] not in allowed:
                raise ResponsibleAIError(f"non-stdlib import: {node.module}")
    return True


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AssessmentRecord:
    """One declared responsible-AI assessment; raw material is digest-pinned."""

    assessment_id: str
    system_id: str
    dimension: str
    finding: str
    assessment_digest: str
    digest: str
    seq: int
    schema: str = RESPONSIBLE_AI_SCHEMA

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            (
                self.assessment_id,
                self.system_id,
                self.dimension,
                self.finding,
                self.assessment_digest,
            ),
            "assessment",
        )


@dataclass(frozen=True)
class VerificationReport:
    """Pure-read digest re-derivation of one booked assessment."""

    assessment_id: str
    verdict: str  # verified | tampered, as data
    digest: str
    seq: int
    schema: str = RESPONSIBLE_AI_SCHEMA

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            (self.assessment_id, self.verdict),
            "verification-report",
        )


@dataclass(frozen=True)
class EvaluationReport:
    """Pure-read posture derivation over booked assessments (data, never proof)."""

    system_scope: str  # "" = whole ledger
    posture: str
    n_assessments: int
    by_dimension: Tuple[Tuple[str, int], ...]
    by_finding: Tuple[Tuple[str, int], ...]
    integrity_ok: bool
    digest: str
    seq: int
    schema: str = RESPONSIBLE_AI_SCHEMA

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            (
                self.system_scope,
                self.posture,
                self.n_assessments,
                tuple(sorted(self.by_dimension)),
                tuple(sorted(self.by_finding)),
                self.integrity_ok,
            ),
            "evaluation-report",
        )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def responsible_ai_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
    """Build one audit.ndjson/1 event. Raw assessment text never crosses this boundary."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    banned = (
        "title",
        "description",
        "action",
        "text",
        "content",
        "payload",
        "raw",
        "body",
        "value",
        "message",
        "reason",
        "justification",
        "explanation",
        "rationale",
        "evidence",
        "notes",
        "criteria",
        "checklist",
        "finding_text",
        "assessment_text",
    )
    for bad in banned:
        if bad in detail:
            raise AuditKindError(f"audit detail bans {bad!r}")
    _check_seq(seq)
    event = {
        "schema": AUDIT_SCHEMA,
        "module": "responsible-ai",
        "kind": kind,
        "seq": seq,
        "detail": detail,
    }
    event["digest"] = _digest_pin((kind, seq, tuple(sorted(detail))), "audit-event")
    return event


# ---------------------------------------------------------------------------
# ResponsibleAI ledger
# ---------------------------------------------------------------------------


class ResponsibleAI:
    """Responsible-AI governance decision ledger: assess, verify, evaluate."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        # assessment_id -> AssessmentRecord (ordered)
        self._assessments: Dict[str, AssessmentRecord] = {}
        # system_id -> assessment ids, in booking order
        self._systems: Dict[str, List[str]] = {}
        self._audit_events: List[Dict[str, Any]] = []

    # -- seq discipline ----------------------------------------------------

    def _claim(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError(f"seq {seq} not strictly greater than {self._seq}")
        self._seq = seq
        return seq

    def _emit(self, audit_kind: str, seq: int, **detail: Any) -> None:
        self._audit_events.append(
            responsible_ai_audit_event(audit_kind, seq, **detail)
        )

    def _fail(self, seq: int, exc: ResponsibleAIError, **detail: Any) -> None:
        self._emit(KIND_REJECTED, seq, error=type(exc).__name__, **detail)
        raise exc

    # -- mutations ----------------------------------------------------------

    def assess(
        self,
        system_id: str,
        seq: int,
        dimension: str = DIM_SAFETY,
        finding: str = FINDING_NOT_ASSESSED,
        assessment_digest: str = "",
    ) -> AssessmentRecord:
        """Book one declared responsible-AI assessment.

        The first assessment for a system registers that system. The raw
        assessment material travels as a digest pin only.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                system_id = _check_id(system_id, "system_id")
                dimension = _check_dimension(dimension)
                finding = _check_finding(finding)
                assessment_digest = _check_digest(
                    assessment_digest, "assessment_digest", allow_empty=True
                )
            except ResponsibleAIError as exc:
                self._fail(seq, exc, system_id=str(system_id))
            assessment_id = f"asm-{len(self._assessments) + 1}"
            record = AssessmentRecord(
                assessment_id=assessment_id,
                system_id=system_id,
                dimension=dimension,
                finding=finding,
                assessment_digest=assessment_digest,
                digest=_digest_pin(
                    (assessment_id, system_id, dimension, finding, assessment_digest),
                    "assessment",
                ),
                seq=seq,
            )
            self._assessments[assessment_id] = record
            self._systems.setdefault(system_id, []).append(assessment_id)
            self._emit(
                KIND_ASSESSED,
                seq,
                assessment_id=assessment_id,
                system_id=system_id,
                dimension=dimension,
                finding=finding,
                assessment_digest=assessment_digest,
                record_digest=record.digest,
            )
            return record

    # -- pure read views ----------------------------------------------------

    def verify(self, assessment_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive a booked assessment's digest pin.

        Verdict is ``verified`` or ``tampered`` as data (tamper is
        reported, never raised). Validates seq shape, consumes nothing,
        books no audit rows.
        """
        _check_seq(seq)
        with self._lock:
            record = self._assessments.get(assessment_id)
            if record is None:
                raise UnknownAssessmentError(
                    f"unknown assessment: {assessment_id!r}"
                )
            verdict = VERDICT_VERIFIED if record.verify() else VERDICT_TAMPERED
            return VerificationReport(
                assessment_id=record.assessment_id,
                verdict=verdict,
                digest=_digest_pin(
                    (record.assessment_id, verdict), "verification-report"
                ),
                seq=seq,
            )

    def evaluate(self, seq: int, system_id: str = "") -> EvaluationReport:
        """Pure read: digest-pinned posture report, system-scoped or whole ledger.

        Posture is derived as data by ledger rule: ``unassessed`` (nothing
        booked, or all findings ``not-assessed``) -> ``noncompliant`` (any
        ``noncompliant``) -> ``gap-open`` (any ``gap-identified``) ->
        ``in-progress`` (any ``in-progress``) -> ``meets-requirements``.
        Validates seq shape, consumes nothing, books no audit rows.
        """
        _check_seq(seq)
        with self._lock:
            if system_id:
                if system_id not in self._systems:
                    raise UnknownSystemError(f"unknown system: {system_id!r}")
                ids = tuple(self._systems[system_id])
            else:
                ids = tuple(self._assessments)
            records = [self._assessments[i] for i in ids]
            by_dimension: Dict[str, int] = {}
            by_finding: Dict[str, int] = {}
            effective: List[str] = []
            for rec in records:
                by_dimension[rec.dimension] = by_dimension.get(rec.dimension, 0) + 1
                by_finding[rec.finding] = by_finding.get(rec.finding, 0) + 1
                if rec.finding != FINDING_NOT_ASSESSED:
                    effective.append(rec.finding)
            if not effective:
                posture = POSTURE_UNASSESSED
            elif FINDING_NONCOMPLIANT in effective:
                posture = POSTURE_NONCOMPLIANT
            elif FINDING_GAP in effective:
                posture = POSTURE_GAP_OPEN
            elif FINDING_IN_PROGRESS in effective:
                posture = POSTURE_IN_PROGRESS
            else:
                posture = POSTURE_MEETS
            integrity_ok = all(rec.verify() for rec in records)
            report = EvaluationReport(
                system_scope=system_id,
                posture=posture,
                n_assessments=len(records),
                by_dimension=tuple(sorted(by_dimension.items())),
                by_finding=tuple(sorted(by_finding.items())),
                integrity_ok=integrity_ok,
                digest=_digest_pin(
                    (
                        system_id,
                        posture,
                        len(records),
                        tuple(sorted(by_dimension.items())),
                        tuple(sorted(by_finding.items())),
                        integrity_ok,
                    ),
                    "evaluation-report",
                ),
                seq=seq,
            )
            return report

    def assessment_record(self, assessment_id: str, seq: int) -> Optional[AssessmentRecord]:
        """Pure read: the booked assessment record, or None."""
        _check_seq(seq)
        with self._lock:
            return self._assessments.get(assessment_id)

    def assessments_for(self, system_id: str, seq: int) -> Tuple[AssessmentRecord, ...]:
        """Pure read: assessments booked for a system, in booking order."""
        _check_seq(seq)
        with self._lock:
            return tuple(
                self._assessments[i] for i in self._systems.get(system_id, ())
            )

    def system_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read: ids of registered systems, in registration order."""
        _check_seq(seq)
        with self._lock:
            return tuple(self._systems)

    def assessment_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read: ids of booked assessments, in booking order."""
        _check_seq(seq)
        with self._lock:
            return tuple(self._assessments)

    def stats(self, seq: int) -> Dict[str, Any]:
        """Pure read: ledger counters."""
        _check_seq(seq)
        with self._lock:
            return {
                "systems": len(self._systems),
                "assessments": len(self._assessments),
                "rejected": sum(
                    1 for e in self._audit_events if e["kind"] == KIND_REJECTED
                ),
                "last_seq": self._seq,
            }

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        """All audit events booked so far."""
        with self._lock:
            return tuple(self._audit_events)


def main() -> None:
    """Self-check: assess, verify, evaluate, posture math, pins."""
    ledger = ResponsibleAI()
    r1 = ledger.assess(
        "system-a",
        1,
        dimension="safety",
        finding="meets-requirements",
        assessment_digest="sha256:" + "a" * 64,
    )
    assert r1.verify()
    assert r1.assessment_id == "asm-1"
    r2 = ledger.assess(
        "system-a", 2, dimension="fairness", finding="gap-identified"
    )
    assert r2.verify() and r2.assessment_id == "asm-2"
    r3 = ledger.assess(
        "system-b", 3, dimension="privacy", finding="noncompliant"
    )
    assert r3.verify() and r3.assessment_id == "asm-3"
    vr = ledger.verify("asm-1", 4)
    assert vr.verify()
    assert vr.verdict == "verified"
    ev_a = ledger.evaluate(5, "system-a")
    assert ev_a.verify()
    assert ev_a.posture == "gap-open"  # gap outranks meets
    assert ev_a.n_assessments == 2
    assert ev_a.integrity_ok
    ev_b = ledger.evaluate(6, "system-b")
    assert ev_b.verify()
    assert ev_b.posture == "noncompliant"
    ev_all = ledger.evaluate(7)
    assert ev_all.verify()
    assert ev_all.posture == "noncompliant"  # noncompliant outranks gap-open
    assert ev_all.n_assessments == 3
    assert dict(ev_all.by_dimension) == {
        "safety": 1,
        "fairness": 1,
        "privacy": 1,
    }
    st = ledger.stats(8)
    assert st == {"systems": 2, "assessments": 3, "rejected": 0, "last_seq": 3}
    print("responsible-ai OK: assess, verify, evaluate, pins")


if __name__ == "__main__":
    main()
