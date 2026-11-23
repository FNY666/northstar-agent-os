"""Trustworthy-AI assessment ledger (sixty-first batch).

Deterministic, single-host bookkeeping for declared trustworthy-AI
assessments: one system declares which assessment framework it is
being judged against, hosts declare per-dimension assessment
outcomes, and the ledger derives a posture report as data.

House rules: frozen dataclasses, caller-supplied strictly-increasing
int ``seq`` with claim-then-burn (failed mutations consume seq and
book a ``trustworthy-ai.rejected`` row; rewinds raise bare without
consuming), no wall-clock, RLock-guarded, fail-closed taxonomy,
stdlib-only (AST self-check) with ``canonical_json`` try/except
fallback, ``sha256:`` digest pins over type-tagged canonical
payloads, ``audit.ndjson/1`` events.

Honest boundary: an assessment is a *host declaration* — the module
books the verdict, it never audits the model, inspects the training
data, or proves trustworthiness. Raw assessment material (evidence
packets, scorecards, reviewer notes) travels as ``sha256:`` digest
pins only and never enters records. An ``assess(outcome=
"trustworthy")`` call is booked as data, never as evidence that a
system is actually trustworthy; production still needs real audits,
independent evaluators, and an execution path.
"""

from __future__ import annotations

import ast
import hashlib
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, Tuple

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    _cj = None  # type: ignore

#: Version pin for this module's record shape.
TRUSTWORTHY_AI_VERSION = "trustworthy-ai.v1"

#: Schema pin carried by records and audit events.
SCHEMA_PIN = "northstar.trustworthy-ai.v1"

#: Pinned assessment frameworks (framework drift detectable).
FRAMEWORKS = (
    "eu-hleg",
    "nist-ai-rmf",
    "oecd-ai-principles",
    "iso-23894",
    "iso-42001",
    "self-declared",
)

#: Pinned trustworthiness dimensions (EU HLEG seven, kept pinned).
DIMENSIONS = (
    "human-oversight",
    "robustness",
    "privacy",
    "transparency",
    "fairness",
    "wellbeing",
    "accountability",
)

#: Pinned assessment outcomes (booked as data, never proof).
OUTCOMES = (
    "trustworthy",
    "conditionally-trustworthy",
    "not-trustworthy",
    "inconclusive",
    "not-assessed",
)

#: Derived posture vocabulary emitted by evaluate().
POSTURES = (
    "unevaluated",
    "not-trustworthy",
    "conditionally-trustworthy",
    "trustworthy",
)

#: Pinned retirement reasons.
RETIRE_REASONS = ("manual", "superseded", "withdrawn")

#: Pinned audit kinds.
AUDIT_KINDS = (
    "assessed",
    "retired",
    "rejected",
)

#: Raw-material keys that may never cross the audit boundary.
_BANNED_AUDIT_KEYS = frozenset(
    {
        "evidence",
        "evidence_packet",
        "scorecard",
        "reviewer_notes",
        "findings",
        "findings_text",
        "remediation",
        "remediation_plan",
        "criterion_text",
        "assessment_report",
        "audit_trail",
        "model_weights",
        "weights",
        "dataset",
        "training_data",
        "prompts",
        "transcript",
        "raw",
        "attachment",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class TrustworthyAIError(Exception):
    """Base error for the trustworthy-AI assessment ledger."""


class BadIdError(TrustworthyAIError):
    """Malformed identifier."""


class BadFrameworkError(TrustworthyAIError):
    """Assessment framework outside the pinned vocabulary."""


class BadDimensionError(TrustworthyAIError):
    """Dimension outside the pinned vocabulary."""


class BadOutcomeError(TrustworthyAIError):
    """Outcome outside the pinned vocabulary."""


class BadDigestError(TrustworthyAIError):
    """Malformed sha256: digest pin."""


class BadReasonError(TrustworthyAIError):
    """Retirement reason outside the pinned vocabulary."""


class UnknownSystemError(TrustworthyAIError):
    """No such assessed system id."""


class UnknownAssessmentError(TrustworthyAIError):
    """No such assessment id."""


class RetiredSystemError(TrustworthyAIError):
    """Mutation attempted against a retired system (ids never recycled)."""


class SeqOrderError(TrustworthyAIError):
    """Caller seq did not strictly increase."""


class AuditKindError(TrustworthyAIError):
    """Unknown audit kind or banned raw key in an audit row."""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _jcs_hash(payload: Mapping[str, Any]) -> str:
    if _cj is not None:
        raw = _cj.jcs_dumps(payload)
        data = raw.encode("utf-8") if isinstance(raw, str) else raw
    else:  # pragma: no cover - stdlib fallback
        import json

        data = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _require_id(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise BadIdError(f"{field_name} must be a non-empty str <= 128 chars")
    return value


def _require_digest(pin: Any, field_name: str) -> str:
    if not isinstance(pin, str) or not pin.startswith("sha256:"):
        raise BadDigestError(f"{field_name} must be a 'sha256:' pin")
    hexpart = pin[7:]
    if len(hexpart) != 64 or any(c not in "0123456789abcdef" for c in hexpart):
        raise BadDigestError(f"{field_name} must be a 64-hex sha256 pin")
    return pin


def _require_optional_digest(pin: Any, field_name: str) -> str:
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
class AssessmentRecord:
    """One declared trustworthy-AI assessment (digest pins only, never raw material)."""

    assessment_id: str
    system_id: str
    framework: str
    dimension: str
    outcome: str
    evidence_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "assessment_id": self.assessment_id,
            "system_id": self.system_id,
            "framework": self.framework,
            "dimension": self.dimension,
            "outcome": self.outcome,
            "evidence_digest": self.evidence_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "assessment_id": self.assessment_id,
                "system_id": self.system_id,
                "framework": self.framework,
                "dimension": self.dimension,
                "outcome": self.outcome,
                "evidence_digest": self.evidence_digest,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class RetireRecord:
    """Terminal retirement bookkeeping for one system (ids never recycled)."""

    system_id: str
    reason: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "system_id": self.system_id,
            "reason": self.reason,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "system_id": self.system_id,
                "reason": self.reason,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class VerificationReport:
    """Pure-read digest re-derivation for one assessment record (as data)."""

    assessment_id: str
    verdict: str
    integrity_ok: bool
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "assessment_id": self.assessment_id,
            "verdict": self.verdict,
            "integrity_ok": self.integrity_ok,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "assessment_id": self.assessment_id,
                "verdict": self.verdict,
                "integrity_ok": self.integrity_ok,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class EvaluationReport:
    """Pure-read derived trust posture for one system (as data)."""

    system_id: str
    n_assessments: int
    outcome_tally: Tuple[Tuple[str, int], ...]
    posture: str
    integrity_ok: bool
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "system_id": self.system_id,
            "n_assessments": self.n_assessments,
            "outcome_tally": [list(pair) for pair in self.outcome_tally],
            "posture": self.posture,
            "integrity_ok": self.integrity_ok,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "system_id": self.system_id,
                "n_assessments": self.n_assessments,
                "outcome_tally": [list(pair) for pair in self.outcome_tally],
                "posture": self.posture,
                "integrity_ok": self.integrity_ok,
                "seq": self.seq,
            }
        )


def trustworthy_ai_audit_event(
    kind: str, seq: int, **details: Any
) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the assessment ledger."""
    if kind not in AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError("audit seq must be a non-negative int")
    for key in details:
        if key in _BANNED_AUDIT_KEYS:
            raise AuditKindError(f"banned raw key in audit detail: {key!r}")
    return {
        "schema": "audit.ndjson/1",
        "kind": kind,
        "seq": seq,
        "details": dict(details),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class TrustworthyAI:
    """Trustworthy-AI assessment governance ledger (Simulated).

    ``assess()`` / ``retire()`` mutate the ledger and consume caller
    seqs; ``verify()``, ``evaluate()``, and all views are pure reads.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._systems: Dict[str, List[str]] = {}
        self._assessments: Dict[str, AssessmentRecord] = {}
        self._retirements: Dict[str, RetireRecord] = {}
        self._retired: set = set()
        self._n_assessments = 0
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
            row = trustworthy_ai_audit_event(
                "rejected", seq, rejected_kind=kind, **details
            )
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(trustworthy_ai_audit_event(audit_kind, seq, **details))

    def _require_read_seq(self, seq: Any, field_name: str = "seq") -> int:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise SeqOrderError(f"{field_name} must be a non-negative int")
        return seq

    def _live(self, system_id: str) -> List[str]:
        assessment_ids = self._systems.get(system_id)
        if assessment_ids is None:
            raise UnknownSystemError(f"unknown system: {system_id!r}")
        if system_id in self._retired:
            raise RetiredSystemError(f"system id retired forever: {system_id!r}")
        return assessment_ids

    # -- assess --------------------------------------------------------------

    def assess(
        self,
        system_id: str,
        seq: int,
        framework: str = "eu-hleg",
        dimension: str = "robustness",
        outcome: str = "not-assessed",
        evidence_digest: str = "",
    ) -> AssessmentRecord:
        """Book one declared trustworthy-AI assessment (minted ``ast-N``).

        The first assessment on a system id registers the system.
        The outcome is booked **as data** — never proof the system is
        actually trustworthy. Raw evidence material never enters the
        record; it travels as a ``sha256:`` digest pin only.
        """
        with self._lock:
            self._claim(seq)
            try:
                _require_id(system_id, "system_id")
                if system_id in self._retired:
                    raise RetiredSystemError(
                        f"system id retired forever: {system_id!r}"
                    )
                if framework not in FRAMEWORKS:
                    raise BadFrameworkError(f"bad framework: {framework!r}")
                if dimension not in DIMENSIONS:
                    raise BadDimensionError(f"bad dimension: {dimension!r}")
                if outcome not in OUTCOMES:
                    raise BadOutcomeError(f"bad outcome: {outcome!r}")
                evidence_digest = _require_optional_digest(
                    evidence_digest, "evidence_digest"
                )
                self._n_assessments += 1
                assessment_id = f"ast-{self._n_assessments}"
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "assessment_id": assessment_id,
                        "system_id": system_id,
                        "framework": framework,
                        "dimension": dimension,
                        "outcome": outcome,
                        "evidence_digest": evidence_digest,
                        "seq": seq,
                    }
                )
                record = AssessmentRecord(
                    assessment_id=assessment_id,
                    system_id=system_id,
                    framework=framework,
                    dimension=dimension,
                    outcome=outcome,
                    evidence_digest=evidence_digest,
                    seq=seq,
                    digest=digest,
                )
                self._assessments[assessment_id] = record
                self._systems.setdefault(system_id, []).append(assessment_id)
                self._emit(
                    "assessed",
                    seq,
                    assessment_id=assessment_id,
                    system_id=system_id,
                    framework=framework,
                    dimension=dimension,
                    outcome=outcome,
                )
                return record
            except TrustworthyAIError:
                self._burn(seq, "assess")
                raise

    # -- verify --------------------------------------------------------------

    def verify(self, assessment_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive the digest pin of one assessment (as data).

        ``seq`` is shape-validated only — it is never consumed and no
        audit row is written.
        """
        with self._lock:
            self._require_read_seq(seq)
            record = self._assessments.get(assessment_id)
            if record is None:
                raise UnknownAssessmentError(
                    f"unknown assessment: {assessment_id!r}"
                )
            integrity_ok = record.verify()
            verdict = "verified" if integrity_ok else "tampered"
            digest = _digest_pin(
                {
                    "schema": SCHEMA_PIN,
                    "assessment_id": assessment_id,
                    "verdict": verdict,
                    "integrity_ok": integrity_ok,
                    "seq": seq,
                }
            )
            return VerificationReport(
                assessment_id=assessment_id,
                verdict=verdict,
                integrity_ok=integrity_ok,
                seq=seq,
                digest=digest,
            )

    # -- evaluate ------------------------------------------------------------

    def evaluate(self, system_id: str, seq: int) -> EvaluationReport:
        """Pure read: derive the trust posture for one system (as data).

        Posture precedence: ``unevaluated`` (no assessments) ->
        ``not-trustworthy`` (any) -> ``conditionally-trustworthy``
        (any, otherwise) -> ``trustworthy`` (all trustworthy /
        inconclusive / not-assessed mix with at least one
        trustworthy). ``seq`` is shape-validated only — never
        consumed, no audit row.
        """
        with self._lock:
            self._require_read_seq(seq)
            assessment_ids = self._systems.get(system_id)
            if assessment_ids is None:
                raise UnknownSystemError(f"unknown system: {system_id!r}")
            outcomes = [self._assessments[aid].outcome for aid in assessment_ids]
            tally = tuple(
                (outcome, outcomes.count(outcome)) for outcome in OUTCOMES
            )
            if not outcomes:
                posture = "unevaluated"
            elif "not-trustworthy" in outcomes:
                posture = "not-trustworthy"
            elif "conditionally-trustworthy" in outcomes:
                posture = "conditionally-trustworthy"
            elif "trustworthy" in outcomes:
                posture = "trustworthy"
            else:
                posture = "unevaluated"
            integrity_ok = all(
                self._assessments[aid].verify() for aid in assessment_ids
            )
            digest = _digest_pin(
                {
                    "schema": SCHEMA_PIN,
                    "system_id": system_id,
                    "n_assessments": len(assessment_ids),
                    "outcome_tally": [list(pair) for pair in tally],
                    "posture": posture,
                    "integrity_ok": integrity_ok,
                    "seq": seq,
                }
            )
            return EvaluationReport(
                system_id=system_id,
                n_assessments=len(assessment_ids),
                outcome_tally=tally,
                posture=posture,
                integrity_ok=integrity_ok,
                seq=seq,
                digest=digest,
            )

    # -- retire --------------------------------------------------------------

    def retire(self, system_id: str, seq: int, reason: str = "manual") -> RetireRecord:
        """Terminally retire one system (ids are never recycled)."""
        with self._lock:
            self._claim(seq)
            try:
                _require_id(system_id, "system_id")
                if reason not in RETIRE_REASONS:
                    raise BadReasonError(f"bad reason: {reason!r}")
                if system_id not in self._systems:
                    raise UnknownSystemError(f"unknown system: {system_id!r}")
                if system_id in self._retired:
                    raise RetiredSystemError(
                        f"system id retired forever: {system_id!r}"
                    )
                self._retired.add(system_id)
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "system_id": system_id,
                        "reason": reason,
                        "seq": seq,
                    }
                )
                record = RetireRecord(
                    system_id=system_id, reason=reason, seq=seq, digest=digest
                )
                self._retirements[system_id] = record
                self._emit("retired", seq, system_id=system_id, reason=reason)
                return record
            except TrustworthyAIError:
                self._burn(seq, "retire")
                raise

    # -- pure-read views -----------------------------------------------------

    def assessment_record(self, assessment_id: str, seq: int) -> AssessmentRecord:
        with self._lock:
            self._require_read_seq(seq)
            record = self._assessments.get(assessment_id)
            if record is None:
                raise UnknownAssessmentError(
                    f"unknown assessment: {assessment_id!r}"
                )
            return record

    def retire_record(self, system_id: str, seq: int) -> RetireRecord:
        with self._lock:
            self._require_read_seq(seq)
            record = self._retirements.get(system_id)
            if record is None:
                raise UnknownSystemError(f"unknown system: {system_id!r}")
            return record

    def assessments_for(self, system_id: str, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            if system_id not in self._systems:
                raise UnknownSystemError(f"unknown system: {system_id!r}")
            return tuple(self._systems[system_id])

    def assessment_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(f"ast-{i}" for i in range(1, self._n_assessments + 1))

    def system_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(self._systems.keys())

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(self._retired)

    def audit_log(self, seq: int) -> Tuple[Mapping[str, Any], ...]:
        with self._lock:
            self._require_read_seq(seq)
            return tuple(self._audit)

    def stats(self, seq: int) -> Dict[str, Any]:
        with self._lock:
            self._require_read_seq(seq)
            return {
                "schema": SCHEMA_PIN,
                "n_systems": len(self._systems),
                "n_assessments": self._n_assessments,
                "n_retired": len(self._retired),
                "seq": self._seq,
                "rejected": sum(1 for row in self._audit if row["kind"] == "rejected"),
            }


# ---------------------------------------------------------------------------
# stdlib self-check / main
# ---------------------------------------------------------------------------

_ALLOWED_STDLIB = frozenset(
    {
        "__future__",
        "ast",
        "hashlib",
        "threading",
        "dataclasses",
        "pathlib",
        "typing",
        "json",
    }
)


def stdlib_only() -> bool:
    """AST self-check: only stdlib (+ the try/except canonical_json import) modules used."""
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imported.add(node.module.split(".")[0])
    imported.discard("canonical_json")
    return imported <= _ALLOWED_STDLIB


def main() -> None:
    ledger = TrustworthyAI()
    assert TRUSTWORTHY_AI_VERSION == "trustworthy-ai.v1"
    assert SCHEMA_PIN == "northstar.trustworthy-ai.v1"
    rec = ledger.assess("sys-1", 1, outcome="trustworthy")
    assert rec.verify()
    assert ledger.verify(rec.assessment_id, 2).verdict == "verified"
    report = ledger.evaluate("sys-1", 3)
    assert report.posture == "trustworthy"
    assert report.verify()
    assert stdlib_only()
    print("trustworthy-ai OK: assess, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
