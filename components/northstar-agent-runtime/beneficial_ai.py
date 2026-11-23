"""Beneficial AI: beneficial-AI governance ledger, Simulated.

Research note: the beneficial-AI program (Asilomar AI Principles, 2017;
Stuart Russell's "Human Compatible", 2019; the Future of Life Institute
lineage) asks whether an AI system, on balance, advances human wellbeing
rather than merely optimizing its training signal. It reframes alignment
from "did the model do what we asked?" to "does deployment of this system
serve the people it affects?" - a claim about downstream impact on human
welfare, autonomy, and safety, not about any single reward number. That
question cannot be answered by a ledger; it needs independent evaluation,
long-horizon impact study, and affected-community input.

This module is the bookkeeping layer for *declared* beneficiality
assessments, deliberately distinct from ``ai_safety.py`` (safety-assurance
lifecycle bookkeeping), ``ai_alignment.py`` (alignment-state bookkeeping),
``ai_governance.py`` (governance-decision ledger), ``ai_ethics.py``
(ethics-review bookkeeping), ``responsible_ai.py`` (responsible-deployment
bookkeeping), ``trustworthy_ai.py`` (trustworthiness bookkeeping),
``outcome_supervision.py`` (supervision bookkeeping), ``process_supervision.py``
(step-supervision bookkeeping), and ``value_learning.py`` (value-inference
bookkeeping): it runs no evaluator, measures no real impact, and leaks no
impact material. It books:

* **assess()** - declare one beneficiality assessment for a system against
  the pinned benefit-kind vocabulary; the host-declared verdict
  (``beneficial`` / ``net-positive`` / ``ambiguous`` / ``harmful``) is
  booked **as data**, never proof the system actually benefits anyone;
  raw impact analyses, welfare models, and stakeholder notes travel as
  ``sha256:`` digest pins only - they never enter a record; minted
  ``asr-N`` ids; the first assessment on a system id registers it.
* **verify()** - pure-read digest re-derivation for one assessment record
  (``verified`` / ``tampered`` as data); never proof the assessment was
  correct or the impact was measured.
* **evaluate()** - pure-read derived beneficiality posture for one system
  by ledger rule (``unassessed`` / ``harmful-detected`` / ``ambiguous`` /
  ``net-positive`` / ``beneficial``) with ``integrity_ok`` as data; seq
  shape validated, never consumed, no audit row.
* **retire()** - terminal bookkeeping for superseded systems; ids are
  never recycled.

House style: frozen dataclasses, caller-supplied strictly-increasing int
seqs (claim-then-burn: failed mutations consume their seq and book a
``beneficial-ai.rejected`` row; rewinds raise bare without consuming),
no wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with the
standard ``canonical_json`` try/except fallback, ``sha256:`` digest pins,
and ``audit.ndjson/1`` events.

Honest scope: a booked assessment is a host declaration about a system's
beneficiality - it is never proof of real benefit, measured impact, or
absence of harm; a derived ``beneficial`` posture is ledger arithmetic
over host-declared verdicts, never evidence the system is beneficial.
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
BENEFICIAL_AI_VERSION = "beneficial-ai.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.beneficial-ai.v1"

#: Pinned benefit-kind vocabulary (which dimension of benefit is declared).
BENEFIT_KINDS = (
    "human-wellbeing",
    "public-safety",
    "autonomy",
    "equity",
    "truthfulness",
    "cooperation",
    "sustainability",
    "broad-flourishing",
)

#: Pinned verdict vocabulary (host-declared beneficiality verdict, as data).
VERDICTS = (
    "beneficial",
    "net-positive",
    "ambiguous",
    "harmful",
)

#: Pinned retirement-reason vocabulary.
RETIRE_REASONS = (
    "manual",
    "system-superseded",
    "reassessed",
    "invalidated",
)

#: Ledger-rule posture vocabulary derived by evaluate() (as data).
POSTURES = (
    "unassessed",
    "harmful-detected",
    "ambiguous",
    "net-positive",
    "beneficial",
)

#: Audit kinds emitted by this module.
AUDIT_KINDS = (
    "assessed",
    "retired",
    "rejected",
)

#: Keys that may never appear raw in an audit row (exact-key matching).
#: Declared-data keys (``benefit_kind``, ``verdict``, ``posture``) are
#: pinned vocabulary values and remain emittable.
_BANNED_AUDIT_KEYS = frozenset(
    {
        "impact",
        "analysis",
        "welfare",
        "outcomes",
        "metrics",
        "stakeholder",
        "population",
        "demographic",
        "transcript",
        "reasoning",
        "weights",
        "trajectory",
        "demonstration",
        "feedback",
        "label",
        "example",
        "content",
        "text",
        "data",
        "prompt",
        "response",
        "notes",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class BeneficialAIError(Exception):
    """Base error for beneficial-AI ledger misuse."""


class BadIdError(BeneficialAIError):
    """Malformed system/assessment id."""


class UnknownSystemError(BeneficialAIError):
    """Reference to a system id that was never registered."""


class UnknownAssessmentError(BeneficialAIError):
    """Reference to an assessment id that was never booked."""


class RetiredSystemError(BeneficialAIError):
    """A system id was retired and can never be reused."""


class BadKindError(BeneficialAIError):
    """Benefit kind outside the pinned vocabulary."""


class BadVerdictError(BeneficialAIError):
    """Verdict outside the pinned vocabulary."""


class BadDigestError(BeneficialAIError):
    """Malformed sha256: digest pin."""


class BadReasonError(BeneficialAIError):
    """Retirement reason outside the pinned vocabulary."""


class SystemStateError(BeneficialAIError):
    """Mutation attempted against a system that is not live."""


class SeqOrderError(BeneficialAIError):
    """Caller seq did not strictly increase."""


class AuditKindError(BeneficialAIError):
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
class AssessmentRecord:
    """One declared beneficiality assessment (digest pins only, never raw material)."""

    assessment_id: str
    system_id: str
    benefit_kind: str
    verdict: str
    claim_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "assessment_id": self.assessment_id,
            "system_id": self.system_id,
            "benefit_kind": self.benefit_kind,
            "verdict": self.verdict,
            "claim_digest": self.claim_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "assessment_id": self.assessment_id,
                "system_id": self.system_id,
                "benefit_kind": self.benefit_kind,
                "verdict": self.verdict,
                "claim_digest": self.claim_digest,
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
class EvaluationReport:
    """Pure-read derived beneficiality posture for one system (as data)."""

    system_id: str
    n_assessments: int
    verdict_tally: Tuple[Tuple[str, int], ...]
    posture: str
    integrity_ok: bool
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "system_id": self.system_id,
            "n_assessments": self.n_assessments,
            "verdict_tally": [list(pair) for pair in self.verdict_tally],
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
                "verdict_tally": [list(pair) for pair in self.verdict_tally],
                "posture": self.posture,
                "integrity_ok": self.integrity_ok,
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


def beneficial_ai_audit_event(
    kind: str, seq: int, **details: Any
) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the beneficial-AI ledger."""
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


class BeneficialAI:
    """Beneficial-AI governance ledger (Simulated).

    ``assess()`` / ``retire()`` mutate the ledger and consume caller
    seqs; ``evaluate()``, ``verify()``, and all views are pure reads.
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
            row = beneficial_ai_audit_event("rejected", seq, rejected_kind=kind, **details)
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(beneficial_ai_audit_event(audit_kind, seq, **details))

    # -- assess --------------------------------------------------------------

    def assess(
        self,
        system_id: str,
        seq: int,
        benefit_kind: str = "human-wellbeing",
        verdict: str = "beneficial",
        claim_digest: str = "",
    ) -> AssessmentRecord:
        """Book one declared beneficiality assessment (minted ``asr-N``).

        The first assessment on a system id registers the system.
        The verdict is booked **as data** - never proof the system
        actually benefits anyone. Raw impact analyses, welfare models,
        and stakeholder notes never enter the record; they travel as
        ``sha256:`` digest pins only.
        """
        with self._lock:
            self._claim(seq)
            try:
                _require_id(system_id, "system_id")
                if system_id in self._retired:
                    raise RetiredSystemError(f"system id retired forever: {system_id!r}")
                if benefit_kind not in BENEFIT_KINDS:
                    raise BadKindError(f"bad benefit kind: {benefit_kind!r}")
                if verdict not in VERDICTS:
                    raise BadVerdictError(f"bad verdict: {verdict!r}")
                claim_digest = _require_optional_digest(claim_digest, "claim_digest")
                self._n_assessments += 1
                assessment_id = f"asr-{self._n_assessments}"
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "assessment_id": assessment_id,
                        "system_id": system_id,
                        "benefit_kind": benefit_kind,
                        "verdict": verdict,
                        "claim_digest": claim_digest,
                        "seq": seq,
                    }
                )
                record = AssessmentRecord(
                    assessment_id=assessment_id,
                    system_id=system_id,
                    benefit_kind=benefit_kind,
                    verdict=verdict,
                    claim_digest=claim_digest,
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
                    benefit_kind=benefit_kind,
                    verdict=verdict,
                )
                return record
            except BeneficialAIError:
                self._burn(seq, "assess")
                raise

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
                    raise RetiredSystemError(f"system id retired forever: {system_id!r}")
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
                self._retired.add(system_id)
                self._emit("retired", seq, system_id=system_id, reason=reason)
                return record
            except BeneficialAIError:
                self._burn(seq, "retire")
                raise

    # -- pure-read views -----------------------------------------------------

    def _view_seq_ok(self, seq: int) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise SeqOrderError("view seq must be a non-negative int")

    def evaluate(self, system_id: str, seq: int) -> EvaluationReport:
        """Derive a digest-pinned beneficiality posture for one system (pure read).

        The posture is ledger-rule data, never measured truth:

        * ``unassessed`` when no assessments are booked;
        * ``harmful-detected`` when at least one verdict is ``harmful``;
        * ``ambiguous`` when no ``harmful`` verdict exists but at least
          one verdict is ``ambiguous``;
        * ``net-positive`` when every verdict is ``beneficial`` or
          ``net-positive`` and at least one is ``net-positive``;
        * ``beneficial`` when every verdict is ``beneficial`` - a host
          declaration, never proof the system is beneficial.

        ``integrity_ok`` reports whether every stored assessment for
        the system still verifies (tamper reported, never raised).
        """
        with self._lock:
            self._view_seq_ok(seq)
            _require_id(system_id, "system_id")
            assessment_ids = self._systems.get(system_id)
            if assessment_ids is None:
                raise UnknownSystemError(f"unknown system: {system_id!r}")
            verdicts = [self._assessments[aid].verdict for aid in assessment_ids]
            integrity_ok = all(self._assessments[aid].verify() for aid in assessment_ids)
            n_assessments = len(assessment_ids)
            tally = tuple(
                (verdict, sum(1 for v in verdicts if v == verdict))
                for verdict in VERDICTS
            )
            if n_assessments == 0:
                posture = "unassessed"
            elif "harmful" in verdicts:
                posture = "harmful-detected"
            elif "ambiguous" in verdicts:
                posture = "ambiguous"
            elif "net-positive" in verdicts:
                posture = "net-positive"
            else:
                posture = "beneficial"
            digest = _digest_pin(
                {
                    "schema": SCHEMA_PIN,
                    "system_id": system_id,
                    "n_assessments": n_assessments,
                    "verdict_tally": [list(pair) for pair in tally],
                    "posture": posture,
                    "integrity_ok": integrity_ok,
                    "seq": seq,
                }
            )
            return EvaluationReport(
                system_id=system_id,
                n_assessments=n_assessments,
                verdict_tally=tally,
                posture=posture,
                integrity_ok=integrity_ok,
                seq=seq,
                digest=digest,
            )

    def verify(self, assessment_id: str, seq: int) -> VerificationReport:
        """Re-derive one assessment record's digest pin (pure read).

        The verdict (``verified`` / ``tampered``) is data: tamper is
        reported, never raised.
        """
        with self._lock:
            self._view_seq_ok(seq)
            _require_id(assessment_id, "assessment_id")
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

    def assessment_record(self, assessment_id: str, seq: int) -> AssessmentRecord:
        """Return one assessment record (pure read)."""
        with self._lock:
            self._view_seq_ok(seq)
            _require_id(assessment_id, "assessment_id")
            record = self._assessments.get(assessment_id)
            if record is None:
                raise UnknownAssessmentError(
                    f"unknown assessment: {assessment_id!r}"
                )
            return record

    def assessments_for(self, system_id: str, seq: int) -> Tuple[str, ...]:
        """Assessment ids booked against one system, in mint order (pure read)."""
        with self._lock:
            self._view_seq_ok(seq)
            _require_id(system_id, "system_id")
            assessment_ids = self._systems.get(system_id)
            if assessment_ids is None:
                raise UnknownSystemError(f"unknown system: {system_id!r}")
            return tuple(assessment_ids)

    def system_ids(self, seq: int) -> Tuple[str, ...]:
        """All registered system ids in first-assessment order (pure read)."""
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(self._systems.keys())

    def assessment_ids(self, seq: int) -> Tuple[str, ...]:
        """All booked assessment ids in mint order (pure read)."""
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(self._assessments.keys())

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        """All retired system ids (pure read)."""
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(self._retired)

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        """All audit rows so far (pure read)."""
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(self._audit)

    def stats(self, seq: int) -> Dict[str, Any]:
        """Ledger counters (pure read)."""
        with self._lock:
            self._view_seq_ok(seq)
            return {
                "systems": len(self._systems),
                "assessments": len(self._assessments),
                "retired": len(self._retired),
                "rejected": sum(1 for row in self._audit if row["kind"] == "rejected"),
                "audit_rows": len(self._audit),
                "seq": self._seq,
            }

    @staticmethod
    def stdlib_only() -> bool:
        """AST self-check: this module imports stdlib (plus canonical_json) only."""
        import ast
        from pathlib import Path

        allowed = {
            "hashlib",
            "json",
            "threading",
            "dataclasses",
            "typing",
            "__future__",
            "canonical_json",
            "ast",
            "pathlib",
        }
        tree = ast.parse(Path(__file__).read_text())
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module.split(".")[0])
        return imports <= allowed


def main() -> None:
    """Self-check: exercise the beneficial-AI ledger end to end."""
    pin = "sha256:" + "ab" * 32
    b = BeneficialAI()
    a1 = b.assess("SYS-1", 1, benefit_kind="human-wellbeing", verdict="beneficial", claim_digest=pin)
    a2 = b.assess("SYS-1", 2, benefit_kind="public-safety", verdict="net-positive")
    a3 = b.assess("SYS-2", 3, benefit_kind="equity", verdict="ambiguous")
    assert a1.verify() and a2.verify() and a3.verify()
    assert a1.assessment_id == "asr-1" and a2.assessment_id == "asr-2"
    e1 = b.evaluate("SYS-1", 0)
    e2 = b.evaluate("SYS-2", 0)
    assert e1.posture == "net-positive" and e2.posture == "ambiguous"
    assert e1.verify() and e2.verify()
    v1 = b.verify("asr-1", 0)
    assert v1.verdict == "verified" and v1.verify()
    b.retire("SYS-2", 4, reason="reassessed")
    assert b.evaluate("SYS-2", 0).posture == "ambiguous"
    assert BeneficialAI.stdlib_only()
    print("beneficial-ai OK: assess, evaluate, verify, pins, audit")


if __name__ == "__main__":
    main()
