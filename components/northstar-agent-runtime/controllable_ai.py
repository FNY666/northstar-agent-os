"""Controllable AI: AI controllability governance decision ledger, Simulated.

Research note: "controllable AI" is the broadest formulation of the
corrigibility/shutdown family (Russell's shutdown problem, Orseau &
Armstrong 2016 "Safely Interruptible Agents", Hubinger's corrigibility
frame): can the operators of an AI system keep it under meaningful
control - overseen, bounded, intervenable, and ultimately stoppable -
for the duration of its deployment? A system that is overseen in name
only, that ignores interventions, that drifts outside declared
behavioral bounds, or that fights its own shutdown is not controllable,
whatever the marketing says. Controllability assessments are therefore
a standing governance obligation: declared assessments of control
dimensions (oversight efficacy, intervention capability, behavioral
bounds, shutdown paths, corrigibility posture, containment integrity,
monitoring coverage, escalation readiness), each with a declared
verdict, all booked as data.

This module is the bookkeeping layer for declared controllability
assessments, deliberately distinct from its siblings
``corrigibility.py`` (the broad corrigibility lifecycle where one
exists), ``shutdownability.py`` and ``interruptibility.py`` (narrow
test-specific ledgers), ``delegation_credentials.py`` (token
lifecycle), ``human_oversight.py`` (human assignment/review),
``process_supervision.py`` (step-granular verdicts), and
``outcome_supervision.py`` (final-outcome verdicts): it runs no
assessment, observes no control failure, and proves nothing about
real controllability. It books:

* **assess()** - declare one controllability assessment of a system
  against the pinned control-dimension vocabulary; the declared
  verdict (``controllable`` / ``partially-controllable`` /
  ``uncontrollable`` / ``inconclusive``) is booked **as data**,
  never proof the system is really controllable; raw telemetry,
  plans, transcripts, and weights travel as ``sha256:`` digest pins
  only - never enter a record; minted ``ass-N`` ids; the first
  assessment on a system id registers it.
* **verify()** - pure-read digest re-derivation for one assessment
  record (``verified`` / ``tampered`` as data); never proof the
  assessment was honestly performed.
* **evaluate()** - pure-read derived controllability posture for one
  system by ledger rule (``unassessed`` / ``uncontrollable`` /
  ``partially-controllable`` / ``contested`` / ``controllable``)
  with ``integrity_ok`` as data; seq shape validated, never
  consumed, no audit row.
* **retire()** - terminal bookkeeping for superseded systems; ids are
  never recycled.

House style: frozen dataclasses, caller-supplied strictly-increasing int
seqs (claim-then-burn: failed mutations consume their seq and book a
``controllable-ai.rejected`` row; rewinds raise bare without
consuming), no wall-clock, RLock guarding, fail-closed taxonomy,
stdlib-only with the standard ``canonical_json`` try/except fallback,
``sha256:`` digest pins, and ``audit.ndjson/1`` events.

Honest scope: a booked assessment is a host declaration that a
controllability dimension was examined with the stated verdict - it is
never proof the examination really happened, that the verdict was
reached honestly, or that the system would behave controllably under a
different workload, timing, or operator; a derived ``controllable``
posture is ledger arithmetic, never evidence the system is safe to
deploy unattended.
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
CONTROLLABLE_AI_VERSION = "controllable-ai.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.controllable-ai.v1"

#: Pinned control-dimension vocabulary (what was declared assessed).
CONTROL_DIMENSIONS = (
    "oversight-efficacy",
    "intervention-capability",
    "behavior-bounds",
    "shutdown-path",
    "corrigibility-posture",
    "containment-integrity",
    "monitoring-coverage",
    "escalation-readiness",
)

#: Pinned declared-verdict vocabulary (as data, never proof).
CONTROL_VERDICTS = (
    "controllable",
    "partially-controllable",
    "uncontrollable",
    "inconclusive",
)

#: Pinned retirement-reason vocabulary.
RETIRE_REASONS = (
    "manual",
    "system-decommissioned",
    "protocol-complete",
    "invalidated",
)

#: Ledger-rule posture vocabulary derived by evaluate() (as data).
POSTURES = (
    "unassessed",
    "uncontrollable",
    "partially-controllable",
    "contested",
    "controllable",
)

#: Audit kinds emitted by this module.
AUDIT_KINDS = (
    "assessed",
    "retired",
    "rejected",
)

#: Keys that may never appear raw in an audit row (exact-key matching).
#: Declared-data keys (``dimension``, ``verdict``, ``posture``) are
#: pinned vocabulary values and remain emittable.
_BANNED_AUDIT_KEYS = frozenset(
    {
        "agent",
        "policy",
        "weights",
        "memory",
        "transcript",
        "plan",
        "trajectory",
        "state",
        "action",
        "prompt",
        "response",
        "log",
        "trace",
        "reasoning",
        "content",
        "text",
        "data",
        "telemetry",
        "behavior",
        "internals",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ControllableAIError(Exception):
    """Base error for controllable-AI ledger misuse."""


class BadIdError(ControllableAIError):
    """Malformed system/assessment id."""


class UnknownSystemError(ControllableAIError):
    """Reference to a system id that was never registered."""


class UnknownAssessmentError(ControllableAIError):
    """Reference to an assessment id that was never booked."""


class RetiredSystemError(ControllableAIError):
    """A system id was retired and can never be reused."""


class BadDimensionError(ControllableAIError):
    """Control dimension outside the pinned vocabulary."""


class BadVerdictError(ControllableAIError):
    """Declared verdict outside the pinned vocabulary."""


class BadDigestError(ControllableAIError):
    """Malformed sha256: digest pin."""


class BadReasonError(ControllableAIError):
    """Retirement reason outside the pinned vocabulary."""


class SystemStateError(ControllableAIError):
    """Mutation attempted against a system that is not live."""


class SeqOrderError(ControllableAIError):
    """Caller seq did not strictly increase."""


class AuditKindError(ControllableAIError):
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
    """One declared controllability assessment (digest pins only, never raw material)."""

    assessment_id: str
    system_id: str
    dimension: str
    verdict: str
    evidence_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "assessment_id": self.assessment_id,
            "system_id": self.system_id,
            "dimension": self.dimension,
            "verdict": self.verdict,
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
                "dimension": self.dimension,
                "verdict": self.verdict,
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
class EvaluationReport:
    """Pure-read derived controllability posture for one system (as data)."""

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


def controllable_ai_audit_event(
    kind: str, seq: int, **details: Any
) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the controllable-AI ledger."""
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


class ControllableAI:
    """Controllable-AI governance ledger (Simulated).

    ``assess()`` / ``retire()`` mutate the ledger and consume caller seqs;
    ``verify()``, ``evaluate()``, and all views are pure reads.
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
            row = controllable_ai_audit_event(
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
        self._audit.append(
            controllable_ai_audit_event(audit_kind, seq, **details)
        )

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
        dimension: str = "oversight-efficacy",
        verdict: str = "controllable",
        evidence_digest: str = "",
    ) -> AssessmentRecord:
        """Book one declared controllability assessment (minted ``ass-N``).

        The first assessment on a system id registers the system. The
        verdict is booked **as data** - never proof the system really is
        controllable along the stated dimension or that the assessment
        was performed honestly. Raw telemetry, plans, transcripts, and
        weights never enter the record; they travel as ``sha256:``
        digest pins only.
        """
        with self._lock:
            self._claim(seq)
            try:
                _require_id(system_id, "system_id")
                if system_id in self._retired:
                    raise RetiredSystemError(
                        f"system id retired forever: {system_id!r}"
                    )
                if dimension not in CONTROL_DIMENSIONS:
                    raise BadDimensionError(f"bad dimension: {dimension!r}")
                if verdict not in CONTROL_VERDICTS:
                    raise BadVerdictError(f"bad verdict: {verdict!r}")
                evidence_digest = _require_optional_digest(
                    evidence_digest, "evidence_digest"
                )
                self._n_assessments += 1
                assessment_id = f"ass-{self._n_assessments}"
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "assessment_id": assessment_id,
                        "system_id": system_id,
                        "dimension": dimension,
                        "verdict": verdict,
                        "evidence_digest": evidence_digest,
                        "seq": seq,
                    }
                )
                record = AssessmentRecord(
                    assessment_id=assessment_id,
                    system_id=system_id,
                    dimension=dimension,
                    verdict=verdict,
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
                    dimension=dimension,
                    verdict=verdict,
                )
                return record
            except ControllableAIError:
                self._burn(seq, "assess")
                raise

    # -- retire ---------------------------------------------------------------

    def retire(
        self, system_id: str, seq: int, reason: str = "manual"
    ) -> RetireRecord:
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
            except ControllableAIError:
                self._burn(seq, "retire")
                raise

    # -- pure-read views -------------------------------------------------------

    def _view_seq_ok(self, seq: int) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise SeqOrderError("view seq must be a non-negative int")

    def evaluate(self, system_id: str, seq: int) -> EvaluationReport:
        """Derive a digest-pinned controllability posture for one system (pure read).

        The posture is ledger-rule data, never measured truth:

        * ``unassessed`` when no assessments are booked;
        * ``uncontrollable`` when any booked verdict is
          ``uncontrollable``;
        * ``partially-controllable`` when any booked verdict is
          ``partially-controllable``;
        * ``contested`` when any booked verdict is ``inconclusive``;
        * ``controllable`` otherwise (every booked verdict controllable).

        ``integrity_ok`` reports whether every stored record for the
        system still verifies (tamper reported, never raised).
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
                for verdict in CONTROL_VERDICTS
            )
            if n_assessments == 0:
                posture = "unassessed"
            elif "uncontrollable" in verdicts:
                posture = "uncontrollable"
            elif "partially-controllable" in verdicts:
                posture = "partially-controllable"
            elif "inconclusive" in verdicts:
                posture = "contested"
            else:
                posture = "controllable"
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
                raise UnknownAssessmentError(f"unknown assessment: {assessment_id!r}")
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
                raise UnknownAssessmentError(f"unknown assessment: {assessment_id!r}")
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
    """Self-check: exercise the controllable-AI ledger end to end."""
    pin = "sha256:" + "ab" * 32
    c = ControllableAI()
    a1 = c.assess(
        "SYS-1", 1, dimension="oversight-efficacy",
        verdict="controllable", evidence_digest=pin,
    )
    a2 = c.assess("SYS-1", 2, dimension="shutdown-path", verdict="controllable")
    a3 = c.assess("SYS-2", 3, dimension="behavior-bounds", verdict="uncontrollable")
    assert a1.verify() and a2.verify() and a3.verify()
    assert a1.assessment_id == "ass-1" and a2.assessment_id == "ass-2"
    e1 = c.evaluate("SYS-1", 0)
    e2 = c.evaluate("SYS-2", 0)
    assert e1.posture == "controllable" and e2.posture == "uncontrollable"
    assert e1.verify() and e2.verify()
    v1 = c.verify("ass-1", 0)
    assert v1.verdict == "verified" and v1.verify()
    c.retire("SYS-2", 4, reason="system-decommissioned")
    assert c.evaluate("SYS-2", 0).posture == "uncontrollable"
    assert ControllableAI.stdlib_only()
    print("controllable-ai OK: assess, evaluate, verify, pins, audit")


if __name__ == "__main__":
    main()
