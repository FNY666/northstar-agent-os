"""AlignedAI: alignment-assessment decision ledger, Simulated.

Research note: an "aligned" AI system is one whose behavior is aligned
with human intent and values - helpful, harmless, honest, obedient to
its principals, faithful to their informed preferences, respectful of
their autonomy, fair, and careful. Nobody can directly *measure*
alignment; what practitioners book are declared assessments: a human
evaluator, red-teamer, auditor, or monitoring pipeline declares that a
system was assessed along some alignment dimension and books the
declared verdict. This module is that *decision ledger*: which systems
had which declared assessments booked, what verdicts were declared
against them, and what alignment posture the ledger derives - defensible
bookkeeping, never proof that a system is really aligned.

This module owns the assess -> verify -> evaluate lifecycle:

* **assess()** - book one declared alignment assessment (minted
  ``asm-N`` ids; pinned dimension vocabulary over the canonical
  alignment dimensions; pinned verdict vocabulary booked *as data*);
  the first assessment registers its system; raw transcripts, labels,
  and weights never enter records - digest pins only.
* **verify()** - **pure read**: re-derive one assessment's digest pin;
  verdict ``verified`` / ``tampered`` booked as data, never as proof
  the assessment really happened.
* **evaluate()** - **pure read**: derive one system's alignment posture
  as data (``unevaluated`` -> ``misaligned`` -> ``contested`` ->
  ``aligned``) with verdict tallies and a digest-pinned integrity flag.
* **retire()** - terminal retirement of a system id; ids are never
  recycled.

Distinct-layer rationale vs siblings: ``ai_alignment.py`` (sibling
batch-61 work) owns the broad alignment-ledger mechanics, and
``trustworthy_ai.py`` / ``responsible_ai.py`` / ``ai_safety.py``
own their own trust/responsibility/safety ledgers - this module is
the alignment-*assessment*-specific ledger: declared assessments
along pinned alignment dimensions, declared verdicts, digest
re-derivation, and the ledger-rule posture that turns assessment
verdicts into an alignment claim ("no known misalignment declared"),
always as data, never as measured truth.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
an ``aligned-ai.rejected`` row; rewinds raise bare without
consuming), no wall-clock, RLock guarding, fail-closed taxonomy,
stdlib-only with the standard ``canonical_json`` try/except fallback,
``sha256:`` digest pins, and ``audit.ndjson/1`` events.

Honest scope: this module runs no systems, performs no evaluations,
measures no alignment, and proves nothing about real alignment. A
booked ``aligned`` verdict means "the host declared it", never "the
system is aligned". Transcripts, labels, traces, weights, reward logs,
and raw evaluation records never enter records or cross the audit
boundary - digest pins only.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

try:
    from canonical_json import jcs_dumps as _jcs_dumps  # type: ignore
except Exception:  # pragma: no cover - fallback when canonical_json is absent

    def _jcs_dumps(obj: Any) -> bytes:  # type: ignore
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


#: Module version pin.
ALIGNED_AI_VERSION = "aligned-ai.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.aligned-ai.v1"

#: Pinned alignment-dimension vocabulary (what was assessed).
DIMENSIONS = (
    "helpfulness",
    "harmlessness",
    "honesty",
    "obedience",
    "fidelity",
    "autonomy-respect",
    "fairness",
    "care",
)

#: Pinned assessment-verdict vocabulary (booked as data, never proof).
VERDICTS = (
    "aligned",
    "misaligned",
    "uncertain",
    "inconclusive",
)

#: Pinned derived postures (booked as data).
POSTURES = (
    "unevaluated",
    "misaligned",
    "contested",
    "aligned",
)

#: Pinned retirement-reason vocabulary.
RETIRE_REASONS = (
    "manual",
    "superseded",
    "decommissioned",
    "false-start",
)

#: Audit kinds emitted by this module.
AUDIT_KINDS = (
    "assessed",
    "retired",
    "rejected",
)

#: Keys that may never appear raw in an audit row.
_BANNED_AUDIT_KEYS = frozenset(
    {
        "weights",
        "model_weights",
        "parameters",
        "params",
        "policy",
        "policies",
        "trajectory",
        "trajectories",
        "transcript",
        "transcripts",
        "log",
        "logs",
        "trace",
        "traces",
        "telemetry",
        "recording",
        "recordings",
        "dump",
        "dumps",
        "snapshot",
        "snapshots",
        "memory",
        "weights_file",
        "checkpoint_data",
        "state",
        "internal_state",
        "hidden_state",
        "activations",
        "gradients",
        "prompt",
        "prompts",
        "response",
        "responses",
        "output",
        "outputs",
        "command_output",
        "shell_output",
        "stderr",
        "stdout",
        "label",
        "labels",
        "annotation",
        "annotations",
        "reward",
        "rewards",
        "preference",
        "preferences",
        "feedback",
        "evaluator_note",
        "evaluator_notes",
    }
)


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class AlignedAIError(Exception):
    """Base class for all aligned-ai errors."""


class BadSystemError(AlignedAIError):
    """system_id is not a non-empty string."""


class DuplicateSystemError(AlignedAIError):
    """A retired system id may never be re-registered."""


class UnknownSystemError(AlignedAIError):
    """No such system is registered in the ledger."""


class RetiredSystemError(AlignedAIError):
    """The system is retired; mutations are refused."""


class BadDimensionError(AlignedAIError):
    """dimension is not in the pinned vocabulary."""


class BadVerdictError(AlignedAIError):
    """verdict is not in the pinned vocabulary."""


class BadDigestError(AlignedAIError):
    """A digest pin is malformed (must be '' or 'sha256:' + 64 hex)."""


class BadReasonError(AlignedAIError):
    """reason is not in the pinned vocabulary."""


class UnknownAssessmentError(AlignedAIError):
    """No such assessment id is booked in the ledger."""


class SeqOrderError(AlignedAIError):
    """seq is not a strictly increasing int (claim-then-burn)."""


class AuditKindError(AlignedAIError):
    """Unknown audit kind requested from the audit builder."""


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str) or not value.strip():
        raise BadSystemError(f"{what} must be a non-empty string")
    return value


def _check_dimension(value: Any) -> str:
    if value not in DIMENSIONS:
        raise BadDimensionError(f"dimension must be one of {DIMENSIONS}")
    return value


def _check_verdict(value: Any) -> str:
    if value not in VERDICTS:
        raise BadVerdictError(f"verdict must be one of {VERDICTS}")
    return value


def _check_digest(value: Any, what: str, allow_empty: bool = True) -> str:
    if value == "" and allow_empty:
        return ""
    if (
        isinstance(value, bool)
        or not isinstance(value, str)
        or not value.startswith("sha256:")
        or len(value) != 71
    ):
        raise BadDigestError(f"{what} must be '' or 'sha256:' + 64 hex chars")
    hexpart = value[7:]
    if any(c not in "0123456789abcdef" for c in hexpart):
        raise BadDigestError(f"{what} must be '' or 'sha256:' + 64 hex chars")
    return value


def _check_reason(value: Any) -> str:
    if value not in RETIRE_REASONS:
        raise BadReasonError(f"reason must be one of {RETIRE_REASONS}")
    return value


def _canonical_bytes(payload: Any) -> bytes:
    raw = _jcs_dumps(payload)
    return raw if isinstance(raw, bytes) else raw.encode("utf-8")


def _digest_pin(payload: Any, tag: str) -> str:
    body = {"tag": tag, "schema": SCHEMA_PIN, "payload": payload}
    return "sha256:" + hashlib.sha256(_canonical_bytes(body)).hexdigest()


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError("seq must be an int")
    return seq


# ---------------------------------------------------------------------------
# Records (frozen)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AssessmentRecord:
    assessment_id: str
    system_id: str
    seq: int
    dimension: str
    verdict: str
    assessment_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _assessment_payload(self), "aligned-ai.assess"
        )


@dataclass(frozen=True)
class RetireRecord:
    system_id: str
    seq: int
    reason: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _retire_payload(self), "aligned-ai.retire"
        )


@dataclass(frozen=True)
class VerificationReport:
    assessment_id: str
    seq: int
    verdict: str
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _verify_payload(self), "aligned-ai.verify"
        )


@dataclass(frozen=True)
class EvaluationReport:
    system_id: str
    seq: int
    posture: str
    n_assessments: int
    n_aligned: int
    n_misaligned: int
    n_uncertain: int
    n_inconclusive: int
    integrity_ok: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            _evaluate_payload(self), "aligned-ai.evaluate"
        )


def _assessment_payload(rec: "AssessmentRecord") -> Dict[str, Any]:
    return {
        "assessment_id": rec.assessment_id,
        "system_id": rec.system_id,
        "seq": rec.seq,
        "dimension": rec.dimension,
        "verdict": rec.verdict,
        "assessment_digest": rec.assessment_digest,
    }


def _retire_payload(rec: "RetireRecord") -> Dict[str, Any]:
    return {"system_id": rec.system_id, "seq": rec.seq, "reason": rec.reason}


def _verify_payload(rep: "VerificationReport") -> Dict[str, Any]:
    return {
        "assessment_id": rep.assessment_id,
        "seq": rep.seq,
        "verdict": rep.verdict,
        "integrity_ok": rep.integrity_ok,
    }


def _evaluate_payload(rep: "EvaluationReport") -> Dict[str, Any]:
    return {
        "system_id": rep.system_id,
        "seq": rep.seq,
        "posture": rep.posture,
        "n_assessments": rep.n_assessments,
        "n_aligned": rep.n_aligned,
        "n_uncertain": rep.n_uncertain,
        "n_misaligned": rep.n_misaligned,
        "n_inconclusive": rep.n_inconclusive,
        "integrity_ok": rep.integrity_ok,
    }


def aligned_ai_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` row for this module.

    Fail-closed: unknown kinds raise; any banned key appearing raw in
    ``detail`` raises (digest pins of those values are fine - the key ban
    applies to raw material).
    """
    if kind not in AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if not isinstance(seq, int) or isinstance(seq, bool):
        raise SeqOrderError("seq must be an int")
    for key in detail:
        if key in _BANNED_AUDIT_KEYS:
            raise AlignedAIError(
                f"raw key {key!r} may not cross the audit boundary"
            )
    return {
        "schema": "audit.ndjson/1",
        "module": "aligned-ai",
        "version": ALIGNED_AI_VERSION,
        "kind": kind,
        "seq": seq,
        "details": dict(detail),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class AlignedAI:
    """Alignment-assessment decision ledger, Simulated.

    Deterministic single-host state machine: frozen dataclass records,
    caller-supplied strictly-increasing int seqs (claim-then-burn), no
    wall-clock, RLock-guarded, fail-closed. All verdicts are booked as
    data - never proof that a system is really aligned.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._assessments: Dict[str, AssessmentRecord] = {}
        self._system_assessments: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._assessment_counter = 0
        self._audit: List[Dict[str, Any]] = []

    # -- seq discipline ----------------------------------------------------

    def _require_seq(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError("seq must strictly increase")
        return seq

    def _require_read_seq(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq < 0:
            raise SeqOrderError("seq must be non-negative")
        return seq

    def _claim(self, seq: int) -> int:
        self._require_seq(seq)
        self._seq = seq
        return seq

    def _burn(self, seq: int, kind: str, **details: Any) -> None:
        self._seq = seq
        try:
            row = aligned_ai_audit_event(
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
        self._audit.append(aligned_ai_audit_event(audit_kind, seq, **details))

    def _require_live(self, system_id: str) -> None:
        if system_id in self._retired:
            raise RetiredSystemError(f"system is retired: {system_id!r}")

    # -- mutations ---------------------------------------------------------

    def assess(
        self,
        system_id: str,
        seq: int,
        dimension: str = "helpfulness",
        verdict: str = "aligned",
        assessment_digest: str = "",
    ) -> AssessmentRecord:
        """Book one declared alignment assessment; mint an ``asm-N`` id.

        The first assessment on an id registers the system. Raw
        transcripts, labels, traces, and weights never enter records -
        digest pins only. Fail-closed: failed mutations consume their
        seq and book an ``aligned-ai.rejected`` row; rewinds raise bare.
        """
        with self._lock:
            try:
                system_id = _check_id(system_id, "system_id")
                self._require_seq(seq)
                dimension = _check_dimension(dimension)
                verdict = _check_verdict(verdict)
                assessment_digest = _check_digest(assessment_digest, "assessment_digest")
                self._require_live(system_id)
            except AlignedAIError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            self._assessment_counter += 1
            assessment_id = f"asm-{self._assessment_counter}"
            provisional = AssessmentRecord(
                assessment_id=assessment_id,
                system_id=system_id,
                seq=seq,
                dimension=dimension,
                verdict=verdict,
                assessment_digest=assessment_digest,
                digest="",
            )
            digest = _digest_pin(_assessment_payload(provisional), "aligned-ai.assess")
            rec = AssessmentRecord(
                assessment_id=assessment_id,
                system_id=system_id,
                seq=seq,
                dimension=dimension,
                verdict=verdict,
                assessment_digest=assessment_digest,
                digest=digest,
            )
            self._assessments[assessment_id] = rec
            self._system_assessments.setdefault(system_id, []).append(assessment_id)
            self._emit(
                "assessed",
                seq,
                assessment_id=assessment_id,
                system_id=system_id,
                dimension=dimension,
                verdict=verdict,
            )
            return rec

    def retire(self, system_id: str, seq: int, reason: str = "manual") -> RetireRecord:
        """Terminally retire a system id; ids are never recycled."""
        with self._lock:
            try:
                system_id = _check_id(system_id, "system_id")
                self._require_seq(seq)
                reason = _check_reason(reason)
                if system_id not in self._system_assessments:
                    raise UnknownSystemError(f"unknown system: {system_id!r}")
                if system_id in self._retired:
                    raise RetiredSystemError(f"already retired: {system_id!r}")
            except AlignedAIError as exc:
                if isinstance(exc, SeqOrderError):
                    raise
                self._burn(seq, type(exc).__name__)
                raise
            self._claim(seq)
            provisional = RetireRecord(
                system_id=system_id, seq=seq, reason=reason, digest=""
            )
            rec = RetireRecord(
                system_id=system_id,
                seq=seq,
                reason=reason,
                digest=_digest_pin(_retire_payload(provisional), "aligned-ai.retire"),
            )
            self._retired[system_id] = rec
            self._emit("retired", seq, system_id=system_id, reason=reason)
            return rec

    # -- pure reads ---------------------------------------------------------

    def verify(self, assessment_id: str, seq: int) -> VerificationReport:
        """Pure read: re-derive one assessment's digest pin.

        The seq is shape-validated but never consumed and no audit row
        is booked. Tamper is reported as data, never raised.
        """
        with self._lock:
            self._require_read_seq(seq)
            assessment_id = _check_id(assessment_id, "assessment_id")
            rec = self._assessments.get(assessment_id)
            if rec is None:
                raise UnknownAssessmentError(f"unknown assessment: {assessment_id!r}")
            integrity_ok = rec.verify()
            provisional = VerificationReport(
                assessment_id=assessment_id,
                seq=seq,
                verdict="verified" if integrity_ok else "tampered",
                integrity_ok=integrity_ok,
                digest="",
            )
            return VerificationReport(
                assessment_id=assessment_id,
                seq=seq,
                verdict=provisional.verdict,
                integrity_ok=integrity_ok,
                digest=_digest_pin(_verify_payload(provisional), "aligned-ai.verify"),
            )

    def evaluate(self, system_id: str, seq: int) -> EvaluationReport:
        """Pure read: derive one system's alignment posture as data.

        Ledger rule: ``unevaluated`` (no assessments) -> ``misaligned``
        (any declared ``misaligned``) -> ``contested`` (any declared
        ``uncertain`` or ``inconclusive``) -> ``aligned`` (all declared
        ``aligned``). ``integrity_ok`` re-derives every in-scope digest
        as data (tamper reported, never raised). The seq is
        shape-validated but never consumed and no audit row is booked.
        """
        with self._lock:
            self._require_read_seq(seq)
            system_id = _check_id(system_id, "system_id")
            ids = self._system_assessments.get(system_id)
            if ids is None:
                raise UnknownSystemError(f"unknown system: {system_id!r}")
            n_aligned = n_misaligned = n_uncertain = n_inconclusive = 0
            integrity_ok = True
            for assessment_id in ids:
                rec = self._assessments[assessment_id]
                if not rec.verify():
                    integrity_ok = False
                if rec.verdict == "aligned":
                    n_aligned += 1
                elif rec.verdict == "misaligned":
                    n_misaligned += 1
                elif rec.verdict == "uncertain":
                    n_uncertain += 1
                else:
                    n_inconclusive += 1
            if n_misaligned:
                posture = "misaligned"
            elif n_uncertain or n_inconclusive:
                posture = "contested"
            elif n_aligned:
                posture = "aligned"
            else:
                posture = "unevaluated"
            provisional = EvaluationReport(
                system_id=system_id,
                seq=seq,
                posture=posture,
                n_assessments=len(ids),
                n_aligned=n_aligned,
                n_misaligned=n_misaligned,
                n_uncertain=n_uncertain,
                n_inconclusive=n_inconclusive,
                integrity_ok=integrity_ok,
                digest="",
            )
            return EvaluationReport(
                system_id=system_id,
                seq=seq,
                posture=posture,
                n_assessments=len(ids),
                n_aligned=n_aligned,
                n_misaligned=n_misaligned,
                n_uncertain=n_uncertain,
                n_inconclusive=n_inconclusive,
                integrity_ok=integrity_ok,
                digest=_digest_pin(_evaluate_payload(provisional), "aligned-ai.evaluate"),
            )

    # -- pure-read views ----------------------------------------------------

    def assessment_record(self, assessment_id: str, seq: int) -> AssessmentRecord:
        """Pure read: fetch one booked assessment."""
        with self._lock:
            self._require_read_seq(seq)
            assessment_id = _check_id(assessment_id, "assessment_id")
            rec = self._assessments.get(assessment_id)
            if rec is None:
                raise UnknownAssessmentError(f"unknown assessment: {assessment_id!r}")
            return rec

    def system_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read: ids of systems with booked assessments."""
        with self._lock:
            self._require_read_seq(seq)
            return tuple(self._system_assessments)

    def assessment_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read: booked assessment ids."""
        with self._lock:
            self._require_read_seq(seq)
            return tuple(self._assessments)

    def assessments_for(self, system_id: str, seq: int) -> Tuple[str, ...]:
        """Pure read: assessment ids booked for one system."""
        with self._lock:
            self._require_read_seq(seq)
            system_id = _check_id(system_id, "system_id")
            ids = self._system_assessments.get(system_id)
            if ids is None:
                raise UnknownSystemError(f"unknown system: {system_id!r}")
            return tuple(ids)

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read: retired system ids."""
        with self._lock:
            self._require_read_seq(seq)
            return tuple(self._retired)

    def stats(self, seq: int) -> Dict[str, Any]:
        """Pure read: ledger counters."""
        with self._lock:
            self._require_read_seq(seq)
            return {
                "schema": SCHEMA_PIN,
                "version": ALIGNED_AI_VERSION,
                "seq": self._seq,
                "n_systems": len(self._system_assessments),
                "n_assessments": len(self._assessments),
                "n_retired": len(self._retired),
                "n_audit_rows": len(self._audit),
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        """Pure read: the audit rows booked so far."""
        with self._lock:
            self._require_read_seq(seq)
            return tuple(self._audit)


def stdlib_only() -> bool:
    """AST self-check: the module imports stdlib names only."""
    import ast
    from pathlib import Path

    allowed = {
        "hashlib",
        "json",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
        "ast",
        "pathlib",
        "canonical_json",
    }
    tree = ast.parse(Path(__file__).read_text())
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
    """Self-check: exercise assess/verify/evaluate/retire and print status."""
    assert stdlib_only(), "stdlib-only AST self-check failed"
    ledger = AlignedAI()
    rec = ledger.assess("sys-1", 1, dimension="honesty", verdict="aligned")
    assert rec.verify()
    assert ledger.verify(rec.assessment_id, 2).verdict == "verified"
    assert ledger.evaluate("sys-1", 3).posture == "aligned"
    ledger.retire("sys-1", 4)
    print("aligned-ai OK: assess, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
