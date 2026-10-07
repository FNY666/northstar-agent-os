"""Weak-to-strong generalization governance ledger, Simulated.

Research note: OpenAI's weak-to-strong work (Burns et al., Dec 2023) asks
whether a strong model trained on weak (GPT-2-class) supervision can
generalize *past* the weak supervisor's mistakes rather than distilling
them. The safety question is what generalizes: capability recovery (the
strong model gets things right the weak supervisor got wrong) versus
error distillation (the strong model memorizes the weak supervisor's
errors), uncertain-region copying, or outright regression.

This module is deliberately distinct from ``weak_to_strong.py`` (the
measurement-instrument layer: declared weak labels vs. declared strong
predictions vs. caller-supplied ground truth, and the GapReport taxonomy
of error-distillation / error-recovery / regression / uncertain-copying):
it runs no trainer, checks no real labels, and leaks no weak or strong
model material. It is the *governance decision ledger* for declared
weak-to-strong generalization work. It books:

* **register_supervisor()** - declare one weak-supervisor identity over
  the pinned supervision-kind vocabulary; supervisor identity material
  travels as ``sha256:`` digest pins only - it never enters a record;
  ids are caller-supplied and never recycled.
* **generalize()** - book one declared generalization run: a strong-model
  system id, a registered supervisor, a pinned training method, and a
  host-declared outcome booked **as data** (never proof the strong model
  actually recovered capability); raw weak labels, strong weights, and
  outcome evidence travel as digest pins only; minted ``gen-N`` ids.
* **verify()** - pure-read digest re-derivation for one record
  (``verified`` / ``tampered`` as data); never proof of real
  generalization.
* **evaluate()** - pure-read derived generalization posture for one
  system by ledger rule (``unstarted`` / ``regressed`` /
  ``error-distilled`` / ``inconclusive`` / ``unevaluated`` /
  ``stalled`` / ``generalizing``) with ``integrity_ok`` as data; seq
  shape validated, never consumed, no audit row.
* **retire()** - terminal bookkeeping for a system or supervisor id;
  ids are never recycled; reads still work post-retire.

House style: frozen dataclasses, caller-supplied strictly-increasing int
seqs (claim-then-burn: failed mutations consume their seq and book a
``weak-to-strong-v2.rejected`` row; rewinds raise bare without consuming),
no wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with the
standard ``canonical_json`` try/except fallback, ``sha256:`` digest pins,
and ``audit.ndjson/1`` events.

Honest scope: a booked generalization is a host declaration that a
weak-to-strong training run happened with the declared method and
outcome - it is never proof the run happened, that the declared outcome
is true, or that the strong model is safe to deploy; a derived
``generalizing`` posture is ledger arithmetic over host-declared
outcomes, never evidence of real weak-to-strong generalization.
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
WEAK_TO_STRONG_V2_VERSION = "weak-to-strong-v2.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.weak-to-strong-v2.v1"

#: Pinned supervision-kind vocabulary (what the weak supervisor produced).
SUPERVISION_KINDS = (
    "labeling",
    "critique",
    "demonstration",
    "correction",
    "preference-pair",
    "oversight-check",
    "red-teaming",
    "gold-standard",
)

#: Pinned training-method vocabulary (how the strong model was trained).
METHOD_KINDS = (
    "finetuning",
    "distillation",
    "rlhf",
    "rlaif",
    "dpo",
    "constitutional",
    "process-supervision",
    "outcome-supervision",
)

#: Pinned outcome vocabulary (host-declared generalization outcome, as data).
OUTCOMES = (
    "not-evaluated",
    "capability-recovered",
    "partial-recovery",
    "error-distilled",
    "uncertain-copied",
    "regression",
    "no-generalization",
    "inconclusive",
)

#: Ledger-rule posture vocabulary derived by evaluate() (as data).
POSTURES = (
    "unstarted",
    "regressed",
    "error-distilled",
    "inconclusive",
    "unevaluated",
    "stalled",
    "generalizing",
)

#: Pinned retirement-reason vocabulary.
RETIRE_REASONS = (
    "manual",
    "system-superseded",
    "supervisor-retired",
    "invalidated",
)

#: Audit kinds emitted by this module.
AUDIT_KINDS = (
    "registered",
    "generalized",
    "retired",
    "rejected",
)

#: Keys that may never appear raw in an audit row (exact-key matching).
#: Declared-data keys (``kind``, ``method``, ``outcome``, ``posture``)
#: are pinned vocabulary values and remain emittable.
_BANNED_AUDIT_KEYS = frozenset(
    {
        "label",
        "labels",
        "weak_label",
        "weak_labels",
        "prediction",
        "predictions",
        "strong_prediction",
        "transcript",
        "reasoning",
        "weights",
        "gradient",
        "gradients",
        "reward",
        "feedback",
        "prompt",
        "response",
        "text",
        "data",
        "example",
        "content",
        "notes",
        "trajectory",
        "demonstration",
        "behavior",
        "preferences",
        "evidence",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class WeakToStrongV2Error(Exception):
    """Base error for weak-to-strong-v2 ledger misuse."""


class BadIdError(WeakToStrongV2Error):
    """Malformed system/supervisor/generalization id."""


class UnknownSystemError(WeakToStrongV2Error):
    """Reference to a system id that was never registered."""


class UnknownSupervisorError(WeakToStrongV2Error):
    """Reference to a supervisor id that was never registered."""


class UnknownGeneralizationError(WeakToStrongV2Error):
    """Reference to a generalization id that was never booked."""


class DuplicateIdError(WeakToStrongV2Error):
    """An id that is already taken was re-registered."""


class RetiredIdError(WeakToStrongV2Error):
    """A retired id can never be reused."""


class BadKindError(WeakToStrongV2Error):
    """Unknown supervision kind."""


class BadMethodError(WeakToStrongV2Error):
    """Unknown training method."""


class BadOutcomeError(WeakToStrongV2Error):
    """Unknown generalization outcome."""


class BadDigestError(WeakToStrongV2Error):
    """Malformed sha256 digest pin."""


class BadReasonError(WeakToStrongV2Error):
    """Unknown retirement reason."""


class SeqOrderError(WeakToStrongV2Error):
    """Caller seq did not strictly increase (or was not an int)."""


class AuditKindError(WeakToStrongV2Error):
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
class SupervisorRecord:
    """One declared weak-supervisor registration (digest pins only)."""

    supervisor_id: str
    kind: str
    supervisor_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "type": "supervisor",
            "version": WEAK_TO_STRONG_V2_VERSION,
            "supervisor_id": self.supervisor_id,
            "kind": self.kind,
            "supervisor_digest": self.supervisor_digest,
            "seq": self.seq,
        }

    def verify(self) -> bool:
        """Re-derive the digest pin; True only if untampered (as data)."""
        body = dict(self.as_dict())
        return _digest_pin(body) == self.digest


@dataclass(frozen=True)
class GeneralizationRecord:
    """One declared weak-to-strong generalization run (digest pins only)."""

    generalization_id: str
    system_id: str
    supervisor_id: str
    method: str
    outcome: str
    weak_digest: str
    strong_digest: str
    outcome_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "type": "generalization",
            "version": WEAK_TO_STRONG_V2_VERSION,
            "generalization_id": self.generalization_id,
            "system_id": self.system_id,
            "supervisor_id": self.supervisor_id,
            "method": self.method,
            "outcome": self.outcome,
            "weak_digest": self.weak_digest,
            "strong_digest": self.strong_digest,
            "outcome_digest": self.outcome_digest,
            "seq": self.seq,
        }

    def verify(self) -> bool:
        """Re-derive the digest pin; True only if untampered (as data)."""
        body = dict(self.as_dict())
        return _digest_pin(body) == self.digest


@dataclass(frozen=True)
class RetireRecord:
    """Terminal bookkeeping for a retired system or supervisor id."""

    target_id: str
    reason: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "type": "retire",
            "version": WEAK_TO_STRONG_V2_VERSION,
            "target_id": self.target_id,
            "reason": self.reason,
            "seq": self.seq,
        }

    def verify(self) -> bool:
        """Re-derive the digest pin; True only if untampered (as data)."""
        body = dict(self.as_dict())
        return _digest_pin(body) == self.digest


@dataclass(frozen=True)
class EvaluationReport:
    """Pure-read derived generalization posture for one system (as data)."""

    system_id: str
    posture: str
    n_generalizations: int
    outcome_tally: Tuple[Tuple[str, str], ...]
    integrity_ok: bool
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "type": "evaluation",
            "version": WEAK_TO_STRONG_V2_VERSION,
            "system_id": self.system_id,
            "posture": self.posture,
            "n_generalizations": self.n_generalizations,
            "outcome_tally": [list(pair) for pair in self.outcome_tally],
            "integrity_ok": self.integrity_ok,
            "seq": self.seq,
        }

    def verify(self) -> bool:
        """Re-derive the digest pin; True only if untampered (as data)."""
        body = dict(self.as_dict())
        return _digest_pin(body) == self.digest


@dataclass(frozen=True)
class VerificationReport:
    """Pure-read digest re-derivation verdict for one record (as data)."""

    record_id: str
    verdict: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "type": "verification",
            "version": WEAK_TO_STRONG_V2_VERSION,
            "record_id": self.record_id,
            "verdict": self.verdict,
            "seq": self.seq,
        }

    def verify(self) -> bool:
        """Re-derive the digest pin; True only if untampered (as data)."""
        body = dict(self.as_dict())
        return _digest_pin(body) == self.digest


def weak_to_strong_v2_audit_event(
    kind: str, seq: int, **details: Any
) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the weak-to-strong-v2 ledger."""
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


class WeakToStrong:
    """Weak-to-strong generalization governance ledger (Simulated).

    ``register_supervisor()`` / ``generalize()`` / ``retire()`` mutate the
    ledger and consume caller seqs; ``verify()``, ``evaluate()``, and all
    views are pure reads.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._supervisors: Dict[str, SupervisorRecord] = {}
        self._systems: Dict[str, List[str]] = {}
        self._generalizations: Dict[str, GeneralizationRecord] = {}
        self._retirements: Dict[str, RetireRecord] = {}
        self._retired: set = set()
        self._gen_counter = 0
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
            row = weak_to_strong_v2_audit_event(
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
        self._audit.append(weak_to_strong_v2_audit_event(audit_kind, seq, **details))

    def _view_seq_ok(self, seq: int) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise SeqOrderError("read seq must be a non-negative int")

    def _live_target(self, target_id: str) -> None:
        if target_id in self._retired:
            raise RetiredIdError(f"id retired forever: {target_id!r}")

    def _live_system(self, system_id: str) -> List[str]:
        self._live_target(system_id)
        gen_ids = self._systems.get(system_id)
        if gen_ids is None:
            raise UnknownSystemError(f"unknown system: {system_id!r}")
        return gen_ids

    def _live_supervisor(self, supervisor_id: str) -> None:
        self._live_target(supervisor_id)
        if supervisor_id not in self._supervisors:
            raise UnknownSupervisorError(f"unknown supervisor: {supervisor_id!r}")

    # -- register_supervisor -------------------------------------------------

    def register_supervisor(
        self,
        supervisor_id: str,
        seq: int,
        kind: str = "labeling",
        supervisor_digest: str = "",
    ) -> SupervisorRecord:
        """Declare one weak supervisor (caller-supplied id, never recycled).

        Raw supervisor material travels as digest pins only.
        """
        with self._lock:
            try:
                _require_id(supervisor_id, "supervisor_id")
                if supervisor_id in self._supervisors or supervisor_id in self._retired:
                    raise DuplicateIdError(
                        f"supervisor id taken or retired: {supervisor_id!r}"
                    )
                if kind not in SUPERVISION_KINDS:
                    raise BadKindError(f"unknown supervision kind: {kind!r}")
                _require_optional_digest(supervisor_digest, "supervisor_digest")
            except WeakToStrongV2Error as exc:
                try:
                    self._check_seq(seq)
                except SeqOrderError:
                    raise
                self._burn(seq, type(exc).__name__, supervisor_id=supervisor_id)
                raise
            self._claim(seq)
            rec = SupervisorRecord(
                supervisor_id=supervisor_id,
                kind=kind,
                supervisor_digest=supervisor_digest,
                seq=seq,
                digest="",
            )
            rec = SupervisorRecord(
                supervisor_id=rec.supervisor_id,
                kind=rec.kind,
                supervisor_digest=rec.supervisor_digest,
                seq=rec.seq,
                digest=_digest_pin(rec.as_dict()),
            )
            self._supervisors[supervisor_id] = rec
            self._emit(
                "registered",
                seq,
                supervisor_id=supervisor_id,
                supervision_kind=kind,
            )
            return rec

    # -- generalize ----------------------------------------------------------

    def generalize(
        self,
        system_id: str,
        supervisor_id: str,
        seq: int,
        method: str = "finetuning",
        outcome: str = "not-evaluated",
        weak_digest: str = "",
        strong_digest: str = "",
        outcome_digest: str = "",
    ) -> GeneralizationRecord:
        """Book one declared weak-to-strong generalization run (minted ``gen-N``).

        The outcome is booked **as data**, never proof the strong model
        actually recovered capability. First run on a system id registers
        the system.
        """
        with self._lock:
            try:
                _require_id(system_id, "system_id")
                self._live_supervisor(supervisor_id)
                self._live_target(system_id)
                if method not in METHOD_KINDS:
                    raise BadMethodError(f"unknown method: {method!r}")
                if outcome not in OUTCOMES:
                    raise BadOutcomeError(f"unknown outcome: {outcome!r}")
                _require_optional_digest(weak_digest, "weak_digest")
                _require_optional_digest(strong_digest, "strong_digest")
                _require_optional_digest(outcome_digest, "outcome_digest")
            except WeakToStrongV2Error as exc:
                try:
                    self._check_seq(seq)
                except SeqOrderError:
                    raise
                self._burn(
                    seq,
                    type(exc).__name__,
                    system_id=system_id,
                    supervisor_id=supervisor_id,
                )
                raise
            self._claim(seq)
            self._gen_counter += 1
            gen_id = f"gen-{self._gen_counter}"
            rec = GeneralizationRecord(
                generalization_id=gen_id,
                system_id=system_id,
                supervisor_id=supervisor_id,
                method=method,
                outcome=outcome,
                weak_digest=weak_digest,
                strong_digest=strong_digest,
                outcome_digest=outcome_digest,
                seq=seq,
                digest="",
            )
            rec = GeneralizationRecord(
                generalization_id=rec.generalization_id,
                system_id=rec.system_id,
                supervisor_id=rec.supervisor_id,
                method=rec.method,
                outcome=rec.outcome,
                weak_digest=rec.weak_digest,
                strong_digest=rec.strong_digest,
                outcome_digest=rec.outcome_digest,
                seq=rec.seq,
                digest=_digest_pin(rec.as_dict()),
            )
            self._generalizations[gen_id] = rec
            self._systems.setdefault(system_id, []).append(gen_id)
            self._emit(
                "generalized",
                seq,
                generalization_id=gen_id,
                system_id=system_id,
                supervisor_id=supervisor_id,
                method=method,
                outcome=outcome,
            )
            return rec

    # -- retire ---------------------------------------------------------------

    def retire(self, target_id: str, seq: int, reason: str = "manual") -> RetireRecord:
        """Terminal bookkeeping for a system or supervisor id (never recycled)."""
        with self._lock:
            try:
                _require_id(target_id, "target_id")
                if target_id in self._retired:
                    raise RetiredIdError(f"id already retired: {target_id!r}")
                if (
                    target_id not in self._systems
                    and target_id not in self._supervisors
                ):
                    raise UnknownSystemError(f"unknown target: {target_id!r}")
                if reason not in RETIRE_REASONS:
                    raise BadReasonError(f"unknown retire reason: {reason!r}")
            except WeakToStrongV2Error as exc:
                try:
                    self._check_seq(seq)
                except SeqOrderError:
                    raise
                self._burn(seq, type(exc).__name__, target_id=target_id)
                raise
            self._claim(seq)
            rec = RetireRecord(
                target_id=target_id,
                reason=reason,
                seq=seq,
                digest="",
            )
            rec = RetireRecord(
                target_id=rec.target_id,
                reason=rec.reason,
                seq=rec.seq,
                digest=_digest_pin(rec.as_dict()),
            )
            self._retired.add(target_id)
            self._retirements[target_id] = rec
            self._emit("retired", seq, target_id=target_id, reason=reason)
            return rec

    # -- pure reads -----------------------------------------------------------

    def verify(self, record_id: str, seq: int) -> VerificationReport:
        """Pure-read digest re-derivation for one record (as data)."""
        with self._lock:
            self._view_seq_ok(seq)
            _require_id(record_id, "record_id")
            rec = self._generalizations.get(record_id)
            if rec is None:
                rec = self._supervisors.get(record_id)
            if rec is None:
                rec = self._retirements.get(record_id)
            if rec is None:
                raise UnknownGeneralizationError(f"unknown record: {record_id!r}")
            verdict = "verified" if rec.verify() else "tampered"
            body = {
                "schema": SCHEMA_PIN,
                "type": "verification",
                "version": WEAK_TO_STRONG_V2_VERSION,
                "record_id": record_id,
                "verdict": verdict,
                "seq": seq,
            }
            return VerificationReport(
                record_id=record_id,
                verdict=verdict,
                seq=seq,
                digest=_digest_pin(body),
            )

    def _derive_posture(self, outcomes: List[str]) -> str:
        if not outcomes:
            return "unstarted"
        if "regression" in outcomes:
            return "regressed"
        if "error-distilled" in outcomes or "uncertain-copied" in outcomes:
            return "error-distilled"
        if "inconclusive" in outcomes:
            return "inconclusive"
        if all(o == "not-evaluated" for o in outcomes):
            return "unevaluated"
        if all(o == "no-generalization" for o in outcomes):
            return "stalled"
        if any(o in ("capability-recovered", "partial-recovery") for o in outcomes):
            return "generalizing"
        return "inconclusive"

    def evaluate(self, system_id: str, seq: int) -> EvaluationReport:
        """Pure-read derived generalization posture for one system (as data)."""
        with self._lock:
            self._view_seq_ok(seq)
            gen_ids = self._systems.get(system_id)
            if gen_ids is None:
                raise UnknownSystemError(f"unknown system: {system_id!r}")
            outcomes = [self._generalizations[g].outcome for g in gen_ids]
            tally: Dict[str, int] = {}
            for o in outcomes:
                tally[o] = tally.get(o, 0) + 1
            integrity_ok = all(
                self._generalizations[g].verify() for g in gen_ids
            )
            body = {
                "schema": SCHEMA_PIN,
                "type": "evaluation",
                "version": WEAK_TO_STRONG_V2_VERSION,
                "system_id": system_id,
                "posture": self._derive_posture(outcomes),
                "n_generalizations": len(gen_ids),
                "outcome_tally": [[k, str(v)] for k, v in sorted(tally.items())],
                "integrity_ok": integrity_ok,
                "seq": seq,
            }
            return EvaluationReport(
                system_id=system_id,
                posture=self._derive_posture(outcomes),
                n_generalizations=len(gen_ids),
                outcome_tally=tuple((k, str(v)) for k, v in sorted(tally.items())),
                integrity_ok=integrity_ok,
                seq=seq,
                digest=_digest_pin(body),
            )

    def supervisor_record(self, supervisor_id: str, seq: int) -> SupervisorRecord:
        """Fetch one supervisor record (pure read)."""
        with self._lock:
            self._view_seq_ok(seq)
            rec = self._supervisors.get(supervisor_id)
            if rec is None:
                raise UnknownSupervisorError(f"unknown supervisor: {supervisor_id!r}")
            return rec

    def generalization_record(self, generalization_id: str, seq: int) -> GeneralizationRecord:
        """Fetch one generalization record (pure read)."""
        with self._lock:
            self._view_seq_ok(seq)
            rec = self._generalizations.get(generalization_id)
            if rec is None:
                raise UnknownGeneralizationError(
                    f"unknown generalization: {generalization_id!r}"
                )
            return rec

    def generalizations_for(self, system_id: str, seq: int) -> Tuple[str, ...]:
        """Generalization ids booked for one system (pure read)."""
        with self._lock:
            self._view_seq_ok(seq)
            gen_ids = self._systems.get(system_id)
            if gen_ids is None:
                raise UnknownSystemError(f"unknown system: {system_id!r}")
            return tuple(gen_ids)

    def system_ids(self, seq: int) -> Tuple[str, ...]:
        """All registered system ids (pure read)."""
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(sorted(self._systems))

    def supervisor_ids(self, seq: int) -> Tuple[str, ...]:
        """All registered supervisor ids (pure read)."""
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(sorted(self._supervisors))

    def generalization_ids(self, seq: int) -> Tuple[str, ...]:
        """All minted generalization ids (pure read)."""
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(sorted(self._generalizations))

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        """All retired ids (pure read)."""
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(sorted(self._retired))

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
                "supervisors": len(self._supervisors),
                "generalizations": len(self._generalizations),
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
    """Self-check: exercise the weak-to-strong-v2 ledger end to end."""
    pin = "sha256:" + "ab" * 32
    w = WeakToStrong()
    w.register_supervisor("SUP-W", 1, kind="labeling", supervisor_digest=pin)
    g1 = w.generalize(
        "SYS-A",
        "SUP-W",
        2,
        method="finetuning",
        outcome="capability-recovered",
        weak_digest=pin,
        strong_digest=pin,
        outcome_digest=pin,
    )
    g2 = w.generalize(
        "SYS-A",
        "SUP-W",
        3,
        method="rlhf",
        outcome="partial-recovery",
        outcome_digest=pin,
    )
    assert g1.verify() and g2.verify()
    assert g1.generalization_id == "gen-1" and g2.generalization_id == "gen-2"
    e1 = w.evaluate("SYS-A", 0)
    assert e1.posture == "generalizing" and e1.integrity_ok
    assert e1.verify()
    v1 = w.verify("gen-1", 0)
    assert v1.verdict == "verified" and v1.verify()
    w.retire("SYS-A", 4, reason="system-superseded")
    assert w.evaluate("SYS-A", 0).posture == "generalizing"
    assert WeakToStrong.stdlib_only()
    print("weak-to-strong-v2 OK: register, generalize, verify, evaluate, pins, audit")


if __name__ == "__main__":
    main()
