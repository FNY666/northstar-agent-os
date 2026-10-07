"""Amplification / distillation decision ledger, Simulated.

Research note: iterated distillation and amplification (IDA, Christiano)
scales oversight by *amplifying* a weak agent (decomposing a task into
subtasks, consulting copies of itself, aggregating answers) and then
*distilling* the amplified behavior back into a model. The dangerous
half of the loop is the raw material: task contents, subtask trees,
overseer answers, transcripts, source/target weights, reward signals.
Those must never be bundled with the bookkeeping record that tracks
the loop's lifecycle.

This module is that bookkeeping layer. It:

* **amplify()** - book one declared amplification run (minted ``amp-N``
  ids) over a pinned strategy vocabulary (task-decomposition, debate,
  recursive-reward-modeling, ...); the first run on an id registers the
  task; overseer/task material travels as ``sha256:`` digest pins only.
* **distill()** - book one declared distillation (minted ``dst-N`` ids)
  of a booked amplification into a target model over a pinned method
  vocabulary; the distilled behavior is data, never proof a real model
  learned the amplified behavior.
* **verify()** - pure-read re-derivation of a booked record's digest pin;
  the verdict (``verified`` / ``tampered``) is data, never proof the
  real amplification or distillation ran.
* **retire()** - terminal; retired task ids are never recycled.

Distinct layer vs ``iterated_amplification.py``: that module is the
structural production primitive (decomposition tree, lineage, budget
caps, combination bookkeeping, distillation pairs). This module is the
decision ledger for the IDA governance loop: declared strategies,
declared distillations, declared verifications - all booked as data.

House style: frozen dataclasses, caller-supplied strictly-increasing int
seqs (claim-then-burn: failed mutations consume their seq and book an
``amplification.rejected`` row; rewinds raise bare without consuming), no
wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only with the
standard ``canonical_json`` try/except fallback, ``sha256:`` digest pins,
and ``audit.ndjson/1`` events.

Honest scope: a booked ``aligned`` is a host-declared claim, never proof
the amplified behavior was aligned; a booked ``verified`` re-derives a
digest pin, never proof a real amplification or distillation executed; a
booked distillation books the *decision* to distill, never the trained
model.
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
AMPLIFICATION_VERSION = "amplification.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.amplification.v1"

#: Pinned amplification-strategy vocabulary (declared, never proof a real
#: amplification ran).
AMPLIFICATION_STRATEGIES = (
    "task-decomposition",
    "debate",
    "recursive-reward-modeling",
    "market-making",
    "imitative-generalization",
    "assistance-games",
    "deliberation",
    "consultation",
)

#: Pinned distillation-method vocabulary (declared, never proof a real
#: distillation trained).
DISTILLATION_METHODS = (
    "behavioral-cloning",
    "knowledge-distillation",
    "rl-distillation",
    "supervised-finetune",
    "constitutional-distillation",
    "dpo-distillation",
    "self-distillation",
    "iterative-distillation",
)

#: Pinned amplification-run outcome vocabulary (declared as data).
AMPLIFY_OUTCOMES = (
    "aligned",
    "misaligned",
    "inconclusive",
    "not-run",
)

#: Pinned distillation outcome vocabulary (declared as data).
DISTILL_OUTCOMES = (
    "faithful",
    "lossy",
    "divergent",
    "incomplete",
)

#: Pinned verification verdict vocabulary (derived as data).
VERIFICATION_VERDICTS = (
    "verified",
    "tampered",
)

#: Pinned derived task postures for status().
TASK_POSTURES = (
    "not-run",
    "amplified",
    "inconclusive",
    "suspect",
    "distilled",
)

#: Pinned retirement reasons.
RETIRE_REASONS = (
    "manual",
    "superseded",
    "cycle-complete",
    "task-withdrawn",
)

#: Audit kinds emitted by this module.
AUDIT_KINDS = (
    "amplified",
    "distilled",
    "retired",
    "rejected",
)

#: Keys that may never appear raw in an audit row (exact-key matching).
_BANNED_AUDIT_KEYS = frozenset(
    {
        "transcript",
        "transcripts",
        "subtask",
        "subtasks",
        "subquery",
        "subqueries",
        "answer",
        "answers",
        "prompt",
        "prompts",
        "response",
        "responses",
        "overseer",
        "overseer_notes",
        "notes",
        "evidence",
        "weights",
        "activations",
        "trace",
        "reasoning",
        "stimulus",
        "dataset",
        "text",
        "content",
        "data",
        "raw",
        "secret",
        "description",
        "details",
        "detail",
        "model",
        "label",
        "labels",
        "reward",
        "trajectory",
        "score",
        "scores",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class AmplificationError(Exception):
    """Base error for amplification-ledger misuse."""


class BadIdError(AmplificationError):
    """Malformed task / amplification / distillation / record id."""


class BadDigestError(AmplificationError):
    """Malformed sha256: digest pin."""


class BadStrategyError(AmplificationError):
    """Amplification strategy outside the pinned vocabulary."""


class BadMethodError(AmplificationError):
    """Distillation method outside the pinned vocabulary."""


class BadOutcomeError(AmplificationError):
    """Outcome outside the pinned vocabulary."""


class BadReasonError(AmplificationError):
    """Retirement reason outside the pinned vocabulary."""


class UnknownTaskError(AmplificationError):
    """Reference to a task id that was never amplified."""


class UnknownAmplificationError(AmplificationError):
    """Reference to an amplification id that was never booked."""


class UnknownRecordError(AmplificationError):
    """verify() referenced a record id that was never booked."""


class RetiredTaskError(AmplificationError):
    """Mutation attempted against a retired task."""


class SeqOrderError(AmplificationError):
    """Caller seq did not strictly increase."""


class AuditKindError(AmplificationError):
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
class AmplificationRecord:
    """One declared amplification run (minted amp-N ids)."""

    amplification_id: str
    task_id: str
    strategy: str
    outcome: str
    overseer_digest: str
    task_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "amplification_id": self.amplification_id,
            "task_id": self.task_id,
            "strategy": self.strategy,
            "outcome": self.outcome,
            "overseer_digest": self.overseer_digest,
            "task_digest": self.task_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "amplification_id": self.amplification_id,
                "task_id": self.task_id,
                "strategy": self.strategy,
                "outcome": self.outcome,
                "overseer_digest": self.overseer_digest,
                "task_digest": self.task_digest,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class DistillationRecord:
    """One declared distillation of a booked amplification (minted dst-N)."""

    distillation_id: str
    amplification_id: str
    target_model_id: str
    method: str
    outcome: str
    source_digest: str
    target_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "distillation_id": self.distillation_id,
            "amplification_id": self.amplification_id,
            "target_model_id": self.target_model_id,
            "method": self.method,
            "outcome": self.outcome,
            "source_digest": self.source_digest,
            "target_digest": self.target_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "distillation_id": self.distillation_id,
                "amplification_id": self.amplification_id,
                "target_model_id": self.target_model_id,
                "method": self.method,
                "outcome": self.outcome,
                "source_digest": self.source_digest,
                "target_digest": self.target_digest,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class VerificationReport:
    """Pure-read re-derivation of a booked record's digest pin, as data."""

    record_id: str
    record_kind: str
    verdict: str
    integrity_ok: bool
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "record_id": self.record_id,
            "record_kind": self.record_kind,
            "verdict": self.verdict,
            "integrity_ok": self.integrity_ok,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "record_id": self.record_id,
                "record_kind": self.record_kind,
                "verdict": self.verdict,
                "integrity_ok": self.integrity_ok,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class RetireRecord:
    """Terminal retirement of a task's amplification lifecycle."""

    task_id: str
    reason: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "task_id": self.task_id,
            "reason": self.reason,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "task_id": self.task_id,
                "reason": self.reason,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class TaskStatus:
    """Pure-read derived posture of one task's amplification lifecycle."""

    task_id: str
    n_runs: int
    n_distillations: int
    posture: str
    integrity_ok: bool
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "task_id": self.task_id,
            "n_runs": self.n_runs,
            "n_distillations": self.n_distillations,
            "posture": self.posture,
            "integrity_ok": self.integrity_ok,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "task_id": self.task_id,
                "n_runs": self.n_runs,
                "n_distillations": self.n_distillations,
                "posture": self.posture,
                "integrity_ok": self.integrity_ok,
            }
        )


# ---------------------------------------------------------------------------
# Audit builder
# ---------------------------------------------------------------------------


def amplification_audit_event(kind: str, seq: int, **details: Any) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the amplification ledger."""
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


class Amplification:
    """Amplification / distillation decision ledger (Simulated).

    ``amplify()`` / ``distill()`` / ``retire()`` mutate the ledger and
    consume caller seqs; ``verify()`` and all views are pure reads.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._runs: Dict[str, AmplificationRecord] = {}
        self._task_runs: Dict[str, List[str]] = {}
        self._distillations: Dict[str, DistillationRecord] = {}
        self._run_distillations: Dict[str, List[str]] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._run_counter = 0
        self._distill_counter = 0
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
            row = amplification_audit_event("rejected", seq, rejected_kind=kind, **details)
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(amplification_audit_event(audit_kind, seq, **details))

    def _require_live(self, task_id: str) -> None:
        if task_id in self._retired:
            raise RetiredTaskError(f"task is retired: {task_id!r}")

    # -- amplify ---------------------------------------------------------------

    def amplify(
        self,
        task_id: str,
        seq: int,
        strategy: str = "task-decomposition",
        outcome: str = "not-run",
        overseer_digest: str = "",
        task_digest: str = "",
    ) -> AmplificationRecord:
        """Book one declared amplification run for a task.

        The first run on an id registers the task; raw overseer/task
        material never enters records (digest pins only). The outcome is
        data, never proof a real amplification ran.
        """
        with self._lock:
            self._claim(seq)
            try:
                _require_id(task_id, "task_id")
                if strategy not in AMPLIFICATION_STRATEGIES:
                    raise BadStrategyError(f"bad strategy: {strategy!r}")
                if outcome not in AMPLIFY_OUTCOMES:
                    raise BadOutcomeError(f"bad outcome: {outcome!r}")
                overseer_digest = _require_optional_digest(overseer_digest, "overseer_digest")
                task_digest = _require_optional_digest(task_digest, "task_digest")
                self._require_live(task_id)
                self._run_counter += 1
                amplification_id = f"amp-{self._run_counter}"
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "amplification_id": amplification_id,
                        "task_id": task_id,
                        "strategy": strategy,
                        "outcome": outcome,
                        "overseer_digest": overseer_digest,
                        "task_digest": task_digest,
                        "seq": seq,
                    }
                )
                record = AmplificationRecord(
                    amplification_id=amplification_id,
                    task_id=task_id,
                    strategy=strategy,
                    outcome=outcome,
                    overseer_digest=overseer_digest,
                    task_digest=task_digest,
                    seq=seq,
                    digest=digest,
                )
                self._runs[amplification_id] = record
                self._task_runs.setdefault(task_id, []).append(amplification_id)
                self._emit(
                    "amplified",
                    seq,
                    amplification_id=amplification_id,
                    task_id=task_id,
                    strategy=strategy,
                    outcome=outcome,
                )
                return record
            except AmplificationError:
                self._burn(seq, "amplify")
                raise

    # -- distill ---------------------------------------------------------------

    def distill(
        self,
        amplification_id: str,
        target_model_id: str,
        seq: int,
        method: str = "behavioral-cloning",
        outcome: str = "faithful",
        source_digest: str = "",
        target_digest: str = "",
    ) -> DistillationRecord:
        """Book one declared distillation of a booked amplification.

        Books the *decision* to distill, never the trained model; the
        outcome is data, never proof the target learned the amplified
        behavior. Distillations of one run form a repeatable chain.
        """
        with self._lock:
            self._claim(seq)
            try:
                _require_id(amplification_id, "amplification_id")
                _require_id(target_model_id, "target_model_id")
                if method not in DISTILLATION_METHODS:
                    raise BadMethodError(f"bad method: {method!r}")
                if outcome not in DISTILL_OUTCOMES:
                    raise BadOutcomeError(f"bad outcome: {outcome!r}")
                source_digest = _require_optional_digest(source_digest, "source_digest")
                target_digest = _require_optional_digest(target_digest, "target_digest")
                if amplification_id not in self._runs:
                    raise UnknownAmplificationError(
                        f"unknown amplification: {amplification_id!r}"
                    )
                self._require_live(self._runs[amplification_id].task_id)
                self._distill_counter += 1
                distillation_id = f"dst-{self._distill_counter}"
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "distillation_id": distillation_id,
                        "amplification_id": amplification_id,
                        "target_model_id": target_model_id,
                        "method": method,
                        "outcome": outcome,
                        "source_digest": source_digest,
                        "target_digest": target_digest,
                        "seq": seq,
                    }
                )
                record = DistillationRecord(
                    distillation_id=distillation_id,
                    amplification_id=amplification_id,
                    target_model_id=target_model_id,
                    method=method,
                    outcome=outcome,
                    source_digest=source_digest,
                    target_digest=target_digest,
                    seq=seq,
                    digest=digest,
                )
                self._distillations[distillation_id] = record
                self._run_distillations.setdefault(amplification_id, []).append(
                    distillation_id
                )
                self._emit(
                    "distilled",
                    seq,
                    distillation_id=distillation_id,
                    amplification_id=amplification_id,
                    target_model_id=target_model_id,
                    method=method,
                    outcome=outcome,
                )
                return record
            except AmplificationError:
                self._burn(seq, "distill")
                raise

    # -- verify (pure read) -----------------------------------------------------

    def verify(self, record_id: str, seq: int) -> VerificationReport:
        """Re-derive a booked record's digest pin, as data (pure read).

        The verdict (``verified`` / ``tampered``) reports ledger
        integrity only; it is never proof a real amplification or
        distillation executed. Seq is shape-validated, never consumed,
        and no audit row is written.
        """
        with self._lock:
            self._check_seq(seq)
            _require_id(record_id, "record_id")
            if record_id in self._runs:
                record = self._runs[record_id]
                record_kind = "amplification"
            elif record_id in self._distillations:
                record = self._distillations[record_id]
                record_kind = "distillation"
            else:
                raise UnknownRecordError(f"unknown record: {record_id!r}")
            ok = record.verify()
            verdict = "verified" if ok else "tampered"
            report = VerificationReport(
                record_id=record_id,
                record_kind=record_kind,
                verdict=verdict,
                integrity_ok=ok,
                seq=seq,
                digest=_digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "record_id": record_id,
                        "record_kind": record_kind,
                        "verdict": verdict,
                        "integrity_ok": ok,
                        "seq": seq,
                    }
                ),
            )
            _ = seq  # seq shape validated, never consumed
            return report

    # -- retire ----------------------------------------------------------------

    def retire(self, task_id: str, seq: int, reason: str = "manual") -> RetireRecord:
        """Terminally retire a task's amplification lifecycle.

        Retired ids are never recycled; post-retire mutations are refused,
        reads still work.
        """
        with self._lock:
            self._claim(seq)
            try:
                _require_id(task_id, "task_id")
                if reason not in RETIRE_REASONS:
                    raise BadReasonError(f"bad reason: {reason!r}")
                if task_id not in self._task_runs:
                    raise UnknownTaskError(f"unknown task: {task_id!r}")
                self._require_live(task_id)
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "task_id": task_id,
                        "reason": reason,
                        "seq": seq,
                    }
                )
                record = RetireRecord(
                    task_id=task_id, reason=reason, seq=seq, digest=digest
                )
                self._retired[task_id] = record
                self._emit("retired", seq, task_id=task_id, reason=reason)
                return record
            except AmplificationError:
                self._burn(seq, "retire")
                raise

    # -- status (pure read) ------------------------------------------------------

    def status(self, task_id: str, seq: int) -> TaskStatus:
        """Derived posture of one task's amplification lifecycle, as data.

        Posture rules (ledger data, never measured truth):
        - ``distilled`` when any booked run has a booked distillation
        - ``suspect`` when any run outcome is ``misaligned``
        - ``inconclusive`` when any run outcome is ``inconclusive``
        - ``amplified`` when runs are booked and all are ``aligned``
        - ``not-run`` when runs are booked with only ``not-run`` outcomes
        """
        with self._lock:
            self._check_seq(seq)
            _require_id(task_id, "task_id")
            if task_id not in self._task_runs:
                raise UnknownTaskError(f"unknown task: {task_id!r}")
            run_ids = self._task_runs[task_id]
            distill_ids = [
                did
                for rid in run_ids
                for did in self._run_distillations.get(rid, [])
            ]
            outcomes = {self._runs[rid].outcome for rid in run_ids}
            all_ok = all(self._runs[rid].verify() for rid in run_ids) and all(
                self._distillations[did].verify() for did in distill_ids
            )
            if distill_ids:
                posture = "distilled"
            elif "misaligned" in outcomes:
                posture = "suspect"
            elif "inconclusive" in outcomes:
                posture = "inconclusive"
            elif outcomes == {"aligned"}:
                posture = "amplified"
            else:
                posture = "not-run"
            record = TaskStatus(
                task_id=task_id,
                n_runs=len(run_ids),
                n_distillations=len(distill_ids),
                posture=posture,
                integrity_ok=all_ok,
                digest=_digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "task_id": task_id,
                        "n_runs": len(run_ids),
                        "n_distillations": len(distill_ids),
                        "posture": posture,
                        "integrity_ok": all_ok,
                    }
                ),
            )
            _ = seq  # seq shape validated, never consumed
            return record

    # -- views (pure reads) ------------------------------------------------------

    def amplification_record(self, amplification_id: str, seq: int) -> AmplificationRecord:
        """Return one amplification record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            _require_id(amplification_id, "amplification_id")
            if amplification_id not in self._runs:
                raise UnknownAmplificationError(
                    f"unknown amplification: {amplification_id!r}"
                )
            return self._runs[amplification_id]

    def distillation_record(self, distillation_id: str, seq: int) -> DistillationRecord:
        """Return one distillation record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            _require_id(distillation_id, "distillation_id")
            if distillation_id not in self._distillations:
                raise UnknownRecordError(
                    f"unknown distillation: {distillation_id!r}"
                )
            return self._distillations[distillation_id]

    def amplifications_for(self, task_id: str, seq: int) -> Tuple[str, ...]:
        """Amplification ids booked against one task, in mint order (pure read)."""
        with self._lock:
            self._check_seq(seq)
            _require_id(task_id, "task_id")
            if task_id not in self._task_runs:
                raise UnknownTaskError(f"unknown task: {task_id!r}")
            return tuple(self._task_runs[task_id])

    def distillations_for(self, amplification_id: str, seq: int) -> Tuple[str, ...]:
        """Distillation ids booked against one amplification, in mint order (pure read)."""
        with self._lock:
            self._check_seq(seq)
            _require_id(amplification_id, "amplification_id")
            if amplification_id not in self._runs:
                raise UnknownAmplificationError(
                    f"unknown amplification: {amplification_id!r}"
                )
            return tuple(self._run_distillations.get(amplification_id, ()))

    def task_ids(self, seq: int) -> Tuple[str, ...]:
        """All amplified task ids in first-run order (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._task_runs.keys())

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        """All retired task ids (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._retired.keys())

    def stats(self, seq: int) -> Dict[str, int]:
        """Ledger counters (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return {
                "tasks": len(self._task_runs),
                "runs": len(self._runs),
                "distillations": len(self._distillations),
                "retired": len(self._retired),
                "rejected": sum(
                    1 for row in self._audit if row["kind"] == "rejected"
                ),
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        """All audit rows so far (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._audit)


def main() -> None:
    """Self-check: exercise the amplification ledger end to end."""
    a = Amplification()
    r1 = a.amplify("t-1", 1, strategy="debate", outcome="aligned")
    d1 = a.distill(r1.amplification_id, "m-1", 2, method="rl-distillation",
                   outcome="faithful")
    assert a.verify(r1.amplification_id, 3).verdict == "verified"
    assert a.verify(d1.distillation_id, 4).verdict == "verified"
    assert a.status("t-1", 5).posture == "distilled"
    a.retire("t-1", 6, reason="cycle-complete")
    assert a.stats(7) == {
        "tasks": 1,
        "runs": 1,
        "distillations": 1,
        "retired": 1,
        "rejected": 0,
    }
    print("amplification OK: amplify, distill, verify, pins, audit")


if __name__ == "__main__":
    main()
