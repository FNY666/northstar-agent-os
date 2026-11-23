"""Outcome supervision: AI alignment outcome-supervision governance ledger, Simulated.

Research note: in preference-based alignment training (RLHF/RLAIF/DPO),
"supervision" comes in two shapes. *Process* supervision grades
intermediate reasoning steps; *outcome* supervision grades only the final
outcome - the produced answer, completion, or action sequence. Outcome
supervision is cheaper (the supervisor never sees the chain of thought)
and therefore the dominant industrial pattern, but it is also the shape
most vulnerable to specification gaming: a host can declare that an
outcome was "reviewed" and "accepted" while the review was shallow, the
rubric was wrong, or the reward signal being chased was the very metric
the supervisor was optimizing.

This module is the bookkeeping layer for declared outcome supervision,
deliberately distinct from its siblings ``process_supervision.py``
(where one exists), ``rlhf.py`` (RLHF pipeline bookkeeping),
``rlaif.py`` (AI feedback lifecycle), ``dpo.py`` (preference-pair
ledger), ``reward_modeling.py`` (reward-model training bookkeeping),
``preference_learning.py`` (preference collection ledger), and
``human_oversight.py`` (human assignment/review): it runs no supervisor,
reviews no outcome, grades no transcript, and leaks no task material. It
books:

* **supervise()** - declare one outcome supervision of a task against the
  pinned supervision-kind vocabulary; the outcome verdict (``accepted`` /
  ``rejected`` / ``flagged`` / ``escalated``) is booked **as data**, never
  proof the outcome was actually inspected or that the verdict was
  honest; task payloads and supervisor notes travel as ``sha256:`` digest
  pins only - raw task text, answers, and rationales never enter a record;
  minted ``sup-N`` ids; the first supervision on a task id registers it.
* **evaluate()** - pure-read derived supervision posture for one task by
  ledger rule (``unsupervised`` / ``rejected-open`` / ``escalated`` /
  ``flagged`` / ``accepted``) with ``integrity_ok`` as data; seq shape
  validated, never consumed, no audit row.
* **verify()** - pure-read digest re-derivation for one supervision
  record (``verified`` / ``tampered`` as data); never proof anything was
  supervised.
* **retire()** - terminal bookkeeping for superseded tasks; ids are never
  recycled.

House style: frozen dataclasses, caller-supplied strictly-increasing int
seqs (claim-then-burn: failed mutations consume their seq and book an
``outcome-supervision.rejected`` row; rewinds raise bare without
consuming), no wall-clock, RLock guarding, fail-closed taxonomy,
stdlib-only with the standard ``canonical_json`` try/except fallback,
``sha256:`` digest pins, and ``audit.ndjson/1`` events.

Honest scope: a booked supervision is a host declaration that an outcome
was supervised with the stated kind and verdict - it is never proof a
supervisor looked at anything, that the supervision was competent, or
that the verdict was not gamed; a derived ``accepted`` posture is ledger
arithmetic, never evidence the outcome is correct or safe.
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
OUTCOME_SUPERVISION_VERSION = "outcome-supervision.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.outcome-supervision.v1"

#: Pinned supervision-kind vocabulary (how the outcome was declared supervised).
SUPERVISION_KINDS = (
    "human-review",
    "model-judge",
    "programmatic-check",
    "spot-check",
    "sampling-audit",
    "consensus-vote",
)

#: Pinned outcome-verdict vocabulary (declared supervision outcome, as data).
OUTCOME_VERDICTS = (
    "accepted",
    "rejected",
    "flagged",
    "escalated",
)

#: Pinned retirement-reason vocabulary.
RETIRE_REASONS = (
    "manual",
    "task-superseded",
    "protocol-complete",
    "invalidated",
)

#: Ledger-rule posture vocabulary derived by evaluate() (as data).
POSTURES = (
    "unsupervised",
    "rejected-open",
    "escalated",
    "flagged",
    "accepted",
)

#: Audit kinds emitted by this module.
AUDIT_KINDS = (
    "supervised",
    "retired",
    "rejected",
)

#: Keys that may never appear raw in an audit row (exact-key matching).
#: Declared-data keys (``supervision_kind``, ``outcome_verdict``, ``posture``)
#: are pinned vocabulary values and remain emittable.
_BANNED_AUDIT_KEYS = frozenset(
    {
        "task",
        "outcome",
        "answer",
        "completion",
        "response",
        "prompt",
        "transcript",
        "reasoning",
        "rationale",
        "notes",
        "review",
        "weights",
        "trace",
        "content",
        "text",
        "data",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class OutcomeSupervisionError(Exception):
    """Base error for outcome-supervision ledger misuse."""


class BadIdError(OutcomeSupervisionError):
    """Malformed task/supervision id."""


class DuplicateTaskError(OutcomeSupervisionError):
    """A task id was declared twice (internal guard)."""


class UnknownTaskError(OutcomeSupervisionError):
    """Reference to a task id that was never registered."""


class UnknownSupervisionError(OutcomeSupervisionError):
    """Reference to a supervision id that was never booked."""


class RetiredTaskError(OutcomeSupervisionError):
    """A task id was retired and can never be reused."""


class BadKindError(OutcomeSupervisionError):
    """Supervision kind outside the pinned vocabulary."""


class BadVerdictError(OutcomeSupervisionError):
    """Outcome verdict outside the pinned vocabulary."""


class BadDigestError(OutcomeSupervisionError):
    """Malformed sha256: digest pin."""


class BadReasonError(OutcomeSupervisionError):
    """Retirement reason outside the pinned vocabulary."""


class TaskStateError(OutcomeSupervisionError):
    """Mutation attempted against a task that is not live."""


class SeqOrderError(OutcomeSupervisionError):
    """Caller seq did not strictly increase."""


class AuditKindError(OutcomeSupervisionError):
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
class SupervisionRecord:
    """One declared outcome supervision (digest pins only, never raw material)."""

    supervision_id: str
    task_id: str
    supervision_kind: str
    outcome_verdict: str
    task_digest: str
    outcome_digest: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "supervision_id": self.supervision_id,
            "task_id": self.task_id,
            "supervision_kind": self.supervision_kind,
            "outcome_verdict": self.outcome_verdict,
            "task_digest": self.task_digest,
            "outcome_digest": self.outcome_digest,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "supervision_id": self.supervision_id,
                "task_id": self.task_id,
                "supervision_kind": self.supervision_kind,
                "outcome_verdict": self.outcome_verdict,
                "task_digest": self.task_digest,
                "outcome_digest": self.outcome_digest,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class RetireRecord:
    """Terminal retirement bookkeeping for one task (ids never recycled)."""

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
class EvaluationReport:
    """Pure-read derived supervision posture for one task (as data)."""

    task_id: str
    n_supervisions: int
    verdict_tally: Tuple[Tuple[str, int], ...]
    posture: str
    integrity_ok: bool
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "task_id": self.task_id,
            "n_supervisions": self.n_supervisions,
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
                "task_id": self.task_id,
                "n_supervisions": self.n_supervisions,
                "verdict_tally": [list(pair) for pair in self.verdict_tally],
                "posture": self.posture,
                "integrity_ok": self.integrity_ok,
                "seq": self.seq,
            }
        )


@dataclass(frozen=True)
class VerificationReport:
    """Pure-read digest re-derivation for one supervision record (as data)."""

    supervision_id: str
    verdict: str
    integrity_ok: bool
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "supervision_id": self.supervision_id,
            "verdict": self.verdict,
            "integrity_ok": self.integrity_ok,
            "seq": self.seq,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "supervision_id": self.supervision_id,
                "verdict": self.verdict,
                "integrity_ok": self.integrity_ok,
                "seq": self.seq,
            }
        )


def outcome_supervision_audit_event(
    kind: str, seq: int, **details: Any
) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the outcome-supervision ledger."""
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


class OutcomeSupervision:
    """Outcome-supervision governance ledger (Simulated).

    ``supervise()`` / ``retire()`` mutate the ledger and consume caller
    seqs; ``evaluate()``, ``verify()``, and all views are pure reads.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        self._tasks: Dict[str, List[str]] = {}
        self._supervisions: Dict[str, SupervisionRecord] = {}
        self._retirements: Dict[str, RetireRecord] = {}
        self._retired: set = set()
        self._n_supervisions = 0
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
            row = outcome_supervision_audit_event("rejected", seq, rejected_kind=kind, **details)
        except (AuditKindError, SeqOrderError):
            row = {
                "schema": "audit.ndjson/1",
                "kind": "rejected",
                "seq": seq,
                "details": {"rejected_kind": kind},
            }
        self._audit.append(row)

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(outcome_supervision_audit_event(audit_kind, seq, **details))

    def _live(self, task_id: str) -> List[str]:
        sup_ids = self._tasks.get(task_id)
        if sup_ids is None:
            raise UnknownTaskError(f"unknown task: {task_id!r}")
        if task_id in self._retired:
            raise RetiredTaskError(f"task id retired forever: {task_id!r}")
        return sup_ids

    # -- supervise -----------------------------------------------------------

    def supervise(
        self,
        task_id: str,
        seq: int,
        supervision_kind: str = "human-review",
        outcome_verdict: str = "accepted",
        task_digest: str = "",
        outcome_digest: str = "",
    ) -> SupervisionRecord:
        """Book one declared outcome supervision (minted ``sup-N``).

        The first supervision on a task id registers the task. The
        verdict is booked **as data** - never proof the outcome was
        actually inspected or that the verdict was honest. Raw task
        text and supervisor notes never enter the record; they travel
        as ``sha256:`` digest pins only.
        """
        with self._lock:
            self._claim(seq)
            try:
                _require_id(task_id, "task_id")
                if task_id in self._retired:
                    raise RetiredTaskError(f"task id retired forever: {task_id!r}")
                if supervision_kind not in SUPERVISION_KINDS:
                    raise BadKindError(f"bad supervision kind: {supervision_kind!r}")
                if outcome_verdict not in OUTCOME_VERDICTS:
                    raise BadVerdictError(f"bad outcome verdict: {outcome_verdict!r}")
                task_digest = _require_optional_digest(task_digest, "task_digest")
                outcome_digest = _require_optional_digest(outcome_digest, "outcome_digest")
                self._n_supervisions += 1
                supervision_id = f"sup-{self._n_supervisions}"
                digest = _digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "supervision_id": supervision_id,
                        "task_id": task_id,
                        "supervision_kind": supervision_kind,
                        "outcome_verdict": outcome_verdict,
                        "task_digest": task_digest,
                        "outcome_digest": outcome_digest,
                        "seq": seq,
                    }
                )
                record = SupervisionRecord(
                    supervision_id=supervision_id,
                    task_id=task_id,
                    supervision_kind=supervision_kind,
                    outcome_verdict=outcome_verdict,
                    task_digest=task_digest,
                    outcome_digest=outcome_digest,
                    seq=seq,
                    digest=digest,
                )
                self._supervisions[supervision_id] = record
                self._tasks.setdefault(task_id, []).append(supervision_id)
                self._emit(
                    "supervised",
                    seq,
                    supervision_id=supervision_id,
                    task_id=task_id,
                    supervision_kind=supervision_kind,
                    outcome_verdict=outcome_verdict,
                )
                return record
            except OutcomeSupervisionError:
                self._burn(seq, "supervise")
                raise

    # -- retire --------------------------------------------------------------

    def retire(self, task_id: str, seq: int, reason: str = "manual") -> RetireRecord:
        """Terminally retire one task (ids are never recycled)."""
        with self._lock:
            self._claim(seq)
            try:
                _require_id(task_id, "task_id")
                if reason not in RETIRE_REASONS:
                    raise BadReasonError(f"bad reason: {reason!r}")
                if task_id not in self._tasks:
                    raise UnknownTaskError(f"unknown task: {task_id!r}")
                if task_id in self._retired:
                    raise RetiredTaskError(f"task id retired forever: {task_id!r}")
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
                self._retirements[task_id] = record
                self._retired.add(task_id)
                self._emit("retired", seq, task_id=task_id, reason=reason)
                return record
            except OutcomeSupervisionError:
                self._burn(seq, "retire")
                raise

    # -- pure-read views -----------------------------------------------------

    def _view_seq_ok(self, seq: int) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise SeqOrderError("view seq must be a non-negative int")

    def evaluate(self, task_id: str, seq: int) -> EvaluationReport:
        """Derive a digest-pinned supervision posture for one task (pure read).

        The posture is ledger-rule data, never measured truth:

        * ``unsupervised`` when no supervisions are booked;
        * ``rejected-open`` when any booked verdict is ``rejected``;
        * ``escalated`` when any booked verdict is ``escalated``;
        * ``flagged`` when any booked verdict is ``flagged``;
        * ``accepted`` otherwise (every booked verdict accepted).

        ``integrity_ok`` reports whether every stored record for the
        task still verifies (tamper reported, never raised).
        """
        with self._lock:
            self._view_seq_ok(seq)
            _require_id(task_id, "task_id")
            sup_ids = self._tasks.get(task_id)
            if sup_ids is None:
                raise UnknownTaskError(f"unknown task: {task_id!r}")
            verdicts = [self._supervisions[sid].outcome_verdict for sid in sup_ids]
            integrity_ok = all(self._supervisions[sid].verify() for sid in sup_ids)
            n_supervisions = len(sup_ids)
            tally = tuple(
                (verdict, sum(1 for v in verdicts if v == verdict))
                for verdict in OUTCOME_VERDICTS
            )
            if n_supervisions == 0:
                posture = "unsupervised"
            elif "rejected" in verdicts:
                posture = "rejected-open"
            elif "escalated" in verdicts:
                posture = "escalated"
            elif "flagged" in verdicts:
                posture = "flagged"
            else:
                posture = "accepted"
            digest = _digest_pin(
                {
                    "schema": SCHEMA_PIN,
                    "task_id": task_id,
                    "n_supervisions": n_supervisions,
                    "verdict_tally": [list(pair) for pair in tally],
                    "posture": posture,
                    "integrity_ok": integrity_ok,
                    "seq": seq,
                }
            )
            return EvaluationReport(
                task_id=task_id,
                n_supervisions=n_supervisions,
                verdict_tally=tally,
                posture=posture,
                integrity_ok=integrity_ok,
                seq=seq,
                digest=digest,
            )

    def verify(self, supervision_id: str, seq: int) -> VerificationReport:
        """Re-derive one supervision record's digest pin (pure read).

        The verdict (``verified`` / ``tampered``) is data: tamper is
        reported, never raised.
        """
        with self._lock:
            self._view_seq_ok(seq)
            _require_id(supervision_id, "supervision_id")
            record = self._supervisions.get(supervision_id)
            if record is None:
                raise UnknownSupervisionError(
                    f"unknown supervision: {supervision_id!r}"
                )
            integrity_ok = record.verify()
            verdict = "verified" if integrity_ok else "tampered"
            digest = _digest_pin(
                {
                    "schema": SCHEMA_PIN,
                    "supervision_id": supervision_id,
                    "verdict": verdict,
                    "integrity_ok": integrity_ok,
                    "seq": seq,
                }
            )
            return VerificationReport(
                supervision_id=supervision_id,
                verdict=verdict,
                integrity_ok=integrity_ok,
                seq=seq,
                digest=digest,
            )

    def supervision_record(self, supervision_id: str, seq: int) -> SupervisionRecord:
        """Return one supervision record (pure read)."""
        with self._lock:
            self._view_seq_ok(seq)
            _require_id(supervision_id, "supervision_id")
            record = self._supervisions.get(supervision_id)
            if record is None:
                raise UnknownSupervisionError(
                    f"unknown supervision: {supervision_id!r}"
                )
            return record

    def supervisions_for(self, task_id: str, seq: int) -> Tuple[str, ...]:
        """Supervision ids booked against one task, in mint order (pure read)."""
        with self._lock:
            self._view_seq_ok(seq)
            _require_id(task_id, "task_id")
            sup_ids = self._tasks.get(task_id)
            if sup_ids is None:
                raise UnknownTaskError(f"unknown task: {task_id!r}")
            return tuple(sup_ids)

    def task_ids(self, seq: int) -> Tuple[str, ...]:
        """All registered task ids in first-supervision order (pure read)."""
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(self._tasks.keys())

    def supervision_ids(self, seq: int) -> Tuple[str, ...]:
        """All booked supervision ids in mint order (pure read)."""
        with self._lock:
            self._view_seq_ok(seq)
            return tuple(self._supervisions.keys())

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        """All retired task ids (pure read)."""
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
                "tasks": len(self._tasks),
                "supervisions": len(self._supervisions),
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
    """Self-check: exercise the outcome-supervision ledger end to end."""
    pin = "sha256:" + "ab" * 32
    o = OutcomeSupervision()
    s1 = o.supervise("TASK-1", 1, supervision_kind="human-review", outcome_verdict="accepted", task_digest=pin)
    s2 = o.supervise("TASK-1", 2, supervision_kind="model-judge", outcome_verdict="accepted")
    s3 = o.supervise("TASK-2", 3, supervision_kind="spot-check", outcome_verdict="rejected", outcome_digest=pin)
    assert s1.verify() and s2.verify() and s3.verify()
    assert s1.supervision_id == "sup-1" and s2.supervision_id == "sup-2"
    e1 = o.evaluate("TASK-1", 0)
    e2 = o.evaluate("TASK-2", 0)
    assert e1.posture == "accepted" and e2.posture == "rejected-open"
    assert e1.verify() and e2.verify()
    v1 = o.verify("sup-1", 0)
    assert v1.verdict == "verified" and v1.verify()
    o.retire("TASK-2", 4, reason="protocol-complete")
    assert o.evaluate("TASK-2", 0).posture == "rejected-open"
    assert OutcomeSupervision.stdlib_only()
    print("outcome-supervision OK: supervise, evaluate, verify, pins, audit")


if __name__ == "__main__":
    main()
