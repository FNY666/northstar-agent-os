"""Process supervision: step-level oversight decision ledger, Simulated.

Research note: process supervision (OpenAI, "Let's Verify Step by Step",
Lightman et al., 2023) supervises *how* a model reasons - each intermediate
reasoning step gets its own correctness verdict - rather than supervising
only the *outcome*. A process-supervised reward model (PRM) learns from
step-level labels; an outcome-supervised one (ORM) learns only from final
answers. This module is the *decision ledger* for declared process
supervision: which systems had which reasoning steps booked, what
step-level verdicts were declared against them, and what process-level
posture the ledger derives - defensible bookkeeping, never proof that any
reasoning is actually correct.

This module owns the supervise -> evaluate -> verify lifecycle:

* **supervise()** - book one declared step-level supervision (minted
  ``sup-N`` ids; pinned verdict vocabulary ``correct`` / ``incorrect`` /
  ``uncertain`` / ``not-assessed``); the first supervision registers its
  system; raw reasoning steps, thoughts, and tool traces never enter
  records - digest pins only; the same ``(system_id, step_id)`` twice is
  refused fail-closed (``DuplicateStepError``).
* **evaluate()** - **pure read**: derive the process-level posture for one
  system as data (``unevaluated`` -> ``error-detected`` -> ``uncertain`` ->
  ``supervised``) with step tallies and a digest-pinned integrity flag.
* **verify()** - **pure read**: re-derive one supervision's digest pin;
  verdict ``verified`` / ``tampered`` booked as data.
* **retire()** - terminal retirement of a system id; ids are never
  recycled.

Distinct-layer rationale vs siblings: ``reward_modeling.py`` owns reward
collection/training bookkeeping, ``process_reward.py``-style scoring (if
present) owns host-declared reward shapes, and ``evaluation.py`` owns
evaluation-governance protocol design - this module is the
process-supervision-*specific* ledger none of them own: step-granular
verdicts, per-step digests, and the ledger-rule posture that turns
step verdicts into a process claim ("no known bad step"), always as
data, never as measured truth.

House style: frozen dataclasses, caller-supplied strictly-increasing
int seqs (claim-then-burn: failed mutations consume their seq and book
a ``process-supervision.rejected`` row; rewinds raise bare without
consuming), no wall-clock, RLock guarding, fail-closed taxonomy,
stdlib-only with the standard ``canonical_json`` try/except fallback,
``sha256:`` digest pins, and ``audit.ndjson/1`` events.

Honest scope: this module runs no models, inspects no reasoning, scores
no steps, and proves nothing about real process correctness. A booked
``incorrect`` verdict means "the host declared it", never "the step is
wrong". Reasoning traces, tool calls, model outputs, prompts, and raw
labels never enter records or cross the audit boundary - digest pins
only.
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
PROCESS_SUPERVISION_VERSION = "process-supervision.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.process-supervision.v1"

#: Pinned step-level verdict vocabulary (booked as data, never proof).
STEP_VERDICTS = (
    "correct",
    "incorrect",
    "uncertain",
    "not-assessed",
)

#: Pinned verification-verdict vocabulary (booked as data).
VERIFY_VERDICTS = (
    "verified",
    "tampered",
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
    "supervised",
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
        "action",
        "actions",
        "state",
        "states",
        "observation",
        "gradient",
        "gradients",
        "reward",
        "rewards",
        "score",
        "scores",
        "capability",
        "capabilities",
        "performance",
        "benchmark",
        "loss",
        "feedback",
        "payload",
        "prompt",
        "response",
        "content",
        "text",
        "note",
        "notes",
        "detail",
        "details",
        "description",
        "report",
        "evidence",
        "result",
        "results",
        "raw",
        "secret",
        "key",
        "step",
        "steps",
        "thought",
        "thoughts",
        "reasoning",
        "trace",
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ProcessSupervisionError(Exception):
    """Base error for process-supervision ledger misuse."""


class BadIdError(ProcessSupervisionError):
    """Malformed system, step, or supervision id."""


class UnknownSystemError(ProcessSupervisionError):
    """System not registered."""


class RetiredSystemError(ProcessSupervisionError):
    """System id already retired; never recycled."""


class BadVerdictError(ProcessSupervisionError):
    """Unknown step-level verdict."""


class BadDigestError(ProcessSupervisionError):
    """Malformed sha256: digest pin."""


class DuplicateStepError(ProcessSupervisionError):
    """This (system_id, step_id) was already supervised."""


class UnknownSupervisionError(ProcessSupervisionError):
    """Supervision id not booked."""


class BadVerifyVerdictError(ProcessSupervisionError):
    """Unknown verification verdict."""


class BadReasonError(ProcessSupervisionError):
    """Unknown retirement reason."""


class SeqOrderError(ProcessSupervisionError):
    """Seq is not a strictly increasing positive int."""


class AuditKindError(ProcessSupervisionError):
    """Unknown audit kind, or banned raw key in audit details."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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


def _digest_pin(payload: Dict[str, Any]) -> str:
    raw = _jcs_hash(payload)
    hexpart = raw[7:] if raw.startswith("sha256:") else raw
    return "sha256:" + hexpart


# ---------------------------------------------------------------------------
# Records (all frozen)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SupervisionRecord:
    supervision_id: str
    system_id: str
    step_id: str
    verdict: str
    step_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "supervision_id": self.supervision_id,
            "system_id": self.system_id,
            "step_id": self.step_id,
            "verdict": self.verdict,
            "step_digest": self.step_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "supervision_id": self.supervision_id,
                "system_id": self.system_id,
                "step_id": self.step_id,
                "verdict": self.verdict,
                "step_digest": self.step_digest,
            }
        )


@dataclass(frozen=True)
class VerificationReport:
    supervision_id: str
    verdict: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "supervision_id": self.supervision_id,
            "verdict": self.verdict,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "supervision_id": self.supervision_id,
                "verdict": self.verdict,
            }
        )


@dataclass(frozen=True)
class EvaluationReport:
    system_id: str
    n_steps: int
    n_correct: int
    n_incorrect: int
    n_uncertain: int
    posture: str
    integrity_ok: bool
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "system_id": self.system_id,
            "n_steps": self.n_steps,
            "n_correct": self.n_correct,
            "n_incorrect": self.n_incorrect,
            "n_uncertain": self.n_uncertain,
            "posture": self.posture,
            "integrity_ok": self.integrity_ok,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "system_id": self.system_id,
                "n_steps": self.n_steps,
                "n_correct": self.n_correct,
                "n_incorrect": self.n_incorrect,
                "n_uncertain": self.n_uncertain,
                "posture": self.posture,
                "integrity_ok": self.integrity_ok,
            }
        )


@dataclass(frozen=True)
class RetireRecord:
    system_id: str
    reason: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "system_id": self.system_id,
            "reason": self.reason,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "schema": SCHEMA_PIN,
                "system_id": self.system_id,
                "reason": self.reason,
            }
        )


# ---------------------------------------------------------------------------
# Audit event builder
# ---------------------------------------------------------------------------


def process_supervision_audit_event(
    audit_kind: str, seq: int, **details: Any
) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the process-supervision ledger."""
    if audit_kind not in AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {audit_kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError("audit seq must be a non-negative int")
    for key in details:
        if key in _BANNED_AUDIT_KEYS:
            raise AuditKindError(f"banned raw key in audit detail: {key!r}")
    return {
        "schema": "audit.ndjson/1",
        "kind": audit_kind,
        "seq": seq,
        "details": dict(details),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class ProcessSupervision:
    """Step-level process-supervision decision ledger, Simulated.

    Deterministic single-host state machine: caller-supplied strictly
    increasing int seqs, claim-then-burn (failed mutations consume their
    seq and book a ``process-supervision.rejected`` row; rewinds raise
    bare), no wall-clock, RLock-guarded, fail-closed, stdlib-only.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._systems: Dict[str, List[str]] = {}
        self._supervisions: Dict[str, SupervisionRecord] = {}
        self._supervisions_by_system: Dict[str, List[str]] = {}
        self._steps_by_system: Dict[str, set] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._sup_counter = 0
        self._seq = 0
        self._audit: List[Dict[str, Any]] = []
        self._rejected = 0

    # -- internal helpers -------------------------------------------------

    def _check_seq(self, seq: Any) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
            raise SeqOrderError("seq must be a positive int, not bool")
        return seq

    def _claim_seq(self, seq: int) -> None:
        """Claim a strictly increasing seq; rewinds raise bare."""
        if seq <= self._seq:
            raise SeqOrderError(
                f"seq must be strictly increasing, got {seq} after {self._seq}"
            )
        self._seq = seq

    def _burn(self, seq: int, method: str, exc: ProcessSupervisionError) -> None:
        """Book a failed mutation: seq consumed, rejected row appended."""
        self._rejected += 1
        self._audit.append(
            process_supervision_audit_event(
                "rejected",
                seq,
                method=method,
                error=type(exc).__name__,
                error_detail=str(exc),
            )
        )

    def _require_live_system(self, system_id: str) -> None:
        if system_id in self._retired:
            raise RetiredSystemError(f"system already retired: {system_id!r}")

    def _require_known_system(self, system_id: str) -> None:
        if system_id not in self._systems:
            raise UnknownSystemError(f"unknown system: {system_id!r}")

    # -- mutations ----------------------------------------------------------

    def supervise(
        self,
        system_id: Any,
        step_id: Any,
        seq: Any,
        verdict: Any = "not-assessed",
        step_digest: Any = "",
    ) -> SupervisionRecord:
        """Book one declared step-level supervision (minted ``sup-N``).

        The first supervision registers its system. The step's reasoning
        content travels as a digest pin only; raw traces never enter
        records. Supervising the same ``(system_id, step_id)`` twice is
        refused - steps are supervised once.
        """
        with self._lock:
            seq_v = self._check_seq(seq)
            self._claim_seq(seq_v)
            try:
                sid = _require_id(system_id, "system_id")
                if sid in self._retired:
                    raise RetiredSystemError(f"system id never recycled: {sid!r}")
                stid = _require_id(step_id, "step_id")
                if not isinstance(verdict, str) or verdict not in STEP_VERDICTS:
                    raise BadVerdictError(
                        f"verdict must be one of {sorted(STEP_VERDICTS)}"
                    )
                pin = _require_digest(step_digest, "step_digest")
                if stid in self._steps_by_system.setdefault(sid, set()):
                    raise DuplicateStepError(
                        f"step already supervised for {sid!r}: {stid!r}"
                    )
                self._sup_counter += 1
                supid = f"sup-{self._sup_counter}"
                rec = SupervisionRecord(
                    supervision_id=supid,
                    system_id=sid,
                    step_id=stid,
                    verdict=verdict,
                    step_digest=pin,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "supervision_id": supid,
                            "system_id": sid,
                            "step_id": stid,
                            "verdict": verdict,
                            "step_digest": pin,
                        }
                    ),
                )
                self._supervisions[supid] = rec
                self._systems.setdefault(sid, []).append(supid)
                self._supervisions_by_system.setdefault(sid, []).append(supid)
                self._steps_by_system[sid].add(stid)
                self._audit.append(
                    process_supervision_audit_event(
                        "supervised",
                        seq_v,
                        supervision_id=supid,
                        system_id=sid,
                        step_id=stid,
                        verdict=verdict,
                        step_digest=pin,
                    )
                )
                return rec
            except ProcessSupervisionError as exc:
                self._burn(seq_v, "supervise", exc)
                raise

    def retire(self, system_id: Any, seq: Any, reason: Any = "manual") -> RetireRecord:
        """Terminal retirement of a system id; ids are never recycled."""
        with self._lock:
            seq_v = self._check_seq(seq)
            self._claim_seq(seq_v)
            try:
                sid = _require_id(system_id, "system_id")
                self._require_known_system(sid)
                if sid in self._retired:
                    raise RetiredSystemError(f"system id never recycled: {sid!r}")
                if not isinstance(reason, str) or reason not in RETIRE_REASONS:
                    raise BadReasonError(f"reason must be one of {sorted(RETIRE_REASONS)}")
                rec = RetireRecord(
                    system_id=sid,
                    reason=reason,
                    digest=_digest_pin(
                        {
                            "schema": SCHEMA_PIN,
                            "system_id": sid,
                            "reason": reason,
                        }
                    ),
                )
                self._retired[sid] = rec
                self._audit.append(
                    process_supervision_audit_event(
                        "retired", seq_v, system_id=sid, reason=reason
                    )
                )
                return rec
            except ProcessSupervisionError as exc:
                self._burn(seq_v, "retire", exc)
                raise

    # -- pure reads ---------------------------------------------------------

    def verify(self, supervision_id: Any, seq: Any) -> VerificationReport:
        """Re-derive one supervision's digest pin (pure read).

        Verdict ``verified`` / ``tampered`` is derived as data: tampering
        is reported, never raised.
        """
        with self._lock:
            self._check_seq(seq)
            supid = _require_id(supervision_id, "supervision_id")
            if supid not in self._supervisions:
                raise UnknownSupervisionError(f"unknown supervision: {supid!r}")
            rec = self._supervisions[supid]
            ok = rec.verify()
            verdict = "verified" if ok else "tampered"
            return VerificationReport(
                supervision_id=supid,
                verdict=verdict,
                digest=_digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "supervision_id": supid,
                        "verdict": verdict,
                    }
                ),
            )

    def evaluate(self, system_id: Any, seq: Any) -> EvaluationReport:
        """Derive the process-level posture for one system (pure read).

        Posture rules (ledger data, never measured truth):
        - ``unevaluated`` when no supervisions are booked
        - ``error-detected`` when any booked verdict is ``incorrect``
        - ``uncertain`` when any booked verdict is ``uncertain``
        - ``supervised`` otherwise (all ``correct`` / ``not-assessed``)
        """
        with self._lock:
            self._check_seq(seq)
            sid = _require_id(system_id, "system_id")
            self._require_known_system(sid)
            sup_ids = self._supervisions_by_system.get(sid, [])
            verdicts = [self._supervisions[i].verdict for i in sup_ids]
            n_correct = sum(1 for v in verdicts if v == "correct")
            n_incorrect = sum(1 for v in verdicts if v == "incorrect")
            n_uncertain = sum(1 for v in verdicts if v == "uncertain")
            if not sup_ids:
                posture = "unevaluated"
            elif n_incorrect > 0:
                posture = "error-detected"
            elif n_uncertain > 0:
                posture = "uncertain"
            else:
                posture = "supervised"
            integrity_ok = all(
                self._supervisions[i].verify() for i in sup_ids
            )
            return EvaluationReport(
                system_id=sid,
                n_steps=len(sup_ids),
                n_correct=n_correct,
                n_incorrect=n_incorrect,
                n_uncertain=n_uncertain,
                posture=posture,
                integrity_ok=integrity_ok,
                digest=_digest_pin(
                    {
                        "schema": SCHEMA_PIN,
                        "system_id": sid,
                        "n_steps": len(sup_ids),
                        "n_correct": n_correct,
                        "n_incorrect": n_incorrect,
                        "n_uncertain": n_uncertain,
                        "posture": posture,
                        "integrity_ok": integrity_ok,
                    }
                ),
            )

    def supervision_record(self, supervision_id: Any, seq: Any) -> SupervisionRecord:
        """Return one supervision record (pure read)."""
        with self._lock:
            self._check_seq(seq)
            supid = _require_id(supervision_id, "supervision_id")
            if supid not in self._supervisions:
                raise UnknownSupervisionError(f"unknown supervision: {supid!r}")
            return self._supervisions[supid]

    def system_ids(self, seq: Any) -> Tuple[str, ...]:
        """All registered system ids in registration order."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._systems.keys())

    def supervision_ids(self, seq: Any) -> Tuple[str, ...]:
        """All supervision ids in mint order."""
        with self._lock:
            self._check_seq(seq)
            return tuple(f"sup-{i}" for i in range(1, self._sup_counter + 1))

    def supervisions_for(self, system_id: Any, seq: Any) -> Tuple[str, ...]:
        """Supervision ids booked against one system (mint order)."""
        with self._lock:
            self._check_seq(seq)
            sid = _require_id(system_id, "system_id")
            self._require_known_system(sid)
            return tuple(self._supervisions_by_system.get(sid, ()))

    def retired_ids(self, seq: Any) -> Tuple[str, ...]:
        """All retired system ids."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._retired.keys())

    def audit_log(self, seq: Any) -> Tuple[Dict[str, Any], ...]:
        """All audit rows so far (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return tuple(self._audit)

    def stats(self, seq: Any) -> Dict[str, int]:
        """Ledger counters (pure read)."""
        with self._lock:
            self._check_seq(seq)
            return {
                "systems": len(self._systems),
                "supervisions": len(self._supervisions),
                "retired": len(self._retired),
                "rejected": self._rejected,
            }


def main() -> None:
    """Self-check: exercise the ledger end to end."""
    ps = ProcessSupervision()
    pin = "sha256:" + "ab" * 32
    sup = ps.supervise("sys-1", "step-1", 1, verdict="correct", step_digest=pin)
    assert sup.supervision_id == "sup-1"
    ps.supervise("sys-1", "step-2", 2, verdict="correct", step_digest=pin)
    ev = ps.evaluate("sys-1", 3)
    assert ev.posture == "supervised"
    assert ev.integrity_ok is True
    vr = ps.verify("sup-1", 4)
    assert vr.verdict == "verified"
    assert vr.verify()
    ps.retire("sys-1", 5, reason="decommissioned")
    assert ps.stats(6) == {
        "systems": 1,
        "supervisions": 2,
        "retired": 1,
        "rejected": 0,
    }
    print("process-supervision OK: supervise, evaluate, verify, pins, audit")


if __name__ == "__main__":
    main()
