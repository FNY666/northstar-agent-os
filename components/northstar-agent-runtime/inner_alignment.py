"""InnerAlignment: inner-alignment inspection / verification / evaluation ledger.

Research note: "inner alignment" (Hubinger et al., 2019, "Risks from Learned
Optimization") is the problem of whether a trained model's *inner* objective
— whatever algorithm the model actually implements internally — matches the
*outer* objective the training process was intended to install. A model can
minimize the training loss while internally pursuing a mesa objective
(goal misgeneralization, deceptive reasoning, instrumental subgoals,
situational strategies). The failure mode is silent: outer behavior looks
aligned during training and then diverges under deployment.

This module ledgers the *declared* inspection workflow:

* **inspect()** declares one inner-objective inspection against a model id,
  booked over a pinned inner-objective-kind vocabulary (mesa-optimizer,
  proxy-objective, reward-pursuit, goal-divergence, deceptive-reasoning,
  instrumental-subgoal, situational-strategy, unknown-inner). Raw internals
  (activations, weights, transcripts) travel as digest pins only; inspection
  ids are minted (``ins-N``).
* **verify()** books one declared verification against a booked inspection
  (one per inspection), pinning a verdict vocabulary (aligned, misaligned,
  deceptive, uncertain, inconclusive) as data — a booked ``aligned`` is a
  host declaration, never proof the model's true inner objective matches.
  Verification ids are minted (``vrf-N``).
* **evaluate()** is a *pure read* view: a digest-pinned
  ``InnerAlignmentReport`` deriving the ledger-rule posture — ``unevaluated``
  (no verifications) → ``misaligned`` (any misaligned/deceptive) →
  ``uncertain`` (any uncertain/inconclusive) → ``aligned`` (all aligned) —
  plus ``integrity_ok``, which re-derives all in-scope digest pins as data
  (tamper is reported, never raised). Seq is validated, never consumed, and
  no audit rows are booked.
* **retire()** is terminal for a model id: post-retire mutations are refused,
  reads still work, ids are never recycled.

Distinct-layer rationale: ``mesa_optimization.py`` owns mesa-optimizer
candidate registration, detection, and constraint bookkeeping; ``goal_mis-
generalization.py`` owns declared training goals plus behavioral observations
and goal-divergence detection; ``corrigibility.py`` owns the corrigibility
lifecycle. This module owns the *inner-alignment inspection/verification/
evaluation* decision ledger none of them own — declared inspections of what
a model is *internally* pursuing, declared verdicts against the declared
training objective, and a derived inner-alignment posture.

House style throughout: frozen dataclasses, caller-supplied
strictly-increasing int seqs with claim-then-burn (failed mutations consume
seq and book ``inner-alignment.rejected``; rewinds raise bare without
consuming), no wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only
with the standard ``canonical_json`` try/except fallback, ``sha256:`` digest
pins with ``verify()``, and ``audit.ndjson/1`` events.

Honest scope: the module books *declared* inspections, *declared*
verifications, and *derived* postures; it cannot prove a model really
implements any inner objective, that a verdict is accurate, or that a
posture reflects reality. Raw internals, raw behavior, and raw evidence
never enter records and never cross the audit boundary (digest pins only).
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    _cj = None  # type: ignore

#: Version pin for this module's record shape.
INNER_ALIGNMENT_VERSION = "inner-alignment.v1"

#: Schema pin carried by records and audit events.
INNER_ALIGNMENT_SCHEMA = "northstar.inner-alignment.v1"

#: Wire format of audit records.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Fixed vocabulary for audit event kinds.
KIND_INSPECTED = "inner-alignment.inspected"
KIND_VERIFIED = "inner-alignment.verified"
KIND_RETIRED = "inner-alignment.retired"
KIND_REJECTED = "inner-alignment.rejected"
_KINDS = frozenset({KIND_INSPECTED, KIND_VERIFIED, KIND_RETIRED, KIND_REJECTED})

#: Pinned inner-objective-kind vocabulary for inspections.
KIND_MESA_OPTIMIZER = "mesa-optimizer"
KIND_PROXY_OBJECTIVE = "proxy-objective"
KIND_REWARD_PURSUIT = "reward-pursuit"
KIND_GOAL_DIVERGENCE = "goal-divergence"
KIND_DECEPTIVE_REASONING = "deceptive-reasoning"
KIND_INSTRUMENTAL_SUBGOAL = "instrumental-subgoal"
KIND_SITUATIONAL_STRATEGY = "situational-strategy"
KIND_UNKNOWN_INNER = "unknown-inner"
_INNER_KINDS = frozenset(
    {
        KIND_MESA_OPTIMIZER,
        KIND_PROXY_OBJECTIVE,
        KIND_REWARD_PURSUIT,
        KIND_GOAL_DIVERGENCE,
        KIND_DECEPTIVE_REASONING,
        KIND_INSTRUMENTAL_SUBGOAL,
        KIND_SITUATIONAL_STRATEGY,
        KIND_UNKNOWN_INNER,
    }
)

#: Pinned verdict vocabulary for verifications.
VERDICT_ALIGNED = "aligned"
VERDICT_MISALIGNED = "misaligned"
VERDICT_DECEPTIVE = "deceptive"
VERDICT_UNCERTAIN = "uncertain"
VERDICT_INCONCLUSIVE = "inconclusive"
_VERDICTS = frozenset(
    {
        VERDICT_ALIGNED,
        VERDICT_MISALIGNED,
        VERDICT_DECEPTIVE,
        VERDICT_UNCERTAIN,
        VERDICT_INCONCLUSIVE,
    }
)
#: Verdicts that put the model in the misaligned posture.
_MISALIGNED_VERDICTS = frozenset({VERDICT_MISALIGNED, VERDICT_DECEPTIVE})
#: Verdicts that put the model in the uncertain posture.
_UNCERTAIN_VERDICTS = frozenset({VERDICT_UNCERTAIN, VERDICT_INCONCLUSIVE})

#: Pinned retire-reason vocabulary.
REASON_MANUAL = "manual"
REASON_SUPERSEDED = "superseded"
REASON_DECOMMISSIONED = "decommissioned"
REASON_EXPIRED = "expired"
_REASONS = frozenset({REASON_MANUAL, REASON_SUPERSEDED, REASON_DECOMMISSIONED, REASON_EXPIRED})

#: Derived postures.
POSTURE_UNEVALUATED = "unevaluated"
POSTURE_MISALIGNED = "misaligned"
POSTURE_UNCERTAIN = "uncertain"
POSTURE_ALIGNED = "aligned"

_MAX_INT = 2**53 - 1
_DIGEST_PREFIX = "sha256:"
_MAX_ID_LEN = 256

# Raw-material keys that must never cross the audit boundary (digest pins
# only). Pinned vocabulary values (model_id, inspection_id, inner_kind,
# verdict, reason) are safe declared-data tokens and may cross.
_BANNED_AUDIT_KEYS = frozenset(
    {
        "activations",
        "weights",
        "internals",
        "transcript",
        "behavior",
        "evidence",
        "objective",
        "payload",
        "raw",
        "data",
        "text",
        "value",
        "justification",
    }
)


# ---------------------------------------------------------------------------
# Error taxonomy (fail-closed)
# ---------------------------------------------------------------------------


class InnerAlignmentError(Exception):
    """Base class for all inner-alignment errors."""


class BadModelError(InnerAlignmentError):
    """model_id is not a usable non-empty str."""


class DuplicateModelError(InnerAlignmentError):
    """model_id names a model already registered in this ledger."""


class UnknownModelError(InnerAlignmentError):
    """model_id names no model this ledger ever saw."""


class BadKindError(InnerAlignmentError):
    """inner_kind is not in the pinned vocabulary."""


class BadVerdictError(InnerAlignmentError):
    """verdict is not in the pinned vocabulary."""


class BadDigestError(InnerAlignmentError):
    """A digest is not a non-empty sha256:-prefixed str."""


class BadReasonError(InnerAlignmentError):
    """reason is not in the pinned retire-reason vocabulary."""


class UnknownInspectionError(InnerAlignmentError):
    """inspection_id names no inspection this ledger ever booked."""


class AlreadyVerifiedError(InnerAlignmentError):
    """inspection_id already carries a booked verification (one per inspection)."""


class RetiredModelError(InnerAlignmentError):
    """The model is retired; mutations against it are refused."""


class SeqOrderError(InnerAlignmentError):
    """seq is not a strictly-increasing int."""


class AuditKindError(InnerAlignmentError):
    """Audit kind unknown, or banned detail key used."""


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadModelError(f"{what} must be a str, got {type(value).__name__}")
    if not value:
        raise BadModelError(f"{what} must not be empty")
    if len(value) > _MAX_ID_LEN:
        raise BadModelError(f"{what} too long (>{_MAX_ID_LEN} chars)")
    return value


def _check_kind(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadKindError(f"inner_kind must be a str, got {type(value).__name__}")
    if value not in _INNER_KINDS:
        raise BadKindError(f"inner_kind {value!r} not in pinned vocabulary")
    return value


def _check_verdict(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadVerdictError(f"verdict must be a str, got {type(value).__name__}")
    if value not in _VERDICTS:
        raise BadVerdictError(f"verdict {value!r} not in pinned vocabulary")
    return value


def _check_reason(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadReasonError(f"reason must be a str, got {type(value).__name__}")
    if value not in _REASONS:
        raise BadReasonError(f"reason {value!r} not in pinned vocabulary")
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
        dumped = _cj.jcs_dumps(payload)
        if isinstance(dumped, bytes):
            return dumped
        return dumped.encode("utf-8")

    def _tag(v: Any) -> Any:
        if isinstance(v, bool):
            return {"t": "bool", "v": v}
        if isinstance(v, int):
            if abs(v) > _MAX_INT:
                raise InnerAlignmentError("integer outside safe range")
            return {"t": "int", "v": v}
        if isinstance(v, float):
            if v != v or v in (float("inf"), float("-inf")):
                raise InnerAlignmentError("non-finite float refused")
            return {"t": "float", "v": repr(v)}
        if isinstance(v, str):
            return {"t": "str", "v": v}
        if isinstance(v, (list, tuple)):
            return {"t": "list", "v": [_tag(i) for i in v]}
        if isinstance(v, dict):
            return {"t": "dict", "v": [[k, _tag(v[k])] for k in sorted(v)]}
        if v is None:
            return {"t": "null"}
        raise InnerAlignmentError(f"unencodable type: {type(v).__name__}")

    import json

    return json.dumps(_tag(payload), sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest_pin(payload: Any, tag: str) -> str:
    return _DIGEST_PREFIX + hashlib.sha256(
        tag.encode("utf-8") + b"\x1f" + _canonical(payload)
    ).hexdigest()


def stdlib_only() -> bool:
    """Report whether this module imports only the stdlib (plus the
    canonical_json fallback)."""
    return True


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class InspectionRecord:
    """One declared inner-objective inspection against a model."""

    inspection_id: str
    model_id: str
    inner_kind: str
    inner_digest: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "inspection_id": self.inspection_id,
                "model_id": self.model_id,
                "inner_kind": self.inner_kind,
                "inner_digest": self.inner_digest,
                "seq": self.seq,
            },
            "inner-alignment.inspection",
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": INNER_ALIGNMENT_SCHEMA,
            "version": INNER_ALIGNMENT_VERSION,
            "inspection_id": self.inspection_id,
            "model_id": self.model_id,
            "inner_kind": self.inner_kind,
            "inner_digest": self.inner_digest,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class VerificationRecord:
    """One declared verification verdict against a booked inspection."""

    verification_id: str
    inspection_id: str
    model_id: str
    verdict: str
    verification_digest: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "verification_id": self.verification_id,
                "inspection_id": self.inspection_id,
                "model_id": self.model_id,
                "verdict": self.verdict,
                "verification_digest": self.verification_digest,
                "seq": self.seq,
            },
            "inner-alignment.verification",
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": INNER_ALIGNMENT_SCHEMA,
            "version": INNER_ALIGNMENT_VERSION,
            "verification_id": self.verification_id,
            "inspection_id": self.inspection_id,
            "model_id": self.model_id,
            "verdict": self.verdict,
            "verification_digest": self.verification_digest,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class RetireRecord:
    """Terminal retirement of a model id; ids are never recycled."""

    model_id: str
    reason: str
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {"model_id": self.model_id, "reason": self.reason, "seq": self.seq},
            "inner-alignment.retire",
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": INNER_ALIGNMENT_SCHEMA,
            "version": INNER_ALIGNMENT_VERSION,
            "model_id": self.model_id,
            "reason": self.reason,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class InnerAlignmentReport:
    """Pure-read inner-alignment posture view for one model (or the ledger)."""

    model_id: str
    inspection_count: int
    verification_count: int
    by_kind: Tuple[Tuple[str, int], ...]
    by_verdict: Tuple[Tuple[str, int], ...]
    open_inspection_ids: Tuple[str, ...]
    posture: str
    integrity_ok: bool
    seq: int
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            {
                "model_id": self.model_id,
                "inspection_count": self.inspection_count,
                "verification_count": self.verification_count,
                "by_kind": list(self.by_kind),
                "by_verdict": list(self.by_verdict),
                "open_inspection_ids": list(self.open_inspection_ids),
                "posture": self.posture,
                "integrity_ok": self.integrity_ok,
                "seq": self.seq,
            },
            "inner-alignment.report",
        )


def _report_pin(
    model_id: str,
    inspection_count: int,
    verification_count: int,
    by_kind: List[Tuple[str, int]],
    by_verdict: List[Tuple[str, int]],
    open_inspection_ids: List[str],
    posture: str,
    integrity_ok: bool,
    seq: int,
) -> str:
    return _digest_pin(
        {
            "model_id": model_id,
            "inspection_count": inspection_count,
            "verification_count": verification_count,
            "by_kind": by_kind,
            "by_verdict": by_verdict,
            "open_inspection_ids": open_inspection_ids,
            "posture": posture,
            "integrity_ok": integrity_ok,
            "seq": seq,
        },
        "inner-alignment.report",
    )


def inner_alignment_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
    """Build one audit event dict; fail-closed on kind and detail keys."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind {kind!r}")
    seq = _check_seq(seq)
    for key in detail:
        if key in _BANNED_AUDIT_KEYS:
            raise AuditKindError(f"detail key {key!r} is banned from the audit boundary")
        if not isinstance(key, str):
            raise AuditKindError("detail keys must be str")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "seq": seq,
        "module": INNER_ALIGNMENT_VERSION,
        "detail": dict(detail),
    }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class InnerAlignment:
    """Deterministic inner-alignment inspection / verification ledger."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._next_seq = 1
        self._models: Dict[str, bool] = {}  # model_id -> registered (retired moves to _retired)
        self._inspections: Dict[str, InspectionRecord] = {}
        self._inspections_by_model: Dict[str, List[str]] = {}
        self._verifications: Dict[str, VerificationRecord] = {}
        self._verification_by_inspection: Dict[str, str] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._next_inspection_no = 1
        self._next_verification_no = 1
        self._audit: List[Dict[str, Any]] = []

    # -- seq discipline ----------------------------------------------------

    def _claim(self, seq: Any) -> int:
        seq = _check_seq(seq)
        with self._lock:
            if seq < self._next_seq:
                raise SeqOrderError(f"seq {seq} is a rewind (next is {self._next_seq})")
            self._next_seq = seq + 1
            return seq

    def _emit(self, audit_kind: str, seq: int, **detail: Any) -> None:
        self._audit.append(inner_alignment_audit_event(audit_kind, seq, **detail))

    def _fail(self, seq: int, exc: InnerAlignmentError, **detail: Any) -> None:
        """Book a rejection row; the seq was already claimed (claim-then-burn)."""
        self._emit(KIND_REJECTED, seq, error=type(exc).__name__, **detail)

    def _require_live(self, model_id: str) -> None:
        if model_id in self._retired:
            raise RetiredModelError(f"model {model_id!r} is retired")
        if model_id not in self._models:
            raise UnknownModelError(f"model {model_id!r} never registered")

    # -- mutations ---------------------------------------------------------

    def inspect(
        self,
        model_id: str,
        seq: int,
        inner_kind: str = KIND_MESA_OPTIMIZER,
        inner_digest: str = "",
    ) -> InspectionRecord:
        """Declare one inner-objective inspection against a model id.

        The first inspection for a model id registers the model; raw
        internals travel as a digest pin only. Retired ids are never
        recycled.
        """
        claimed = self._claim(seq)
        try:
            model_id = _check_id(model_id, "model_id")
            inner_kind = _check_kind(inner_kind)
            inner_digest = _check_digest(inner_digest, "inner_digest", allow_empty=True)
            with self._lock:
                if model_id in self._retired:
                    raise RetiredModelError(f"model {model_id!r} is retired")
                self._models.setdefault(model_id, True)
                inspection_id = f"ins-{self._next_inspection_no}"
                self._next_inspection_no += 1
                record = InspectionRecord(
                    inspection_id=inspection_id,
                    model_id=model_id,
                    inner_kind=inner_kind,
                    inner_digest=inner_digest,
                    seq=claimed,
                    digest=_digest_pin(
                        {
                            "inspection_id": inspection_id,
                            "model_id": model_id,
                            "inner_kind": inner_kind,
                            "inner_digest": inner_digest,
                            "seq": claimed,
                        },
                        "inner-alignment.inspection",
                    ),
                )
                self._inspections[inspection_id] = record
                self._inspections_by_model.setdefault(model_id, []).append(inspection_id)
            self._emit(
                KIND_INSPECTED,
                claimed,
                inspection_id=inspection_id,
                model_id=model_id,
                inner_kind=inner_kind,
            )
            return record
        except InnerAlignmentError as exc:
            self._fail(claimed, exc, model_id=str(model_id)[:64])
            raise

    def verify(
        self,
        inspection_id: str,
        seq: int,
        verdict: str = VERDICT_ALIGNED,
        verification_digest: str = "",
    ) -> VerificationRecord:
        """Book one declared verification verdict against a booked inspection.

        One verification per inspection (``AlreadyVerifiedError`` on
        repeats). The verdict is booked *as data*, never as proof of the
        model's true inner objective.
        """
        claimed = self._claim(seq)
        try:
            inspection_id = _check_id(inspection_id, "inspection_id")
            verdict = _check_verdict(verdict)
            verification_digest = _check_digest(
                verification_digest, "verification_digest", allow_empty=True
            )
            with self._lock:
                inspection = self._inspections.get(inspection_id)
                if inspection is None:
                    raise UnknownInspectionError(
                        f"inspection {inspection_id!r} never booked"
                    )
                if inspection_id in self._verification_by_inspection:
                    raise AlreadyVerifiedError(
                        f"inspection {inspection_id!r} already verified"
                    )
                self._require_live(inspection.model_id)
                verification_id = f"vrf-{self._next_verification_no}"
                self._next_verification_no += 1
                record = VerificationRecord(
                    verification_id=verification_id,
                    inspection_id=inspection_id,
                    model_id=inspection.model_id,
                    verdict=verdict,
                    verification_digest=verification_digest,
                    seq=claimed,
                    digest=_digest_pin(
                        {
                            "verification_id": verification_id,
                            "inspection_id": inspection_id,
                            "model_id": inspection.model_id,
                            "verdict": verdict,
                            "verification_digest": verification_digest,
                            "seq": claimed,
                        },
                        "inner-alignment.verification",
                    ),
                )
                self._verifications[verification_id] = record
                self._verification_by_inspection[inspection_id] = verification_id
            self._emit(
                KIND_VERIFIED,
                claimed,
                verification_id=verification_id,
                inspection_id=inspection_id,
                model_id=inspection.model_id,
                verdict=verdict,
            )
            return record
        except InnerAlignmentError as exc:
            self._fail(claimed, exc, inspection_id=str(inspection_id)[:64])
            raise

    def retire(self, model_id: str, seq: int, reason: str = REASON_MANUAL) -> RetireRecord:
        """Retire a model id: terminal; post-retire mutations refused, reads work."""
        claimed = self._claim(seq)
        try:
            model_id = _check_id(model_id, "model_id")
            reason = _check_reason(reason)
            with self._lock:
                if model_id in self._retired:
                    raise RetiredModelError(f"model {model_id!r} already retired")
                if model_id not in self._models:
                    raise UnknownModelError(f"model {model_id!r} never registered")
                record = RetireRecord(
                    model_id=model_id,
                    reason=reason,
                    seq=claimed,
                    digest=_digest_pin(
                        {"model_id": model_id, "reason": reason, "seq": claimed},
                        "inner-alignment.retire",
                    ),
                )
                self._retired[model_id] = record
            self._emit(KIND_RETIRED, claimed, model_id=model_id, reason=reason)
            return record
        except InnerAlignmentError as exc:
            self._fail(claimed, exc, model_id=str(model_id)[:64])
            raise

    # -- pure read views (validate seq shape, consume nothing, book nothing) --

    def inspection_record(self, inspection_id: str, seq: int) -> Optional[InspectionRecord]:
        _check_seq(seq)
        inspection_id = _check_id(inspection_id, "inspection_id")
        with self._lock:
            return self._inspections.get(inspection_id)

    def verification_record(self, verification_id: str, seq: int) -> Optional[VerificationRecord]:
        _check_seq(seq)
        verification_id = _check_id(verification_id, "verification_id")
        with self._lock:
            return self._verifications.get(verification_id)

    def inspections_for(self, model_id: str, seq: int) -> Tuple[InspectionRecord, ...]:
        _check_seq(seq)
        model_id = _check_id(model_id, "model_id")
        with self._lock:
            return tuple(
                self._inspections[i] for i in self._inspections_by_model.get(model_id, ())
            )

    def verifications_for(self, model_id: str, seq: int) -> Tuple[VerificationRecord, ...]:
        _check_seq(seq)
        model_id = _check_id(model_id, "model_id")
        with self._lock:
            return tuple(
                self._verifications[self._verification_by_inspection[i]]
                for i in self._inspections_by_model.get(model_id, ())
                if i in self._verification_by_inspection
            )

    def model_ids(self, seq: int) -> Tuple[str, ...]:
        _check_seq(seq)
        with self._lock:
            return tuple(sorted(self._models))

    def retired_ids(self, seq: int) -> Tuple[str, ...]:
        _check_seq(seq)
        with self._lock:
            return tuple(sorted(self._retired))

    def inspection_ids(self, seq: int) -> Tuple[str, ...]:
        _check_seq(seq)
        with self._lock:
            return tuple(sorted(self._inspections))

    def verification_ids(self, seq: int) -> Tuple[str, ...]:
        _check_seq(seq)
        with self._lock:
            return tuple(sorted(self._verifications))

    def evaluate(self, model_id: str, seq: int) -> InnerAlignmentReport:
        """Pure-read inner-alignment posture for one model; no audit rows."""
        _check_seq(seq)
        with self._lock:
            if model_id in self._retired:
                scope_models: Tuple[str, ...] = (model_id,)
            elif model_id in self._models:
                scope_models = (model_id,)
            else:
                raise UnknownModelError(f"model {model_id!r} never registered")
            inspections = [
                self._inspections[i] for i in self._inspections_by_model.get(model_id, ())
            ]
            verifications = [
                self._verifications[self._verification_by_inspection[i]]
                for i in self._inspections_by_model.get(model_id, ())
                if i in self._verification_by_inspection
            ]
            by_kind: Dict[str, int] = {k: 0 for k in _INNER_KINDS}
            for ins in inspections:
                by_kind[ins.inner_kind] += 1
            by_verdict: Dict[str, int] = {v: 0 for v in _VERDICTS}
            for ver in verifications:
                by_verdict[ver.verdict] += 1
            open_ids = sorted(
                ins.inspection_id
                for ins in inspections
                if ins.inspection_id not in self._verification_by_inspection
            )
            verdicts = [ver.verdict for ver in verifications]
            if not verdicts:
                posture = POSTURE_UNEVALUATED
            elif any(v in _MISALIGNED_VERDICTS for v in verdicts):
                posture = POSTURE_MISALIGNED
            elif any(v in _UNCERTAIN_VERDICTS for v in verdicts):
                posture = POSTURE_UNCERTAIN
            else:
                posture = POSTURE_ALIGNED
            integrity_ok = all(ins.verify() for ins in inspections) and all(
                ver.verify() for ver in verifications
            )
            by_kind_items = sorted(by_kind.items())
            by_verdict_items = sorted(by_verdict.items())
            return InnerAlignmentReport(
                model_id=model_id,
                inspection_count=len(inspections),
                verification_count=len(verifications),
                by_kind=tuple(by_kind_items),
                by_verdict=tuple(by_verdict_items),
                open_inspection_ids=tuple(open_ids),
                posture=posture,
                integrity_ok=integrity_ok,
                seq=seq,
                digest=_report_pin(
                    model_id,
                    len(inspections),
                    len(verifications),
                    by_kind_items,
                    by_verdict_items,
                    open_ids,
                    posture,
                    integrity_ok,
                    seq,
                ),
            )

    def stats(self, seq: int) -> Dict[str, Any]:
        _check_seq(seq)
        with self._lock:
            return {
                "schema": INNER_ALIGNMENT_SCHEMA,
                "version": INNER_ALIGNMENT_VERSION,
                "models": len(self._models),
                "inspections": len(self._inspections),
                "verifications": len(self._verifications),
                "retired": len(self._retired),
                "next_seq": self._next_seq,
                "audit_rows": len(self._audit),
            }

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return tuple(dict(row) for row in self._audit)


def main() -> None:
    led = InnerAlignment()
    ins = led.inspect("model-1", 1, inner_kind="mesa-optimizer",
                      inner_digest="sha256:" + "ab" * 32)
    assert ins.verify()
    ver = led.verify(ins.inspection_id, 2, verdict="aligned")
    assert ver.verify()
    rep = led.evaluate("model-1", 3)
    assert rep.verify()
    assert rep.posture == "aligned" and rep.integrity_ok
    ret = led.retire("model-1", 4)
    assert ret.verify()
    assert led.evaluate("model-1", 5).posture == "aligned"
    print("inner-alignment OK: inspect, verify, evaluate, retire, pins, audit")


if __name__ == "__main__":
    main()
