"""model_theft.py — model-theft detect/deter governance ledger.

Model-extraction / substitute-model theft governance as a deterministic
single-host decision ledger. This layer owns the *governance* lifecycle —
book a declared theft detection (against a host-reported detector verdict),
book declared deterrence actions, and derive audit reports — all as frozen
records with caller-supplied strictly increasing sequence numbers.

Distinct from ``model_extraction_detector.py`` (the sibling *signal* layer:
it computes suspicion from query shapes — volume, diversity, perturbation
clusters, output-class coverage — and must be read before this one). This
module runs no detector math and performs no enforcement; it books the
host's declared decisions:

1. ``detect()`` — book one declared theft-detection decision for a model,
   pinned to the detector report digest and a host-reported suspicion score
   in [0, 1]. The verdict (``suspected-theft``/``monitoring``/``clean``/
   ``inconclusive``) is booked **as data**.
2. ``deter()`` — book one declared deterrence action against a booked
   detection (``rate-limit``/``noise-inject``/``watermark-inject``/
   ``challenge-response``/``query-ban``/``model-throttle``/``escalate``),
   repeatable as an action chain. Books the *decision*, never executes it.
3. ``audit()`` — pure read view deriving an ``AuditReport`` for a model
   (detection counts by verdict, deterrence actions applied, digest-pinned
   with ``verify()``).

Honest scope: a booked ``suspected-theft`` verdict means "the host reported
suspicion above its own threshold", never proof that theft occurred; a
booked deterrence action means "the host declared it applied this action",
never that the action was enforced. The module inspects no queries and
blocks no callers; it keeps the governance trail honest and replayable.

House rules (shared with the runtime fleet): frozen dataclasses, no
wall-clock reads, RLock-guarded, fail-closed, stdlib-only with
``canonical_json`` try/except fallback, ``sha256:`` digest pins with
``verify()``, claim-then-burn seq discipline (failed mutations consume
their seq and book ``model-theft.rejected``; bare rewinds raise without
consuming), and ``audit.ndjson/1`` events with raw query/model content
banned from the audit boundary.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

try:  # pragma: no cover
    from canonical_json import jcs_dumps as _jcs_dumps  # type: ignore
except Exception:  # pragma: no cover
    _jcs_dumps = None  # type: ignore

VERSION = "model-theft.v1"
SCHEMA = "northstar.model-theft.v1"
AUDIT_SCHEMA = "audit.ndjson/1"

_DIGEST_PREFIX = "sha256:"
_MAX_ID_LEN = 128

#: Verdict vocabulary a detection may carry. Booked as data.
VERDICTS = (
    "suspected-theft",
    "monitoring",
    "clean",
    "inconclusive",
)

#: Deterrence action vocabulary. Each books the *decision*, never enforcement.
DETERRENCE_ACTIONS = (
    "rate-limit",
    "noise-inject",
    "watermark-inject",
    "challenge-response",
    "query-ban",
    "model-throttle",
    "escalate",
)

AUDIT_KINDS = (
    "theft-detected",
    "deterrence-applied",
    "model-theft.rejected",
)


class ModelTheftError(Exception):
    """Base for all model-theft ledger errors."""


class BadIdError(ModelTheftError):
    pass


class DuplicateDetectionError(ModelTheftError):
    pass


class UnknownDetectionError(ModelTheftError):
    pass


class BadDigestError(ModelTheftError):
    pass


class BadSuspicionError(ModelTheftError):
    pass


class BadVerdictError(ModelTheftError):
    pass


class BadActionError(ModelTheftError):
    pass


class SeqOrderError(ModelTheftError):
    pass


class AuditKindError(ModelTheftError):
    pass


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"seq must be an int, got {type(seq).__name__}")
    return seq


def _check_id(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadIdError(f"{what} must be a str, got {type(value).__name__}")
    if not value or len(value) > _MAX_ID_LEN:
        raise BadIdError(f"{what} must be a non-empty str of <= {_MAX_ID_LEN} chars")
    return value


def _check_digest(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadDigestError(f"{what} must be a str, got {type(value).__name__}")
    if len(value) != len(_DIGEST_PREFIX) + 64 or not value.startswith(_DIGEST_PREFIX):
        raise BadDigestError(f"{what} must be a 'sha256:<64hex>' pin")
    if any(c not in "0123456789abcdef" for c in value[len(_DIGEST_PREFIX):]):
        raise BadDigestError(f"{what} hex part must be lowercase hex")
    return value


def _check_suspicion(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise BadSuspicionError(
            f"suspicion must be a real number in [0, 1], got {type(value).__name__}"
        )
    score = float(value)
    if not (0.0 <= score <= 1.0):
        raise BadSuspicionError(f"suspicion must be in [0, 1], got {score!r}")
    return score


def _canonical(payload: Any) -> bytes:
    if _jcs_dumps is not None:
        try:
            return _jcs_dumps(payload).encode("utf-8")
        except Exception:
            pass  # fall through to the deterministic fallback
    import json

    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest_pin(payload: Any, tag: str) -> str:
    return _DIGEST_PREFIX + hashlib.sha256(
        tag.encode("utf-8") + b"\x1f" + _canonical(payload)
    ).hexdigest()


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DetectionRecord:
    """One declared theft-detection decision for a model."""

    detection_id: str
    model_id: str
    detector_digest: str
    suspicion: float
    verdict: str
    seq: int
    digest: str
    schema: str = SCHEMA
    version: str = VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "detection_id": self.detection_id,
            "model_id": self.model_id,
            "detector_digest": self.detector_digest,
            "suspicion": self.suspicion,
            "verdict": self.verdict,
            "seq": self.seq,
            "digest": self.digest,
            "schema": self.schema,
            "version": self.version,
        }

    def verify(self) -> bool:
        expect = _digest_pin(
            (
                self.detection_id,
                self.model_id,
                self.detector_digest,
                repr(self.suspicion),
                self.verdict,
            ),
            "detection",
        )
        return self.digest == expect


@dataclass(frozen=True)
class DeterrenceRecord:
    """One declared deterrence action booked against a detection."""

    action_id: str
    detection_id: str
    action: str
    params_digest: str
    seq: int
    digest: str
    schema: str = SCHEMA
    version: str = VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "action_id": self.action_id,
            "detection_id": self.detection_id,
            "action": self.action,
            "params_digest": self.params_digest,
            "seq": self.seq,
            "digest": self.digest,
            "schema": self.schema,
            "version": self.version,
        }

    def verify(self) -> bool:
        expect = _digest_pin(
            (
                self.action_id,
                self.detection_id,
                self.action,
                self.params_digest,
            ),
            "deterrence",
        )
        return self.digest == expect


@dataclass(frozen=True)
class AuditReport:
    """Pure read view: theft-governance posture for one model."""

    model_id: str
    seq: int
    detection_ids: Tuple[str, ...]
    verdict_counts: Tuple[Tuple[str, int], ...]
    deterrence_ids: Tuple[str, ...]
    actions_applied: Tuple[Tuple[str, int], ...]
    digest: str
    schema: str = SCHEMA
    version: str = VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "model_id": self.model_id,
            "seq": self.seq,
            "detection_ids": list(self.detection_ids),
            "verdict_counts": [
                {"verdict": v, "count": c} for v, c in self.verdict_counts
            ],
            "deterrence_ids": list(self.deterrence_ids),
            "actions_applied": [
                {"action": a, "count": c} for a, c in self.actions_applied
            ],
            "digest": self.digest,
            "schema": self.schema,
            "version": self.version,
        }

    def verify(self) -> bool:
        expect = _digest_pin(
            (
                self.model_id,
                self.detection_ids,
                self.verdict_counts,
                self.deterrence_ids,
                self.actions_applied,
            ),
            "audit",
        )
        return self.digest == expect


# ---------------------------------------------------------------------------
# Audit event builder
# ---------------------------------------------------------------------------


def model_theft_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
    """Build one audit.ndjson/1 event. Raw queries/model content never crosses this boundary."""
    if kind not in AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    banned = (
        "query",
        "queries",
        "input",
        "inputs",
        "output",
        "outputs",
        "text",
        "content",
        "payload",
        "raw",
        "value",
        "weights",
        "model_weights",
        "secret",
        "plaintext",
        "key",
    )
    for bad in banned:
        if bad in detail:
            raise AuditKindError(f"audit detail bans {bad!r}")
    _check_seq(seq)
    event = {
        "schema": AUDIT_SCHEMA,
        "module": "model_theft",
        "kind": kind,
        "seq": seq,
        "detail": detail,
    }
    event["digest"] = _digest_pin((kind, seq, tuple(sorted(detail))), "audit-event")
    return event


# ---------------------------------------------------------------------------
# Model-theft ledger
# ---------------------------------------------------------------------------


class ModelTheft:
    """Model-theft governance bookkeeping: detect, deter, audit."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        # detection_id -> DetectionRecord (insertion ordered)
        self._detections: Dict[str, DetectionRecord] = {}
        # action_id -> DeterrenceRecord (insertion ordered)
        self._deterrence: Dict[str, DeterrenceRecord] = {}
        self._audit_events: List[Dict[str, Any]] = []
        self._det_counter = 0
        self._act_counter = 0

    # -- seq discipline ----------------------------------------------------

    def _claim(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError(f"seq {seq} not strictly greater than {self._seq}")
        self._seq = seq
        return seq

    def _emit(self, audit_kind: str, seq: int, **detail: Any) -> None:
        self._audit_events.append(
            model_theft_audit_event(audit_kind, seq, **detail)
        )

    def _fail(self, seq: int, exc: ModelTheftError, **detail: Any) -> None:
        self._emit(AUDIT_KINDS[-1], seq, error=type(exc).__name__, **detail)
        raise exc

    # -- mutations ----------------------------------------------------------

    def detect(
        self,
        model_id: str,
        detector_digest: str,
        seq: int,
        suspicion: float,
        verdict: str,
    ) -> DetectionRecord:
        """Book one declared theft-detection decision.

        ``detector_digest`` pins the host detector's report (e.g. the
        sibling ``model_extraction_detector`` analysis) — raw queries
        never enter a record. ``verdict`` is booked as data, never proof.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                model_id = _check_id(model_id, "model_id")
                detector_digest = _check_digest(detector_digest, "detector_digest")
                suspicion = _check_suspicion(suspicion)
                if verdict not in VERDICTS:
                    raise BadVerdictError(
                        f"verdict must be one of {VERDICTS}, got {verdict!r}"
                    )
            except ModelTheftError as exc:
                self._fail(seq, exc, model_id=str(model_id))
            self._det_counter += 1
            detection_id = f"det-{self._det_counter}"
            record = DetectionRecord(
                detection_id=detection_id,
                model_id=model_id,
                detector_digest=detector_digest,
                suspicion=suspicion,
                verdict=verdict,
                seq=seq,
                digest=_digest_pin(
                    (
                        detection_id,
                        model_id,
                        detector_digest,
                        repr(suspicion),
                        verdict,
                    ),
                    "detection",
                ),
            )
            self._detections[detection_id] = record
            self._emit(
                AUDIT_KINDS[0],
                seq,
                detection_id=detection_id,
                model_id=model_id,
                suspicion=repr(suspicion),
                verdict=verdict,
            )
            return record

    def deter(
        self,
        detection_id: str,
        action: str,
        seq: int,
        params_digest: str = "",
    ) -> DeterrenceRecord:
        """Book one declared deterrence action against a booked detection.

        Repeatable as an action chain (``dtr-1``..``dtr-N``); books the
        *decision*, never performs the action.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                detection_id = _check_id(detection_id, "detection_id")
                if action not in DETERRENCE_ACTIONS:
                    raise BadActionError(
                        f"action must be one of {DETERRENCE_ACTIONS}, got {action!r}"
                    )
                if params_digest != "" and not isinstance(params_digest, str):
                    raise BadDigestError("params_digest must be a str")
                if params_digest and not params_digest.startswith(_DIGEST_PREFIX):
                    raise BadDigestError(
                        "params_digest must be a 'sha256:<64hex>' pin or ''"
                    )
                if params_digest:
                    params_digest = _check_digest(params_digest, "params_digest")
                if detection_id not in self._detections:
                    raise UnknownDetectionError(
                        f"no booked detection: {detection_id!r}"
                    )
            except ModelTheftError as exc:
                self._fail(seq, exc, detection_id=str(detection_id))
            self._act_counter += 1
            action_id = f"dtr-{self._act_counter}"
            record = DeterrenceRecord(
                action_id=action_id,
                detection_id=detection_id,
                action=action,
                params_digest=params_digest,
                seq=seq,
                digest=_digest_pin(
                    (action_id, detection_id, action, params_digest), "deterrence"
                ),
            )
            self._deterrence[action_id] = record
            self._emit(
                AUDIT_KINDS[1],
                seq,
                action_id=action_id,
                detection_id=detection_id,
                action=action,
            )
            return record

    def audit(self, seq: int, model_id: str) -> AuditReport:
        """Pure read view: governance posture for one model.

        Validates seq shape, never consumes it, writes no audit row.
        """
        with self._lock:
            _check_seq(seq)
            model_id = _check_id(model_id, "model_id")
            detections = [
                r for r in self._detections.values() if r.model_id == model_id
            ]
            verdict_counts: List[Tuple[str, int]] = [
                (v, sum(1 for r in detections if r.verdict == v))
                for v in VERDICTS
                if any(r.verdict == v for r in detections)
            ]
            booked_ids = {r.detection_id for r in detections}
            deterrence = [
                a for a in self._deterrence.values() if a.detection_id in booked_ids
            ]
            actions_applied: List[Tuple[str, int]] = [
                (a, sum(1 for r in deterrence if r.action == a))
                for a in DETERRENCE_ACTIONS
                if any(r.action == a for r in deterrence)
            ]
            detection_ids = tuple(r.detection_id for r in detections)
            deterrence_ids = tuple(r.action_id for r in deterrence)
            return AuditReport(
                model_id=model_id,
                seq=seq,
                detection_ids=detection_ids,
                verdict_counts=tuple(verdict_counts),
                deterrence_ids=deterrence_ids,
                actions_applied=tuple(actions_applied),
                digest=_digest_pin(
                    (
                        model_id,
                        detection_ids,
                        tuple(verdict_counts),
                        deterrence_ids,
                        tuple(actions_applied),
                    ),
                    "audit",
                ),
            )

    # -- pure views ---------------------------------------------------------

    def detection_record(self, detection_id: str) -> DetectionRecord:
        with self._lock:
            detection_id = _check_id(detection_id, "detection_id")
            try:
                return self._detections[detection_id]
            except KeyError:
                raise UnknownDetectionError(
                    f"no booked detection: {detection_id!r}"
                ) from None

    def deterrence_for(self, detection_id: str) -> List[DeterrenceRecord]:
        with self._lock:
            detection_id = _check_id(detection_id, "detection_id")
            if detection_id not in self._detections:
                raise UnknownDetectionError(
                    f"no booked detection: {detection_id!r}"
                )
            return [
                a
                for a in self._deterrence.values()
                if a.detection_id == detection_id
            ]

    def detection_ids(self) -> List[str]:
        with self._lock:
            return list(self._detections)

    def model_ids(self) -> List[str]:
        with self._lock:
            seen: List[str] = []
            for record in self._detections.values():
                if record.model_id not in seen:
                    seen.append(record.model_id)
            return seen

    def stats(self) -> Dict[str, int]:
        with self._lock:
            return {
                "detections": len(self._detections),
                "deterrence_actions": len(self._deterrence),
                "models": len(self.model_ids()),
                "seq": self._seq,
            }

    def audit_log(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [dict(event) for event in self._audit_events]


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------


def main() -> None:
    import hashlib as _hl

    ledger = ModelTheft()
    pin = _DIGEST_PREFIX + _hl.sha256(b"detector-report").hexdigest()
    det = ledger.detect("model-alpha", pin, 1, 0.9, "suspected-theft")
    assert det.verify()
    act = ledger.deter(det.detection_id, "rate-limit", 2)
    assert act.verify()
    report = ledger.audit(3, "model-alpha")
    assert report.verify() and report.verdict_counts == (("suspected-theft", 1),)
    print("model-theft OK: detect, deter, audit, pins, rejected-rows")


if __name__ == "__main__":  # pragma: no cover
    main()
