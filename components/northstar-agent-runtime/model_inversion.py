"""Model-inversion attack defense bookkeeping.

Detection-assessment and defense-decision ledger for model-inversion
attacks (the shape this mirrors: Fredrikson et al.'s confidence-score
inversion / reconstruction attacks, where an adversary recovers private
training inputs from model outputs) as a deterministic single-host
state machine.

House style:
  - frozen dataclasses, caller int seqs strictly increasing (no wall-clock)
  - RLock-guarded, fail-closed, stdlib-only
  - `sha256:` digest pins with `verify()`
  - `audit.ndjson/1` events; reconstructed samples stay out of the audit
    boundary
  - failed mutations consume their seq (claim-then-burn) and book
    `model-inversion.rejected`

Honest scope: books *declared* detection assessments over *host-reported*
signals and *declared* defense decisions. A booked `confirmed` verdict
means the host's reported signals crossed the pinned thresholds - never
proof a real inversion attack happened. This module runs no attack,
reconstructs nothing, sees no model weights and no training data; every
signal is GIGO bookkeeping data.
"""

from __future__ import annotations

import hashlib
import json
import math
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

try:  # pragma: no cover - sibling convention
    from canonical_json import jcs_dumps  # type: ignore
except Exception:  # pragma: no cover
    def jcs_dumps(obj: Any) -> bytes:
        return json.dumps(
            obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

VERSION = "model-inversion.v1"
SCHEMA = "northstar.model-inversion.v1"

RISK_CLASSES = ("low", "medium", "high", "critical")

VERDICTS = ("confirmed", "suspected", "benign")

DEFENSES = (
    "output-rounding",
    "confidence-truncation",
    "rate-limit",
    "query-budget",
    "differential-privacy",
    "model-distillation",
    "block",
)

STRENGTHS = ("light", "standard", "strict")

#: Similarity at or above this books `confirmed` (host-reported
#: reconstruction similarity in [0, 1]).
CONFIRMED_SIMILARITY = 0.8
#: Similarity at or above this books `suspected`.
SUSPECTED_SIMILARITY = 0.5
#: Query count at or above this books `suspected` regardless of similarity.
SUSPECTED_QUERIES = 200

_HASH_DOMAIN = b"northstar.model-inversion.v1\x00"


# ---------------------------------------------------------------------------
# errors
# ---------------------------------------------------------------------------

class ModelInversionError(Exception):
    """Base."""


class BadModelError(ModelInversionError):
    pass


class DuplicateModelError(ModelInversionError):
    pass


class UnknownModelError(ModelInversionError):
    pass


class BadRiskClassError(ModelInversionError):
    pass


class BadSignalError(ModelInversionError):
    pass


class BadDefenseError(ModelInversionError):
    pass


class BadStrengthError(ModelInversionError):
    pass


class BadDigestError(ModelInversionError):
    pass


class SeqOrderError(ModelInversionError):
    pass


class AuditKindError(ModelInversionError):
    pass


# ---------------------------------------------------------------------------
# audit
# ---------------------------------------------------------------------------

_AUDIT_KINDS = (
    "model-registered",
    "detection-booked",
    "defense-applied",
    "rejected",
)


def model_inversion_audit_event(
    kind: str, detail: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    if kind not in _AUDIT_KINDS:
        raise AuditKindError(f"bad audit kind: {kind!r}")
    _check_audit_detail(dict(detail or {}))
    return {
        "kind": kind,
        "detail": dict(detail or {}),
        "schema": "audit.ndjson/1",
    }


_BANNED_AUDIT_KEYS = (
    "sample",
    "reconstruction",
    "image",
    "pixels",
    "training_data",
    "embedding",
    "query",
    "text",
    "secret",
    "face",
    "biometric",
)


def _check_audit_detail(detail: Dict[str, Any]) -> None:
    for key in _BANNED_AUDIT_KEYS:
        if key in detail:
            raise BadDigestError(f"raw data key banned from audit boundary: {key!r}")


# ---------------------------------------------------------------------------
# validation helpers
# ---------------------------------------------------------------------------

def _check_id(value: Any) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise BadModelError(f"bad id: {value!r}")
    if len(value) > 128:
        raise BadModelError("id too long")
    return value


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError(f"bad seq: {seq!r}")
    return seq


def _check_digest(value: Any) -> str:
    # raw reconstructed samples / secrets never enter the ledger; pins only
    if not isinstance(value, str):
        raise BadDigestError(f"bad digest: {value!r}")
    if value == "":
        return value
    if len(value) != 7 + 64 or not value.startswith("sha256:"):
        raise BadDigestError(f"bad digest: {value!r}")
    try:
        int(value[7:], 16)
    except ValueError:
        raise BadDigestError(f"bad digest: {value!r}")
    return value


def _check_queries(value: Any) -> int:
    # host-reported related-query count; bool is never a count
    if isinstance(value, bool) or not isinstance(value, int):
        raise BadSignalError(f"bad query count: {value!r}")
    if value < 0:
        raise BadSignalError(f"query count must be >= 0: {value!r}")
    return value


def _check_similarity(value: Any) -> float:
    # host-reported reconstruction similarity in [0, 1]; bool refused
    if isinstance(value, bool):
        raise BadSignalError(f"bool is not a similarity: {value!r}")
    if isinstance(value, int):
        value = float(value)
    if not isinstance(value, float) or not math.isfinite(value):
        raise BadSignalError(f"bad similarity: {value!r}")
    if not 0.0 <= value <= 1.0:
        raise BadSignalError(f"similarity must be in [0, 1]: {value!r}")
    return value


def _check_entropy(value: Any) -> float:
    # host-reported average confidence entropy >= 0; bool refused
    if isinstance(value, bool):
        raise BadSignalError(f"bool is not an entropy: {value!r}")
    if isinstance(value, int):
        value = float(value)
    if not isinstance(value, float) or not math.isfinite(value):
        raise BadSignalError(f"bad entropy: {value!r}")
    if value < 0.0:
        raise BadSignalError(f"entropy must be >= 0: {value!r}")
    return value


def _digest_pin(*parts: Any) -> str:
    blob = jcs_dumps([_HASH_DOMAIN.hex()] + list(parts))
    if isinstance(blob, str):
        blob = blob.encode("utf-8")
    return "sha256:" + hashlib.sha256(blob).hexdigest()


def _derive_verdict(similarity: float, queries: int) -> str:
    """Deterministic verdict from host-reported signals, booked as data."""
    if similarity >= CONFIRMED_SIMILARITY:
        return "confirmed"
    if similarity >= SUSPECTED_SIMILARITY or queries >= SUSPECTED_QUERIES:
        return "suspected"
    return "benign"


# ---------------------------------------------------------------------------
# frozen records
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ModelRecord:
    model_id: str
    risk_class: str
    owner_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            self.model_id, self.risk_class, self.owner_digest
        )


@dataclass(frozen=True)
class DetectionRecord:
    detection_id: str
    model_id: str
    queries: int
    similarity: float
    entropy: float
    signals_digest: str
    verdict: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            self.detection_id,
            self.model_id,
            self.queries,
            repr(self.similarity),
            repr(self.entropy),
            self.signals_digest,
            self.verdict,
        )


@dataclass(frozen=True)
class DefenseRecord:
    defense_id: str
    model_id: str
    defense: str
    strength: str
    detail_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            self.defense_id,
            self.model_id,
            self.defense,
            self.strength,
            self.detail_digest,
        )


@dataclass(frozen=True)
class AuditReport:
    model_id: str
    detections: int
    verdict_counts: Tuple[Tuple[str, int], ...]
    defenses: int
    defense_counts: Tuple[Tuple[str, int], ...]
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            self.model_id,
            self.detections,
            [list(row) for row in self.verdict_counts],
            self.defenses,
            [list(row) for row in self.defense_counts],
        )


# ---------------------------------------------------------------------------
# ledger
# ---------------------------------------------------------------------------

class ModelInversion:
    """Detection/defense decision ledger for model-inversion attacks."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._models: Dict[str, ModelRecord] = {}
        self._detections: Dict[str, DetectionRecord] = {}
        self._defenses: Dict[str, DefenseRecord] = {}
        self._last_seq: int = -1
        self._detection_seq = 0
        self._defense_seq = 0
        self._audit: List[Dict[str, Any]] = []

    # -- seq discipline -----------------------------------------------------

    def _claim(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(f"seq must strictly increase: {seq!r}")
        self._last_seq = seq
        return seq

    def _emit(self, audit_kind: str, detail: Dict[str, Any]) -> None:
        _check_audit_detail(detail)
        self._audit.append(model_inversion_audit_event(audit_kind, detail))

    # -- models -------------------------------------------------------------

    def register_model(
        self,
        model_id: Any,
        seq: Any,
        risk_class: Any = "high",
        owner_digest: Any = "",
    ) -> ModelRecord:
        """Declare a model under inversion-defense protection."""
        with self._lock:
            seq = self._claim(seq)
            try:
                mid = _check_id(model_id)
                if mid in self._models:
                    raise DuplicateModelError(f"model exists: {mid!r}")
                if risk_class not in RISK_CLASSES:
                    raise BadRiskClassError(f"bad risk class: {risk_class!r}")
                owner = _check_digest(owner_digest)
                record = ModelRecord(
                    model_id=mid,
                    risk_class=risk_class,
                    owner_digest=owner,
                    digest=_digest_pin(mid, risk_class, owner),
                )
                self._models[mid] = record
                self._emit(
                    "model-registered",
                    {"model_id": mid, "risk_class": risk_class},
                )
                return record
            except ModelInversionError:
                self._emit("rejected", {"seq": seq, "op": "register_model"})
                raise

    def model_record(self, model_id: Any) -> ModelRecord:
        with self._lock:
            mid = _check_id(model_id)
            if mid not in self._models:
                raise UnknownModelError(f"unknown model: {mid!r}")
            return self._models[mid]

    def model_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._models))

    # -- detection ----------------------------------------------------------

    def detect(
        self,
        model_id: Any,
        seq: Any,
        signals_digest: Any = "",
        queries: Any = 0,
        similarity: Any = 0.0,
        entropy: Any = 0.0,
    ) -> DetectionRecord:
        """Book one detection assessment over host-reported signals.

        The verdict is derived deterministically from the pinned
        thresholds (similarity >= 0.8 -> `confirmed`; similarity >= 0.5
        or queries >= 200 -> `suspected`; else `benign`) and booked **as
        data** - never proof of a real inversion attack.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                mid = _check_id(model_id)
                if mid not in self._models:
                    raise UnknownModelError(f"unknown model: {mid!r}")
                s_digest = _check_digest(signals_digest)
                n_queries = _check_queries(queries)
                sim = _check_similarity(similarity)
                ent = _check_entropy(entropy)
                verdict = _derive_verdict(sim, n_queries)
                self._detection_seq += 1
                det_id = f"det-{self._detection_seq}"
                record = DetectionRecord(
                    detection_id=det_id,
                    model_id=mid,
                    queries=n_queries,
                    similarity=sim,
                    entropy=ent,
                    signals_digest=s_digest,
                    verdict=verdict,
                    digest=_digest_pin(
                        det_id, mid, n_queries,
                        repr(sim), repr(ent), s_digest, verdict,
                    ),
                )
                self._detections[det_id] = record
                self._emit(
                    "detection-booked",
                    {
                        "detection_id": det_id,
                        "model_id": mid,
                        "verdict": verdict,
                    },
                )
                return record
            except ModelInversionError:
                self._emit("rejected", {"seq": seq, "op": "detect"})
                raise

    def detection_record(self, detection_id: Any) -> DetectionRecord:
        with self._lock:
            if not isinstance(detection_id, str) or detection_id not in self._detections:
                raise UnknownModelError(f"unknown detection: {detection_id!r}")
            return self._detections[detection_id]

    def detections_for(self, model_id: Any) -> Tuple[str, ...]:
        with self._lock:
            mid = _check_id(model_id)
            if mid not in self._models:
                raise UnknownModelError(f"unknown model: {mid!r}")
            return tuple(
                sorted(
                    det_id
                    for det_id, rec in self._detections.items()
                    if rec.model_id == mid
                )
            )

    # -- defense ------------------------------------------------------------

    def defend(
        self,
        model_id: Any,
        seq: Any,
        defense: Any,
        strength: Any = "standard",
        detail_digest: Any = "",
    ) -> DefenseRecord:
        """Book one declared defense decision for a model.

        Defenses are repeatable (a defense chain); this books the
        *decision*, never proof the defense is effective.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                mid = _check_id(model_id)
                if mid not in self._models:
                    raise UnknownModelError(f"unknown model: {mid!r}")
                if defense not in DEFENSES:
                    raise BadDefenseError(f"bad defense: {defense!r}")
                if strength not in STRENGTHS:
                    raise BadStrengthError(f"bad strength: {strength!r}")
                d_digest = _check_digest(detail_digest)
                self._defense_seq += 1
                def_id = f"def-{self._defense_seq}"
                record = DefenseRecord(
                    defense_id=def_id,
                    model_id=mid,
                    defense=defense,
                    strength=strength,
                    detail_digest=d_digest,
                    digest=_digest_pin(def_id, mid, defense, strength, d_digest),
                )
                self._defenses[def_id] = record
                self._emit(
                    "defense-applied",
                    {
                        "defense_id": def_id,
                        "model_id": mid,
                        "defense": defense,
                        "strength": strength,
                    },
                )
                return record
            except ModelInversionError:
                self._emit("rejected", {"seq": seq, "op": "defend"})
                raise

    def defense_record(self, defense_id: Any) -> DefenseRecord:
        with self._lock:
            if not isinstance(defense_id, str) or defense_id not in self._defenses:
                raise UnknownModelError(f"unknown defense: {defense_id!r}")
            return self._defenses[defense_id]

    def defenses_for(self, model_id: Any) -> Tuple[str, ...]:
        with self._lock:
            mid = _check_id(model_id)
            if mid not in self._models:
                raise UnknownModelError(f"unknown model: {mid!r}")
            return tuple(
                sorted(
                    def_id
                    for def_id, rec in self._defenses.items()
                    if rec.model_id == mid
                )
            )

    # -- audit --------------------------------------------------------------

    def audit(self, seq: Any, model_id: Any = "") -> AuditReport:
        """Pure-read audit report: verdict/defense tallies, digest-pinned.

        Validates seq shape only - never consumes seq, writes no audit row.
        Empty model_id aggregates every registered model.
        """
        with self._lock:
            _check_seq(seq)
            if model_id == "":
                mids = set(self._models)
                label = ""
            else:
                mid = _check_id(model_id)
                if mid not in self._models:
                    raise UnknownModelError(f"unknown model: {mid!r}")
                mids = {mid}
                label = mid
            verdict_counts = {v: 0 for v in VERDICTS}
            defense_counts = {d: 0 for d in DEFENSES}
            n_det = 0
            n_def = 0
            for rec in self._detections.values():
                if rec.model_id in mids:
                    n_det += 1
                    verdict_counts[rec.verdict] += 1
            for rec in self._defenses.values():
                if rec.model_id in mids:
                    n_def += 1
                    defense_counts[rec.defense] += 1
            report = AuditReport(
                model_id=label,
                detections=n_det,
                verdict_counts=tuple(
                    (v, verdict_counts[v]) for v in VERDICTS
                ),
                defenses=n_def,
                defense_counts=tuple(
                    (d, defense_counts[d]) for d in DEFENSES
                ),
                digest="",
            )
            digest = _digest_pin(
                label,
                n_det,
                [list(row) for row in report.verdict_counts],
                n_def,
                [list(row) for row in report.defense_counts],
            )
            # frozen: rebuild with the digest (no object.__setattr__ needed)
            return AuditReport(
                model_id=label,
                detections=n_det,
                verdict_counts=report.verdict_counts,
                defenses=n_def,
                defense_counts=report.defense_counts,
                digest=digest,
            )

    # -- views --------------------------------------------------------------

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "version": VERSION,
                "schema": SCHEMA,
                "models": len(self._models),
                "detections": len(self._detections),
                "defenses": len(self._defenses),
            }

    def audit_log(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [dict(row) for row in self._audit]


def main() -> None:
    mi = ModelInversion()
    m = mi.register_model("face-classifier", 1, risk_class="critical")
    assert m.verify()
    benign = mi.detect("face-classifier", 2, queries=3, similarity=0.1)
    assert benign.verdict == "benign" and benign.verify()
    suspected = mi.detect("face-classifier", 3, queries=500, similarity=0.2)
    assert suspected.verdict == "suspected" and suspected.verify()
    confirmed = mi.detect("face-classifier", 4, queries=10, similarity=0.95)
    assert confirmed.verdict == "confirmed" and confirmed.verify()
    d = mi.defend("face-classifier", 5, "confidence-truncation", strength="strict")
    assert d.verify()
    rep = mi.audit(6, "face-classifier")
    assert rep.verify() and rep.detections == 3 and rep.defenses == 1
    print("model-inversion OK: register, detect, defend, audit, pins")


if __name__ == "__main__":  # pragma: no cover
    main()
