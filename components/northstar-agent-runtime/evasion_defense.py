"""Evasion-attack defense decision ledger.

Detect -> respond -> harden lifecycle for evasion attacks (FGSM / PGD /
CW / DeepFool-shaped) as a deterministic single-host state machine. The
module books *declared* defense decisions over *host-reported* suspicion
scores; it never sees an input, a model, or an attack, and never proves
an input was truly adversarial or truly benign.

Distinct-layer rationale: `evasion_corpus` owns the held-out evasion
corpus, `adversarial_detector` owns statistical input tripwires, and
`robustness_testing` owns robustness-test harnesses. This module owns the
defense *lifecycle ledger*: a detection verdict booked as data, the
declared response to it, and declared hardening of a model afterwards.

House style:
  - frozen dataclasses, caller int seqs strictly increasing (no wall-clock)
  - RLock-guarded, fail-closed, stdlib-only
  - `sha256:` digest pins with `verify()`
  - `audit.ndjson/1` events; raw inputs stay out of the audit boundary
  - failed mutations consume their seq (claim-then-burn) and book
    `evasion-defense.rejected`; rewinds raise bare without consuming

Honest scope: a booked verdict of `malicious` means "the host reported a
suspicion score >= threshold", never proof of an evasion attempt; a
booked `blocked` response means the host declared it blocked the query,
never that an attack was stopped. Verdicts are score arithmetic; GIGO
scores in, ledger truth out.
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

VERSION = "evasion-defense.v1"
SCHEMA = "northstar.evasion-defense.v1"

#: Pinned attack-technique vocabulary.
TECHNIQUES = ("fgsm", "pgd", "cw", "bim", "deepfool", "autoattack", "unrestricted")

#: Pinned response-action vocabulary.
ACTIONS = ("allow", "flag", "block", "sanitize", "re-authenticate", "escalate")

#: Pinned hardening-defense vocabulary.
DEFENSES = (
    "adversarial-training",
    "gradient-masking",
    "input-sanitization",
    "certified-defense",
    "ensemble",
    "randomized-smoothing",
)

#: Pinned verdict vocabulary derived from the suspicion score.
VERDICTS = ("clean", "suspicious", "malicious")

#: Score thresholds: < SUSPICIOUS_THRESHOLD -> clean;
#: < MALICIOUS_THRESHOLD -> suspicious; else malicious. Pinned.
SUSPICIOUS_THRESHOLD = 0.5
MALICIOUS_THRESHOLD = 0.8

_HASH_DOMAIN = b"northstar.evasion-defense.v1\x00"


# ---------------------------------------------------------------------------
# errors
# ---------------------------------------------------------------------------

class EvasionDefenseError(Exception):
    """Base."""


class BadIdError(EvasionDefenseError):
    pass


class DuplicateQueryError(EvasionDefenseError):
    pass


class UnknownQueryError(EvasionDefenseError):
    pass


class BadScoreError(EvasionDefenseError):
    pass


class BadTechniqueError(EvasionDefenseError):
    pass


class BadActionError(EvasionDefenseError):
    pass


class BadDefenseError(EvasionDefenseError):
    pass


class UnknownDetectionError(EvasionDefenseError):
    pass


class DuplicateResponseError(EvasionDefenseError):
    pass


class DuplicateModelError(EvasionDefenseError):
    pass


class BadDigestError(EvasionDefenseError):
    pass


class SeqOrderError(EvasionDefenseError):
    pass


class AuditKindError(EvasionDefenseError):
    pass


# ---------------------------------------------------------------------------
# audit
# ---------------------------------------------------------------------------

_AUDIT_KINDS = (
    "detection-booked",
    "response-booked",
    "hardening-booked",
    "rejected",
)


def evasion_defense_audit_event(
    audit_kind: str, detail: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    if audit_kind not in _AUDIT_KINDS:
        raise AuditKindError(f"bad audit kind: {audit_kind!r}")
    return {
        "kind": audit_kind,
        "detail": dict(detail or {}),
        "schema": "audit.ndjson/1",
    }


_BANNED_AUDIT_KEYS = (
    "input", "text", "content", "message", "payload", "raw", "value",
    "secret", "plaintext", "features", "vector", "candidate", "bytes",
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
        raise BadIdError(f"bad id: {value!r}")
    if len(value) > 128:
        raise BadIdError("id too long")
    return value


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError(f"bad seq: {seq!r}")
    return seq


def _check_score(value: Any) -> float:
    # host-reported suspicion score in [0, 1]; bool/NaN/inf refused
    if isinstance(value, bool):
        raise BadScoreError(f"bool is not a score: {value!r}")
    if isinstance(value, int):
        value = float(value)
    if not isinstance(value, float) or not math.isfinite(value):
        raise BadScoreError(f"bad score: {value!r}")
    if not 0.0 <= value <= 1.0:
        raise BadScoreError(f"score out of [0, 1]: {value!r}")
    return value


def _check_technique(value: Any) -> str:
    if value == "":
        return value
    if not isinstance(value, str) or value not in TECHNIQUES:
        raise BadTechniqueError(f"bad technique: {value!r}")
    return value


def _check_action(value: Any) -> str:
    if not isinstance(value, str) or value not in ACTIONS:
        raise BadActionError(f"bad action: {value!r}")
    return value


def _check_defense(value: Any) -> str:
    if not isinstance(value, str) or value not in DEFENSES:
        raise BadDefenseError(f"bad defense: {value!r}")
    return value


def _check_digest(value: Any) -> str:
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


def _digest_pin(*parts: Any) -> str:
    blob = jcs_dumps(list(parts))
    if isinstance(blob, str):
        blob = blob.encode("utf-8")
    return "sha256:" + hashlib.sha256(blob).hexdigest()


def _verdict_for(score: float) -> str:
    if score < SUSPICIOUS_THRESHOLD:
        return "clean"
    if score < MALICIOUS_THRESHOLD:
        return "suspicious"
    return "malicious"


# ---------------------------------------------------------------------------
# frozen records
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DetectionRecord:
    detection_id: str
    query_id: str
    technique: str
    score_num: int  # scaled by 1000, exact integer bookkeeping
    score_den: int
    verdict: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            self.detection_id, self.query_id, self.technique,
            self.score_num, self.score_den, self.verdict,
        )

    @property
    def score(self) -> float:
        return self.score_num / self.score_den


@dataclass(frozen=True)
class ResponseRecord:
    response_id: str
    detection_id: str
    action: str
    reason_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            self.response_id, self.detection_id, self.action, self.reason_digest
        )


@dataclass(frozen=True)
class HardenRecord:
    harden_id: str
    model_id: str
    defense: str
    coverage_digest: str
    digest: str

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            self.harden_id, self.model_id, self.defense, self.coverage_digest
        )


# ---------------------------------------------------------------------------
# ledger
# ---------------------------------------------------------------------------

class EvasionDefense:
    """Evasion-attack defense lifecycle ledger."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._queries: Dict[str, bool] = {}  # query_id -> seen
        self._detections: Dict[str, DetectionRecord] = {}
        self._responses: Dict[str, ResponseRecord] = {}
        self._responded: Dict[str, bool] = {}  # detection_id -> responded
        self._models: Dict[str, bool] = {}  # model_id -> seen
        self._hardenings: Dict[str, HardenRecord] = {}
        self._last_seq: int = -1
        self._detection_seq = 0
        self._response_seq = 0
        self._harden_seq = 0
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
        self._audit.append(evasion_defense_audit_event(audit_kind, detail))

    # -- detect --------------------------------------------------------------

    def detect(
        self,
        query_id: Any,
        score: Any,
        seq: Any,
        technique: Any = "",
        query_digest: Any = "",
    ) -> DetectionRecord:
        """Book one declared evasion-detection decision.

        The score is host-reported and booked as data; the verdict is
        derived deterministically from the pinned thresholds. Duplicate
        query ids are refused fail-closed.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                qid = _check_id(query_id)
                if qid in self._queries:
                    raise DuplicateQueryError(f"query already seen: {qid!r}")
                s = _check_score(score)
                tech = _check_technique(technique)
                q_digest = _check_digest(query_digest)
                verdict = _verdict_for(s)
                s_num = round(s * 1000)
                s_den = 1000
                self._detection_seq += 1
                det_id = f"det-{self._detection_seq}"
                record = DetectionRecord(
                    detection_id=det_id,
                    query_id=qid,
                    technique=tech,
                    score_num=s_num,
                    score_den=s_den,
                    verdict=verdict,
                    digest=_digest_pin(det_id, qid, tech, s_num, s_den, verdict),
                )
                self._queries[qid] = True
                self._detections[det_id] = record
                self._emit(
                    "detection-booked",
                    {
                        "detection_id": det_id,
                        "query_id": qid,
                        "verdict": verdict,
                        "query_digest": q_digest,
                    },
                )
                return record
            except EvasionDefenseError:
                self._emit("rejected", {"seq": seq, "op": "detect"})
                raise

    def detection_record(self, detection_id: Any) -> DetectionRecord:
        with self._lock:
            if not isinstance(detection_id, str) or detection_id not in self._detections:
                raise UnknownDetectionError(f"unknown detection: {detection_id!r}")
            return self._detections[detection_id]

    def detection_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._detections))

    # -- respond -------------------------------------------------------------

    def respond(
        self,
        detection_id: Any,
        action: Any,
        seq: Any,
        reason_digest: Any = "",
    ) -> ResponseRecord:
        """Book one declared response to a detection.

        One response per detection: a second response to the same
        detection is refused fail-closed. The action is the host's
        declared handling, never proof it was executed.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                did = _check_id(detection_id)
                if did not in self._detections:
                    raise UnknownDetectionError(f"unknown detection: {did!r}")
                if did in self._responded:
                    raise DuplicateResponseError(
                        f"detection already responded: {did!r}"
                    )
                act = _check_action(action)
                r_digest = _check_digest(reason_digest)
                self._response_seq += 1
                rsp_id = f"rsp-{self._response_seq}"
                record = ResponseRecord(
                    response_id=rsp_id,
                    detection_id=did,
                    action=act,
                    reason_digest=r_digest,
                    digest=_digest_pin(rsp_id, did, act, r_digest),
                )
                self._responded[did] = True
                self._responses[rsp_id] = record
                self._emit(
                    "response-booked",
                    {
                        "response_id": rsp_id,
                        "detection_id": did,
                        "action": act,
                    },
                )
                return record
            except EvasionDefenseError:
                self._emit("rejected", {"seq": seq, "op": "respond"})
                raise

    def response_record(self, response_id: Any) -> ResponseRecord:
        with self._lock:
            if not isinstance(response_id, str) or response_id not in self._responses:
                raise UnknownDetectionError(f"unknown response: {response_id!r}")
            return self._responses[response_id]

    def response_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._responses))

    # -- harden ---------------------------------------------------------------

    def harden(
        self,
        model_id: Any,
        defense: Any,
        seq: Any,
        coverage_digest: Any = "",
    ) -> HardenRecord:
        """Book one declared model-hardening event.

        A model id may be hardened multiple times (defense-in-depth is
        cumulative), but duplicate (model_id, defense) pairs are refused
        fail-closed.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                mid = _check_id(model_id)
                dfn = _check_defense(defense)
                c_digest = _check_digest(coverage_digest)
                if mid not in self._models:
                    self._models[mid] = True
                for rec in self._hardenings.values():
                    if rec.model_id == mid and rec.defense == dfn:
                        raise DuplicateModelError(
                            f"defense already booked for {mid!r}: {dfn!r}"
                        )
                self._harden_seq += 1
                hdn_id = f"hdn-{self._harden_seq}"
                record = HardenRecord(
                    harden_id=hdn_id,
                    model_id=mid,
                    defense=dfn,
                    coverage_digest=c_digest,
                    digest=_digest_pin(hdn_id, mid, dfn, c_digest),
                )
                self._hardenings[hdn_id] = record
                self._emit(
                    "hardening-booked",
                    {
                        "harden_id": hdn_id,
                        "model_id": mid,
                        "defense": dfn,
                    },
                )
                return record
            except EvasionDefenseError:
                self._emit("rejected", {"seq": seq, "op": "harden"})
                raise

    def harden_record(self, harden_id: Any) -> HardenRecord:
        with self._lock:
            if not isinstance(harden_id, str) or harden_id not in self._hardenings:
                raise UnknownDetectionError(f"unknown hardening: {harden_id!r}")
            return self._hardenings[harden_id]

    def harden_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._hardenings))

    # -- views ----------------------------------------------------------------

    def verdicts_for(self, query_id: Any) -> Tuple[DetectionRecord, ...]:
        """Pure read: all detections booked for a query."""
        with self._lock:
            qid = _check_id(query_id)
            return tuple(
                sorted(
                    (r for r in self._detections.values() if r.query_id == qid),
                    key=lambda r: r.detection_id,
                )
            )

    def defenses_for(self, model_id: Any) -> Tuple[HardenRecord, ...]:
        """Pure read: all hardenings booked for a model."""
        with self._lock:
            mid = _check_id(model_id)
            return tuple(
                sorted(
                    (r for r in self._hardenings.values() if r.model_id == mid),
                    key=lambda r: r.harden_id,
                )
            )

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            verdict_counts = {v: 0 for v in VERDICTS}
            for r in self._detections.values():
                verdict_counts[r.verdict] += 1
            return {
                "version": VERSION,
                "schema": SCHEMA,
                "queries": len(self._queries),
                "detections": len(self._detections),
                "verdicts": verdict_counts,
                "responses": len(self._responses),
                "models": len(self._models),
                "hardenings": len(self._hardenings),
            }

    def audit_log(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [dict(row) for row in self._audit]


def main() -> None:
    ed = EvasionDefense()
    det = ed.detect("q-1", 0.92, 1, technique="pgd")
    assert det.verify()
    assert det.verdict == "malicious"
    assert det.score_num == 920 and det.score_den == 1000
    rsp = ed.respond("det-1", "block", 2)
    assert rsp.verify()
    assert rsp.action == "block"
    hdn = ed.harden("m-1", "adversarial-training", 3)
    assert hdn.verify()
    assert ed.stats()["verdicts"]["malicious"] == 1
    print("evasion-defense OK: detect, respond, harden, pins, audit")


if __name__ == "__main__":  # pragma: no cover
    main()
