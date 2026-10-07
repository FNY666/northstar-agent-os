"""DeepfakeDetection: synthetic-media detection decision bookkeeping for agents.

Research note: modern synthetic-media detectors (CNN classifiers,
frequency-domain detectors, audio spoof countermeasures, multimodal
consistency checks) report a *score* for "probability this artifact is
synthetic", and detection deployments book the *decision* (what was
examined, what score was reported, what flag followed). This module is
the *ledger* layer for that practice:

* **analyze()** books one declared media examination: a media id pinned
  to a pinned modality vocabulary (``image`` / ``video`` / ``audio`` /
  ``text``), the artifact itself pinned by digest only. Analysis ids are
  minted (``ana-N``).
* **score()** books one host-declared detection score (``0 <= score <= 1``,
  the reported probability the artifact is synthetic) against a booked
  analysis. The verdict (``authentic`` / ``suspicious`` / ``synthetic``)
  is derived deterministically from pinned thresholds and booked *as
  data*, never as a finding of fact. Score ids are minted (``scr-N``).
* **flag()** books one declared flag decision against a booked analysis
  (``quarantine`` / ``human-review`` / ``label-synthetic`` / ``block`` /
  ``escalate``), forming a flag chain: an analysis may be flagged more
  than once. Flag ids are minted (``flg-N``).

House style throughout: frozen dataclasses, caller-supplied
strictly-increasing int seqs, no wall-clock, RLock guarding, fail-closed
taxonomy, stdlib-only with the standard ``canonical_json`` try/except
fallback, ``sha256:`` digest pins, and ``audit.ndjson/1`` events.

Honest scope: the module is *simulated* -- it books declared analyses,
declared scores, and declared flags; it runs no detector, sees no media
bytes, and cannot prove an artifact is authentic or synthetic. A booked
``synthetic`` verdict means "the host reported a score above the pinned
threshold", never "this media is a deepfake". Raw media bytes, raw
evidence text, and raw justification text never enter records and never
cross the audit boundary (digest pins only).
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
DEEPFAKE_DETECTION_VERSION = "deepfake-detection.v1"

#: Schema pin carried by records and audit events.
DEEPFAKE_DETECTION_SCHEMA = "northstar.deepfake-detection.v1"

#: Wire format of audit records.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Fixed vocabulary for audit event kinds.
KIND_ANALYZED = "deepfake-detection.analyzed"
KIND_SCORED = "deepfake-detection.scored"
KIND_FLAGGED = "deepfake-detection.flagged"
KIND_REJECTED = "deepfake-detection.rejected"
_KINDS = frozenset({KIND_ANALYZED, KIND_SCORED, KIND_FLAGGED, KIND_REJECTED})

#: Pinned media-modality vocabulary for analyses.
MODALITY_IMAGE = "image"
MODALITY_VIDEO = "video"
MODALITY_AUDIO = "audio"
MODALITY_TEXT = "text"
_MODALITIES = frozenset(
    {MODALITY_IMAGE, MODALITY_VIDEO, MODALITY_AUDIO, MODALITY_TEXT}
)

#: Pinned verdict vocabulary derived from a booked score.
VERDICT_AUTHENTIC = "authentic"
VERDICT_SUSPICIOUS = "suspicious"
VERDICT_SYNTHETIC = "synthetic"
_VERDICTS = frozenset({VERDICT_AUTHENTIC, VERDICT_SUSPICIOUS, VERDICT_SYNTHETIC})

#: Pinned flag-decision vocabulary.
FLAG_QUARANTINE = "quarantine"
FLAG_HUMAN_REVIEW = "human-review"
FLAG_LABEL_SYNTHETIC = "label-synthetic"
FLAG_BLOCK = "block"
FLAG_ESCALATE = "escalate"
_FLAGS = frozenset(
    {
        FLAG_QUARANTINE,
        FLAG_HUMAN_REVIEW,
        FLAG_LABEL_SYNTHETIC,
        FLAG_BLOCK,
        FLAG_ESCALATE,
    }
)

#: Score thresholds (host-reported score = P(synthetic)): below LOW is
#: authentic, at or above HIGH is synthetic, between is suspicious.
_THRESHOLD_AUTHENTIC_BELOW = 0.5
_THRESHOLD_SYNTHETIC_AT_OR_ABOVE = 0.8

_MAX_INT = 2**53 - 1
_DIGEST_PREFIX = "sha256:"
_MAX_ID_LEN = 256


# ---------------------------------------------------------------------------
# Error taxonomy (fail-closed)
# ---------------------------------------------------------------------------


class DeepfakeDetectionError(Exception):
    """Base class for all deepfake-detection errors."""


class BadMediaError(DeepfakeDetectionError):
    """media_id is not a usable non-empty str."""


class BadModelError(DeepfakeDetectionError):
    """model_id is not a usable str."""


class BadModalityError(DeepfakeDetectionError):
    """modality is not in the pinned vocabulary."""


class BadDigestError(DeepfakeDetectionError):
    """A digest is not a non-empty sha256:-prefixed str."""


class BadScoreError(DeepfakeDetectionError):
    """score is not a finite float/int in [0, 1] (bool refused)."""


class BadFlagError(DeepfakeDetectionError):
    """flag is not in the pinned vocabulary."""


class DuplicateMediaError(DeepfakeDetectionError):
    """media_id already has a booked analysis."""


class DuplicateAnalysisError(DeepfakeDetectionError):
    """analysis_id is already booked (ids never recycled)."""


class UnknownAnalysisError(DeepfakeDetectionError):
    """analysis_id names no analysis this ledger ever saw."""


class SeqOrderError(DeepfakeDetectionError):
    """seq is not a strictly-increasing int."""


class AuditKindError(DeepfakeDetectionError):
    """Audit kind unknown, or banned detail key used."""


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str, allow_empty: bool = False) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadMediaError(f"{what} must be a str, got {type(value).__name__}")
    if not value and not allow_empty:
        raise BadMediaError(f"{what} must not be empty")
    if len(value) > _MAX_ID_LEN:
        raise BadMediaError(f"{what} too long (>{_MAX_ID_LEN} chars)")
    return value


def _check_model_id(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadModelError(f"model_id must be a str, got {type(value).__name__}")
    if len(value) > _MAX_ID_LEN:
        raise BadModelError(f"model_id too long (>{_MAX_ID_LEN} chars)")
    return value


def _check_modality(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadModalityError(f"modality must be a str, got {type(value).__name__}")
    if value not in _MODALITIES:
        raise BadModalityError(f"modality {value!r} not in pinned vocabulary")
    return value


def _check_flag(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadFlagError(f"flag must be a str, got {type(value).__name__}")
    if value not in _FLAGS:
        raise BadFlagError(f"flag {value!r} not in pinned vocabulary")
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


def _check_score(value: Any) -> float:
    if isinstance(value, bool):
        raise BadScoreError("score must be a number, got bool")
    if isinstance(value, int):
        value = float(value)
    if not isinstance(value, float):
        raise BadScoreError(f"score must be a number, got {type(value).__name__}")
    if value != value or value in (float("inf"), float("-inf")):
        raise BadScoreError("score must be finite")
    if not 0.0 <= value <= 1.0:
        raise BadScoreError(f"score {value!r} outside [0, 1]")
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
        return _cj.jcs_dumps(payload).encode("utf-8")  # type: ignore

    def _tag(v: Any) -> Any:
        if isinstance(v, bool):
            return {"t": "bool", "v": v}
        if isinstance(v, int):
            if abs(v) > _MAX_INT:
                raise DeepfakeDetectionError("integer outside safe range")
            return {"t": "int", "v": v}
        if isinstance(v, float):
            if v != v or v in (float("inf"), float("-inf")):
                raise DeepfakeDetectionError("non-finite float refused")
            return {"t": "float", "v": repr(v)}
        if isinstance(v, str):
            return {"t": "str", "v": v}
        if isinstance(v, (list, tuple)):
            return {"t": "list", "v": [_tag(i) for i in v]}
        if isinstance(v, dict):
            return {"t": "dict", "v": [[k, _tag(v[k])] for k in sorted(v)]}
        if v is None:
            return {"t": "null"}
        raise DeepfakeDetectionError(f"unencodable type: {type(v).__name__}")

    import json

    return json.dumps(_tag(payload), sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest_pin(payload: Any, tag: str) -> str:
    return _DIGEST_PREFIX + hashlib.sha256(
        tag.encode("utf-8") + b"\x1f" + _canonical(payload)
    ).hexdigest()


def _verdict_for(score: float) -> str:
    """Deterministic verdict from a booked score (data, never a finding)."""
    if score >= _THRESHOLD_SYNTHETIC_AT_OR_ABOVE:
        return VERDICT_SYNTHETIC
    if score >= _THRESHOLD_AUTHENTIC_BELOW:
        return VERDICT_SUSPICIOUS
    return VERDICT_AUTHENTIC


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AnalysisRecord:
    """One declared media examination; the artifact is digest-pinned only."""

    analysis_id: str
    media_id: str
    modality: str
    media_digest: str
    model_id: str
    digest: str
    seq: int
    schema: str = DEEPFAKE_DETECTION_SCHEMA

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            (
                self.analysis_id,
                self.media_id,
                self.modality,
                self.media_digest,
                self.model_id,
            ),
            "analysis",
        )


@dataclass(frozen=True)
class ScoreRecord:
    """One host-declared detection score; the verdict is derived data."""

    score_id: str
    analysis_id: str
    score: float
    verdict: str
    detector_digest: str
    digest: str
    seq: int
    schema: str = DEEPFAKE_DETECTION_SCHEMA

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            (
                self.score_id,
                self.analysis_id,
                self.score,
                self.verdict,
                self.detector_digest,
            ),
            "score",
        )


@dataclass(frozen=True)
class FlagRecord:
    """One declared flag decision against a booked analysis (a flag-chain step)."""

    flag_id: str
    analysis_id: str
    flag: str
    reason_digest: str
    digest: str
    seq: int
    schema: str = DEEPFAKE_DETECTION_SCHEMA

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            (
                self.flag_id,
                self.analysis_id,
                self.flag,
                self.reason_digest,
            ),
            "flag",
        )


@dataclass(frozen=True)
class ScoreSummary:
    """Digest-pinned summary of the ledger's synthetic-media posture (pure read view)."""

    total_analyses: int
    total_scores: int
    total_flags: int
    by_verdict: Tuple[Tuple[str, int], ...]
    by_flag: Tuple[Tuple[str, int], ...]
    by_modality: Tuple[Tuple[str, int], ...]
    open_analyses: Tuple[str, ...]
    digest: str
    seq: int
    schema: str = DEEPFAKE_DETECTION_SCHEMA

    def verify(self) -> bool:
        return self.digest == _summary_pin(
            self.total_analyses,
            self.total_scores,
            self.total_flags,
            self.by_verdict,
            self.by_flag,
            self.by_modality,
            self.open_analyses,
        )


def _summary_pin(
    analyses: int,
    scores: int,
    flags: int,
    by_verdict: Tuple[Tuple[str, int], ...],
    by_flag: Tuple[Tuple[str, int], ...],
    by_modality: Tuple[Tuple[str, int], ...],
    open_analyses: Tuple[str, ...],
) -> str:
    return _digest_pin(
        (
            analyses,
            scores,
            flags,
            tuple(sorted(by_verdict)),
            tuple(sorted(by_flag)),
            tuple(sorted(by_modality)),
            tuple(open_analyses),
        ),
        "score-summary",
    )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def deepfake_detection_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
    """Build one audit.ndjson/1 event. Raw media/evidence text never crosses this boundary."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    banned = (
        "media",
        "bytes",
        "pixels",
        "frames",
        "audio",
        "text",
        "content",
        "payload",
        "raw",
        "body",
        "value",
        "message",
        "reason",
        "justification",
        "explanation",
        "evidence",
        "transcript",
    )
    for bad in banned:
        if bad in detail:
            raise AuditKindError(f"audit detail bans {bad!r}")
    _check_seq(seq)
    event = {
        "schema": AUDIT_SCHEMA,
        "module": "deepfake-detection",
        "kind": kind,
        "seq": seq,
        "detail": detail,
    }
    event["digest"] = _digest_pin((kind, seq, tuple(sorted(detail))), "audit-event")
    return event


# ---------------------------------------------------------------------------
# DeepfakeDetection ledger
# ---------------------------------------------------------------------------


class DeepfakeDetection:
    """Synthetic-media detection decision bookkeeping ledger: analyze, score, flag."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        # analysis_id -> AnalysisRecord (ordered)
        self._analyses: Dict[str, AnalysisRecord] = {}
        # media_id -> analysis_id (one active analysis per media id)
        self._media_index: Dict[str, str] = {}
        # score_id -> ScoreRecord (ordered)
        self._scores: Dict[str, ScoreRecord] = {}
        # flag_id -> FlagRecord (ordered)
        self._flags: Dict[str, FlagRecord] = {}
        # analysis_id -> count of flags booked against it
        self._flag_counts: Dict[str, int] = {}
        self._audit_events: List[Dict[str, Any]] = []

    # -- seq discipline ----------------------------------------------------

    def _claim(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError(f"seq {seq} not strictly greater than {self._seq}")
        self._seq = seq
        return seq

    def _emit(self, audit_kind: str, seq: int, **detail: Any) -> None:
        self._audit_events.append(deepfake_detection_audit_event(audit_kind, seq, **detail))

    def _fail(self, seq: int, exc: DeepfakeDetectionError, **detail: Any) -> None:
        self._emit(KIND_REJECTED, seq, error=type(exc).__name__, **detail)
        raise exc

    # -- mutations ----------------------------------------------------------

    def analyze(
        self,
        media_id: str,
        seq: int,
        media_digest: str = "",
        modality: str = MODALITY_VIDEO,
        model_id: str = "",
    ) -> AnalysisRecord:
        """Book a declared media examination. The artifact is pinned by digest only."""
        with self._lock:
            seq = self._claim(seq)
            try:
                media_id = _check_id(media_id, "media_id")
                modality = _check_modality(modality)
                media_digest = _check_digest(media_digest, "media_digest", allow_empty=True)
                model_id = _check_model_id(model_id)
            except DeepfakeDetectionError as exc:
                self._fail(seq, exc, media_id=str(media_id))
            if media_id in self._media_index:
                self._fail(
                    seq,
                    DuplicateMediaError(f"media already analyzed: {media_id!r}"),
                    media_id=media_id,
                )
            analysis_id = f"ana-{len(self._analyses) + 1}"
            record = AnalysisRecord(
                analysis_id=analysis_id,
                media_id=media_id,
                modality=modality,
                media_digest=media_digest,
                model_id=model_id,
                digest=_digest_pin(
                    (analysis_id, media_id, modality, media_digest, model_id),
                    "analysis",
                ),
                seq=seq,
            )
            self._analyses[analysis_id] = record
            self._media_index[media_id] = analysis_id
            self._flag_counts[analysis_id] = 0
            self._emit(
                KIND_ANALYZED,
                seq,
                analysis_id=analysis_id,
                media_id=media_id,
                modality=modality,
                media_digest=media_digest,
                model_id=model_id,
                record_digest=record.digest,
            )
            return record

    def score(
        self,
        analysis_id: str,
        seq: int,
        score: float,
        detector_digest: str = "",
    ) -> ScoreRecord:
        """Book a host-declared detection score against a booked analysis.

        The verdict (authentic/suspicious/synthetic) is derived
        deterministically from pinned thresholds and booked as data.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                analysis_id = _check_id(analysis_id, "analysis_id")
                score = _check_score(score)
                detector_digest = _check_digest(
                    detector_digest, "detector_digest", allow_empty=True
                )
            except DeepfakeDetectionError as exc:
                self._fail(seq, exc, analysis_id=str(analysis_id))
            if analysis_id not in self._analyses:
                self._fail(
                    seq,
                    UnknownAnalysisError(f"unknown analysis: {analysis_id!r}"),
                    analysis_id=analysis_id,
                )
            verdict = _verdict_for(score)
            score_id = f"scr-{len(self._scores) + 1}"
            record = ScoreRecord(
                score_id=score_id,
                analysis_id=analysis_id,
                score=score,
                verdict=verdict,
                detector_digest=detector_digest,
                digest=_digest_pin(
                    (score_id, analysis_id, score, verdict, detector_digest),
                    "score",
                ),
                seq=seq,
            )
            self._scores[score_id] = record
            self._emit(
                KIND_SCORED,
                seq,
                analysis_id=analysis_id,
                score_id=score_id,
                score=score,
                verdict=verdict,
                detector_digest=detector_digest,
                record_digest=record.digest,
            )
            return record

    def flag(
        self,
        analysis_id: str,
        seq: int,
        flag: str,
        reason_digest: str = "",
    ) -> FlagRecord:
        """Book a declared flag decision against a booked analysis.

        An analysis may be flagged more than once (a flag chain); each
        decision is a new ``FlagRecord``.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                analysis_id = _check_id(analysis_id, "analysis_id")
                flag = _check_flag(flag)
                reason_digest = _check_digest(
                    reason_digest, "reason_digest", allow_empty=True
                )
            except DeepfakeDetectionError as exc:
                self._fail(seq, exc, analysis_id=str(analysis_id))
            if analysis_id not in self._analyses:
                self._fail(
                    seq,
                    UnknownAnalysisError(f"unknown analysis: {analysis_id!r}"),
                    analysis_id=analysis_id,
                )
            flag_id = f"flg-{len(self._flags) + 1}"
            record = FlagRecord(
                flag_id=flag_id,
                analysis_id=analysis_id,
                flag=flag,
                reason_digest=reason_digest,
                digest=_digest_pin(
                    (flag_id, analysis_id, flag, reason_digest),
                    "flag",
                ),
                seq=seq,
            )
            self._flags[flag_id] = record
            self._flag_counts[analysis_id] += 1
            self._emit(
                KIND_FLAGGED,
                seq,
                analysis_id=analysis_id,
                flag_id=flag_id,
                flag=flag,
                reason_digest=reason_digest,
                record_digest=record.digest,
            )
            return record

    # -- pure read views ----------------------------------------------------

    def analysis(self, analysis_id: str, seq: int) -> Optional[AnalysisRecord]:
        """Pure read: the booked analysis record, or None."""
        _check_seq(seq)
        with self._lock:
            return self._analyses.get(analysis_id)

    def analysis_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read: ids of booked analyses, in booking order."""
        _check_seq(seq)
        with self._lock:
            return tuple(self._analyses)

    def scores_for(self, analysis_id: str, seq: int) -> Tuple[ScoreRecord, ...]:
        """Pure read: score records booked for an analysis, in seq order."""
        _check_seq(seq)
        with self._lock:
            return tuple(s for s in self._scores.values() if s.analysis_id == analysis_id)

    def flags_for(self, analysis_id: str, seq: int) -> Tuple[FlagRecord, ...]:
        """Pure read: flag decisions booked for an analysis, in seq order."""
        _check_seq(seq)
        with self._lock:
            return tuple(f for f in self._flags.values() if f.analysis_id == analysis_id)

    def is_flagged(self, analysis_id: str, seq: int) -> bool:
        """Pure read: whether a booked analysis has at least one flag."""
        _check_seq(seq)
        with self._lock:
            if analysis_id not in self._analyses:
                raise UnknownAnalysisError(f"unknown analysis: {analysis_id!r}")
            return self._flag_counts.get(analysis_id, 0) > 0

    def summary(self, seq: int) -> ScoreSummary:
        """Pure read: digest-pinned posture summary. Consumes no seq, books no rows."""
        _check_seq(seq)
        with self._lock:
            by_verdict: Dict[str, int] = {}
            for s in self._scores.values():
                by_verdict[s.verdict] = by_verdict.get(s.verdict, 0) + 1
            by_flag: Dict[str, int] = {}
            for f in self._flags.values():
                by_flag[f.flag] = by_flag.get(f.flag, 0) + 1
            by_modality: Dict[str, int] = {}
            for a in self._analyses.values():
                by_modality[a.modality] = by_modality.get(a.modality, 0) + 1
            open_ids = tuple(
                a_id
                for a_id in self._analyses
                if self._flag_counts.get(a_id, 0) == 0
            )
            report = ScoreSummary(
                total_analyses=len(self._analyses),
                total_scores=len(self._scores),
                total_flags=len(self._flags),
                by_verdict=tuple(sorted(by_verdict.items())),
                by_flag=tuple(sorted(by_flag.items())),
                by_modality=tuple(sorted(by_modality.items())),
                open_analyses=open_ids,
                digest=_summary_pin(
                    len(self._analyses),
                    len(self._scores),
                    len(self._flags),
                    tuple(sorted(by_verdict.items())),
                    tuple(sorted(by_flag.items())),
                    tuple(sorted(by_modality.items())),
                    open_ids,
                ),
                seq=seq,
            )
            return report

    def stats(self, seq: int) -> Dict[str, Any]:
        """Pure read: ledger counters."""
        _check_seq(seq)
        with self._lock:
            return {
                "analyses": len(self._analyses),
                "scores": len(self._scores),
                "flags": len(self._flags),
                "open": sum(
                    1 for a in self._analyses if self._flag_counts.get(a, 0) == 0
                ),
                "last_seq": self._seq,
            }

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        """All audit events booked so far."""
        with self._lock:
            return tuple(self._audit_events)


def main() -> None:
    """Self-check: analyze, score, flag, summary."""
    ledger = DeepfakeDetection()
    ana = ledger.analyze(
        "media-1",
        1,
        media_digest="sha256:" + "a" * 64,
        modality="video",
        model_id="detector-x1",
    )
    assert ana.verify()
    assert ana.analysis_id == "ana-1"
    scr = ledger.score(ana.analysis_id, 2, 0.92, detector_digest="sha256:" + "b" * 64)
    assert scr.verify()
    assert scr.score_id == "scr-1"
    assert scr.verdict == "synthetic"
    flg = ledger.flag(
        ana.analysis_id, 3, "quarantine", reason_digest="sha256:" + "c" * 64
    )
    assert flg.verify()
    assert flg.flag_id == "flg-1"
    # a flag chain: a second flag on the same analysis is allowed
    flg2 = ledger.flag(ana.analysis_id, 4, "human-review")
    assert flg2.verify() and flg2.flag_id == "flg-2"
    assert ledger.is_flagged(ana.analysis_id, 4)
    ana2 = ledger.analyze("media-2", 5, modality="audio")
    assert ana2.verify()
    scr2 = ledger.score(ana2.analysis_id, 6, 0.2)
    assert scr2.verdict == "authentic"
    scr3 = ledger.score(ana2.analysis_id, 7, 0.6)
    assert scr3.verdict == "suspicious"
    summary = ledger.summary(7)
    assert summary.verify()
    assert summary.total_analyses == 2
    assert summary.total_scores == 3
    assert summary.total_flags == 2
    assert summary.open_analyses == ("ana-2",)
    assert ledger.stats(7)["open"] == 1
    print("deepfake-detection OK: analyze, score, flag, summary, pins, audit")


if __name__ == "__main__":
    main()
