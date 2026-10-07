"""RobustWatermark: robustness-under-transformation watermark bookkeeping for agents.

Research note: watermarking for AI-generated content splits into *fragile*
and *robust* families (Cox et al. 2007, "Digital Watermarking and
Steganography"; Kirchenbauer et al. 2023 "A Watermark for Large Language
Models"; SynthID-style approaches; C2PA for media provenance). A fragile
watermark breaks on any edit (good for tamper evidence); a *robust*
watermark is designed to **survive** common transformations - paraphrase,
cropping, compression, translation, summarization - so provenance can be
recovered after downstream handling.

This module is the *ledger* layer for that practice, deliberately distinct
from the sibling layers:

* ``model_watermark.py``      - model-side embedding primitive
* ``watermark_verifier.py``   - HMAC zero-width channel verifier (fragile-by-design)
* ``watermark_tracker.py``    - watermark lifecycle tracking
* ``robust_watermark.py``     - THIS module: declared embedding decisions +
  declared robustness trials (embed / survive / extract)

API:

* **embed()** books one declared watermark-embedding decision: which channel
  was chosen (pinned vocabulary ``lexical-redundancy`` / ``syntactic-variation``
  / ``statistical-bias`` / ``semantic-paraphrase``), which content it covers
  (digest pin only - raw content never enters a record), and the declared
  robustness level (``fragile`` / ``medium`` / ``strong``). Embed ids are
  minted (``emb-N``).
* **survive()** books one declared robustness trial: a pinned transform
  (``paraphrase`` / ``crop`` / ``compress`` / ``translate`` / ``summarize`` /
  ``noise-inject`` / ``reformat``) at a declared severity in [0,1] was
  applied to the watermarked content, and the watermark *survived* or did
  not - booked **as data**, never raised. Trial ids are minted (``tr-N``).
* **extract()** is a *pure read* view: the digest-pinned payload summary for
  an embedded watermark - payload digest, channel, robustness level, and the
  aggregate survival outcome. It validates seq shape, consumes nothing, and
  books no audit rows.

House style throughout: frozen dataclasses, caller-supplied
strictly-increasing int seqs (claim-then-burn: failed mutations consume
their seq and book a ``rejected`` row; rewinds raise bare without
consuming), no wall-clock, RLock guarding, fail-closed taxonomy,
stdlib-only with the standard ``canonical_json`` try/except fallback,
``sha256:`` digest pins, and ``audit.ndjson/1`` events.

Honest scope: the module books *declared* embedding decisions and *declared*
trial outcomes; it runs no real watermark channel, embeds nothing in actual
content, and cannot prove a watermark would survive a real transform.
Host-reported ``survived`` values are GIGO. Raw content/payload text never
enters records and never crosses the audit boundary (digest pins only).
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from fractions import Fraction
from typing import Any, Dict, List, Optional, Tuple

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    _cj = None  # type: ignore

#: Version pin for this module's record shape.
ROBUST_WATERMARK_VERSION = "robust-watermark.v1"

#: Schema pin carried by records and audit events.
ROBUST_WATERMARK_SCHEMA = "northstar.robust-watermark.v1"

#: Wire format of audit records.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Pinned embedding-channel vocabulary.
CHANNELS = (
    "lexical-redundancy",
    "syntactic-variation",
    "statistical-bias",
    "semantic-paraphrase",
)

#: Declared robustness levels.
ROBUSTNESS_LEVELS = ("fragile", "medium", "strong")

#: Pinned transform vocabulary for robustness trials.
TRANSFORMS = (
    "paraphrase",
    "crop",
    "compress",
    "translate",
    "summarize",
    "noise-inject",
    "reformat",
)

#: Audit kinds for this module (append-only vocabulary).
KIND_EMBEDDED = "watermark-embedded"
KIND_TRIAL = "robustness-trial"
KIND_REJECTED = "robust-watermark.rejected"
_KINDS = (KIND_EMBEDDED, KIND_TRIAL, KIND_REJECTED)


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class RobustWatermarkError(Exception):
    """Base class for all robust-watermark failures."""


class BadEmbedError(RobustWatermarkError):
    """Malformed embed id or embedding parameter."""


class DuplicateEmbedError(RobustWatermarkError):
    """An embedding with this id (or caller-chosen id) already exists."""


class UnknownEmbedError(RobustWatermarkError):
    """No embedding with this id is known."""


class RetiredEmbedError(RobustWatermarkError):
    """The embedding id was retired and may never be reused."""


class BadChannelError(RobustWatermarkError):
    """Embedding channel not in the pinned CHANNELS vocabulary."""


class BadRobustnessError(RobustWatermarkError):
    """Robustness level not in the pinned ROBUSTNESS_LEVELS vocabulary."""


class BadTransformError(RobustWatermarkError):
    """Transform not in the pinned TRANSFORMS vocabulary."""


class BadSeverityError(RobustWatermarkError):
    """Severity is not a finite float in [0, 1]."""


class BadDigestError(RobustWatermarkError):
    """A digest pin is not a ``sha256:<64hex>`` pin (or is empty)."""


class SeqOrderError(RobustWatermarkError):
    """Seq is not a strictly increasing int."""


class AuditKindError(RobustWatermarkError):
    """Unknown audit kind, or banned raw-text key in audit detail."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"seq must be int, got {type(seq).__name__}")
    if seq <= 0:
        raise SeqOrderError(f"seq must be positive, got {seq}")
    return seq


def _check_id(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise BadEmbedError(f"{name} must be a non-empty str (<=128 chars)")
    if value != value.strip() or any(c.isspace() for c in value):
        raise BadEmbedError(f"{name} must not contain whitespace")
    return value


def _check_digest(value: Any, name: str, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise BadDigestError(f"{name} must be str, got {type(value).__name__}")
    if allow_empty and value == "":
        return ""
    if not value.startswith("sha256:") or len(value) != len("sha256:") + 64:
        raise BadDigestError(f"{name} must be 'sha256:' + 64 hex chars")
    try:
        int(value[7:], 16)
    except ValueError:
        raise BadDigestError(f"{name} hex part is not hex") from None
    return value


def _check_channel(channel: Any) -> str:
    if not isinstance(channel, str) or channel not in CHANNELS:
        raise BadChannelError(f"channel must be one of {CHANNELS}, got {channel!r}")
    return channel


def _check_robustness(level: Any) -> str:
    if not isinstance(level, str) or level not in ROBUSTNESS_LEVELS:
        raise BadRobustnessError(
            f"robustness must be one of {ROBUSTNESS_LEVELS}, got {level!r}"
        )
    return level


def _check_transform(transform: Any) -> str:
    if not isinstance(transform, str) or transform not in TRANSFORMS:
        raise BadTransformError(f"transform must be one of {TRANSFORMS}, got {transform!r}")
    return transform


def _check_severity(severity: Any) -> float:
    if isinstance(severity, bool):
        raise BadSeverityError("severity must not be bool")
    if not isinstance(severity, (int, float)):
        raise BadSeverityError(f"severity must be a number, got {type(severity).__name__}")
    value = float(severity)
    if not (0.0 <= value <= 1.0) or value != value:  # NaN fails the range too
        raise BadSeverityError(f"severity must be finite in [0, 1], got {severity!r}")
    return value


def _check_survived(survived: Any) -> bool:
    if not isinstance(survived, bool):
        raise RobustWatermarkError(
            f"survived must be bool, got {type(survived).__name__}"
        )
    return survived


# ---------------------------------------------------------------------------
# Digest pins
# ---------------------------------------------------------------------------


def _canonical(obj: Any) -> bytes:
    if _cj is not None:
        return _cj.jcs_dumps(obj).encode("utf-8")
    import json

    def _norm(value: Any) -> Any:
        if isinstance(value, bool):
            return {"__bool__": value}
        if isinstance(value, float):
            if value != value or value in (float("inf"), float("-inf")):
                raise ValueError("non-finite float not canonicalizable")
            return {"__float__": repr(value)}
        if isinstance(value, int):
            return {"__int__": str(value)}
        if isinstance(value, (list, tuple)):
            return [_norm(v) for v in value]
        if isinstance(value, dict):
            return {str(k): _norm(value[k]) for k in sorted(value)}
        if value is None:
            return None
        return str(value)

    return json.dumps(_norm(obj), separators=(",", ":"), sort_keys=True).encode("utf-8")


def _digest_pin(parts: Tuple[Any, ...], domain: str) -> str:
    h = hashlib.sha256()
    h.update(b"northstar.robust-watermark:")
    h.update(domain.encode("utf-8"))
    h.update(b":")
    h.update(_canonical(parts))
    return "sha256:" + h.hexdigest()


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EmbedRecord:
    """One declared watermark-embedding decision."""

    embed_id: str
    channel: str
    robustness: str
    content_digest: str
    payload_digest: str
    digest: str
    schema: str = ROBUST_WATERMARK_SCHEMA
    version: str = ROBUST_WATERMARK_VERSION

    def verify(self) -> bool:
        """Recompute the digest pin; False means the record was tampered with."""
        return self.digest == _digest_pin(
            (self.embed_id, self.channel, self.robustness,
             self.content_digest, self.payload_digest),
            "embed",
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "version": self.version,
            "embed_id": self.embed_id,
            "channel": self.channel,
            "robustness": self.robustness,
            "content_digest": self.content_digest,
            "payload_digest": self.payload_digest,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class TrialRecord:
    """One declared robustness trial against a booked embedding."""

    trial_id: str
    embed_id: str
    transform: str
    severity: float
    survived: bool
    digest: str
    schema: str = ROBUST_WATERMARK_SCHEMA
    version: str = ROBUST_WATERMARK_VERSION

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            (self.trial_id, self.embed_id, self.transform,
             repr(self.severity), self.survived),
            "trial",
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "version": self.version,
            "trial_id": self.trial_id,
            "embed_id": self.embed_id,
            "transform": self.transform,
            "severity": self.severity,
            "survived": self.survived,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class ExtractionReport:
    """Pure-read extraction summary for one embedding."""

    embed_id: str
    channel: str
    robustness: str
    payload_digest: str
    trials: int
    survived_trials: int
    survival_rate_text: str
    digest: str
    schema: str = ROBUST_WATERMARK_SCHEMA
    version: str = ROBUST_WATERMARK_VERSION

    def verify(self) -> bool:
        return self.digest == _digest_pin(
            (self.embed_id, self.channel, self.robustness, self.payload_digest,
             self.trials, self.survived_trials, self.survival_rate_text),
            "extract",
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "version": self.version,
            "embed_id": self.embed_id,
            "channel": self.channel,
            "robustness": self.robustness,
            "payload_digest": self.payload_digest,
            "trials": self.trials,
            "survived_trials": self.survived_trials,
            "survival_rate_text": self.survival_rate_text,
            "digest": self.digest,
        }


def _survival_rate_text(trials: int, survived: int) -> str:
    if trials == 0:
        return "0/1"
    frac = Fraction(survived, trials)
    return f"{frac.numerator}/{frac.denominator}"


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def robust_watermark_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
    """Build one audit.ndjson/1 event. Raw content never crosses this boundary."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    banned = (
        "content",
        "payload",
        "text",
        "raw",
        "body",
        "value",
        "message",
        "reason",
        "note",
        "notes",
        "comment",
        "data",
    )
    for bad in banned:
        if bad in detail:
            raise AuditKindError(f"audit detail bans {bad!r}")
    _check_seq(seq)
    event = {
        "schema": AUDIT_SCHEMA,
        "module": "robust-watermark",
        "kind": kind,
        "seq": seq,
        "detail": detail,
    }
    event["digest"] = _digest_pin((kind, seq, tuple(sorted(detail))), "audit-event")
    return event


# ---------------------------------------------------------------------------
# RobustWatermark ledger
# ---------------------------------------------------------------------------


class RobustWatermark:
    """Robust watermark embedding / robustness-trial bookkeeping ledger."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        # embed_id -> EmbedRecord (ordered)
        self._embeds: Dict[str, EmbedRecord] = {}
        # trial_id -> TrialRecord (ordered)
        self._trials: Dict[str, TrialRecord] = {}
        # embed_id -> list of trial ids, in booking order
        self._trials_for: Dict[str, List[str]] = {}
        self._audit_events: List[Dict[str, Any]] = []

    # -- seq discipline ----------------------------------------------------

    def _claim(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError(f"seq {seq} not strictly greater than {self._seq}")
        self._seq = seq
        return seq

    def _emit(self, audit_kind: str, seq: int, **detail: Any) -> None:
        self._audit_events.append(
            robust_watermark_audit_event(audit_kind, seq, **detail)
        )

    def _fail(self, seq: int, exc: RobustWatermarkError, **detail: Any) -> None:
        self._emit(KIND_REJECTED, seq, error=type(exc).__name__, **detail)
        raise exc

    # -- mutations ----------------------------------------------------------

    def embed(
        self,
        content_digest: str,
        channel: str,
        seq: int,
        robustness: str = "medium",
        payload_digest: str = "",
    ) -> EmbedRecord:
        """Book one declared watermark-embedding decision. Embed ids are minted."""
        with self._lock:
            seq = self._claim(seq)
            try:
                content_digest = _check_digest(content_digest, "content_digest")
                payload_digest = _check_digest(
                    payload_digest, "payload_digest", allow_empty=True
                )
                channel = _check_channel(channel)
                robustness = _check_robustness(robustness)
            except RobustWatermarkError as exc:
                self._fail(seq, exc)
            embed_id = f"emb-{len(self._embeds) + 1}"
            if embed_id in self._embeds:  # pragma: no cover - ids are never recycled
                self._fail(seq, DuplicateEmbedError(f"duplicate embed id {embed_id}"))
            record = EmbedRecord(
                embed_id=embed_id,
                channel=channel,
                robustness=robustness,
                content_digest=content_digest,
                payload_digest=payload_digest,
                digest=_digest_pin(
                    (embed_id, channel, robustness, content_digest, payload_digest),
                    "embed",
                ),
            )
            self._embeds[embed_id] = record
            self._trials_for[embed_id] = []
            self._emit(
                KIND_EMBEDDED,
                seq,
                embed_id=embed_id,
                channel=channel,
                robustness=robustness,
                content_digest=content_digest,
                payload_digest=payload_digest,
            )
            return record

    def survive(
        self,
        embed_id: str,
        transform: str,
        severity: float,
        survived: bool,
        seq: int,
    ) -> TrialRecord:
        """Book one declared robustness trial. Survival is data, never raised."""
        with self._lock:
            seq = self._claim(seq)
            try:
                embed_id = _check_id(embed_id, "embed_id")
                if embed_id not in self._embeds:
                    raise UnknownEmbedError(f"unknown embed id {embed_id!r}")
                transform = _check_transform(transform)
                severity = _check_severity(severity)
                survived = _check_survived(survived)
            except RobustWatermarkError as exc:
                self._fail(seq, exc, embed_id=str(embed_id))
            trial_id = f"tr-{len(self._trials) + 1}"
            record = TrialRecord(
                trial_id=trial_id,
                embed_id=embed_id,
                transform=transform,
                severity=severity,
                survived=survived,
                digest=_digest_pin(
                    (trial_id, embed_id, transform, repr(severity), survived),
                    "trial",
                ),
            )
            self._trials[trial_id] = record
            self._trials_for[embed_id].append(trial_id)
            self._emit(
                KIND_TRIAL,
                seq,
                trial_id=trial_id,
                embed_id=embed_id,
                transform=transform,
                severity=severity,
                survived=survived,
            )
            return record

    # -- pure reads ----------------------------------------------------------

    def extract(self, embed_id: str, seq: int) -> ExtractionReport:
        """Pure-read extraction summary: payload pin + survival outcome as data."""
        with self._lock:
            _check_seq(seq)
            embed_id = _check_id(embed_id, "embed_id")
            record = self._embeds.get(embed_id)
            if record is None:
                raise UnknownEmbedError(f"unknown embed id {embed_id!r}")
            trial_ids = self._trials_for[embed_id]
            survived_count = sum(
                1 for tid in trial_ids if self._trials[tid].survived
            )
            rate_text = _survival_rate_text(len(trial_ids), survived_count)
            report = ExtractionReport(
                embed_id=embed_id,
                channel=record.channel,
                robustness=record.robustness,
                payload_digest=record.payload_digest,
                trials=len(trial_ids),
                survived_trials=survived_count,
                survival_rate_text=rate_text,
                digest=_digest_pin(
                    (
                        embed_id,
                        record.channel,
                        record.robustness,
                        record.payload_digest,
                        len(trial_ids),
                        survived_count,
                        rate_text,
                    ),
                    "extract",
                ),
            )
            return report

    def embed_record(self, embed_id: str, seq: int) -> EmbedRecord:
        """Pure-read lookup of one booked embedding."""
        with self._lock:
            _check_seq(seq)
            embed_id = _check_id(embed_id, "embed_id")
            record = self._embeds.get(embed_id)
            if record is None:
                raise UnknownEmbedError(f"unknown embed id {embed_id!r}")
            return record

    def trial_record(self, trial_id: str, seq: int) -> TrialRecord:
        """Pure-read lookup of one booked trial."""
        with self._lock:
            _check_seq(seq)
            trial_id = _check_id(trial_id, "trial_id")
            record = self._trials.get(trial_id)
            if record is None:
                raise BadEmbedError(f"unknown trial id {trial_id!r}")
            return record

    def embed_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            _check_seq(seq)
            return tuple(self._embeds)

    def trials_for(self, embed_id: str, seq: int) -> Tuple[str, ...]:
        with self._lock:
            _check_seq(seq)
            embed_id = _check_id(embed_id, "embed_id")
            if embed_id not in self._embeds:
                raise UnknownEmbedError(f"unknown embed id {embed_id!r}")
            return tuple(self._trials_for[embed_id])

    def stats(self, seq: int) -> Dict[str, Any]:
        """Pure-read ledger statistics."""
        with self._lock:
            _check_seq(seq)
            return {
                "embeds": len(self._embeds),
                "trials": len(self._trials),
                "by_channel": {
                    ch: sum(1 for r in self._embeds.values() if r.channel == ch)
                    for ch in CHANNELS
                },
                "by_transform": {
                    tr: sum(1 for r in self._trials.values() if r.transform == tr)
                    for tr in TRANSFORMS
                },
                "survived": sum(1 for r in self._trials.values() if r.survived),
                "audit_rows": len(self._audit_events),
                "seq": self._seq,
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            _check_seq(seq)
            return tuple(self._audit_events)


def main() -> None:
    """Self-check entry point."""
    rw = RobustWatermark()
    digest = "sha256:" + "ab" * 32
    rec = rw.embed(digest, "lexical-redundancy", 1, robustness="strong")
    assert rec.verify()
    tr = rw.survive(rec.embed_id, "paraphrase", 0.4, True, 2)
    assert tr.verify()
    rw.survive(rec.embed_id, "crop", 0.9, False, 3)
    rep = rw.extract(rec.embed_id, 4)
    assert rep.verify()
    assert rep.trials == 2 and rep.survived_trials == 1
    assert rep.survival_rate_text == "1/2"
    print("robust-watermark OK: embed, survive, extract, pins, audit")


if __name__ == "__main__":
    main()
