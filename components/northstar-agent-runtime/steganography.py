"""steganography.py — hidden-message embedding/extraction/detection bookkeeping.

Steganography-shaped decision ledger (LSB embedding, zero-width-character
steganography, metadata carriers, whitespace/unicode tricks) as a
deterministic single-host state machine: book the *declared decision* to
hide a message in a carrier, book an extraction attempt, and book a
steganalysis verdict — all as ledger records. Simulated: the module never
performs real embedding or real steganalysis. Message content travels as a
``sha256:<64hex>`` digest pin only — raw message text never enters a record
and is banned from the audit boundary. A booked ``extracted`` outcome is
host-reported ledger truth, never proof a message was really recovered; a
``suspicious`` detect verdict is a declared claim, never a finding of fact.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

try:  # pragma: no cover
    from canonical_json import jcs_dumps as _jcs_dumps  # type: ignore
except Exception:  # pragma: no cover
    _jcs_dumps = None  # type: ignore

VERSION = "steganography.v1"
SCHEMA = "northstar.steganography.v1"
AUDIT_SCHEMA = "audit.ndjson/1"

_DIGEST_PREFIX = "sha256:"
_MAX_INT = 2**53
_MAX_ID_LEN = 128

TECHNIQUES = (
    "lsb",
    "zero-width",
    "metadata",
    "whitespace",
    "unicode-homoglyph",
)

EXTRACT_OUTCOMES = (
    "recovered",
    "no-payload",
    "ambiguous",
)

DETECT_VERDICTS = (
    "clean",
    "suspicious",
    "inconclusive",
)

AUDIT_KINDS = (
    "message-hidden",
    "extracted",
    "detection-reported",
    "steganography.rejected",
)


class SteganographyError(Exception):
    """Base for all steganography errors."""


class BadIdError(SteganographyError):
    pass


class DuplicateHideError(SteganographyError):
    pass


class UnknownCarrierError(SteganographyError):
    pass


class BadTechniqueError(SteganographyError):
    pass


class BadDigestError(SteganographyError):
    pass


class BadScoreError(SteganographyError):
    pass


class BadVerdictError(SteganographyError):
    pass


class SeqOrderError(SteganographyError):
    pass


class AuditKindError(SteganographyError):
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


def _check_digest_opt(value: Any, what: str) -> str:
    if value == "":
        return ""
    return _check_digest(value, what)


def _check_technique(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadTechniqueError(f"technique must be a str, got {type(value).__name__}")
    if value not in TECHNIQUES:
        raise BadTechniqueError(f"technique {value!r} not in pinned vocabulary")
    return value


def _check_score(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise BadScoreError(f"score must be a number, got {type(value).__name__}")
    score = float(value)
    if score != score or score in (float("inf"), float("-inf")):
        raise BadScoreError("score must be finite")
    if not 0.0 <= score <= 1.0:
        raise BadScoreError("score must be in [0,1]")
    return score


def _check_verdict(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadVerdictError(f"verdict must be a str, got {type(value).__name__}")
    if value not in DETECT_VERDICTS:
        raise BadVerdictError(f"verdict {value!r} not in pinned vocabulary")
    return value


# ---------------------------------------------------------------------------
# Canonical encoding and digest pins
# ---------------------------------------------------------------------------


def _canonical(payload: Any) -> bytes:
    if _jcs_dumps is not None:
        return _jcs_dumps(payload).encode("utf-8")  # type: ignore

    def _tag(v: Any) -> Any:
        if isinstance(v, bool):
            return {"t": "bool", "v": v}
        if isinstance(v, int):
            if abs(v) > _MAX_INT:
                raise SteganographyError("integer outside safe range")
            return {"t": "int", "v": v}
        if isinstance(v, float):
            if v != v or v in (float("inf"), float("-inf")):
                raise SteganographyError("non-finite float refused")
            return {"t": "float", "v": repr(v)}
        if isinstance(v, str):
            return {"t": "str", "v": v}
        if isinstance(v, (list, tuple)):
            return {"t": "list", "v": [_tag(i) for i in v]}
        if isinstance(v, dict):
            return {"t": "dict", "v": [[k, _tag(v[k])] for k in sorted(v)]}
        if v is None:
            return {"t": "null"}
        raise SteganographyError(f"unencodable type: {type(v).__name__}")

    import json

    return json.dumps(_tag(payload), sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest_pin(payload: Any, tag: str) -> str:
    return _DIGEST_PREFIX + hashlib.sha256(
        tag.encode("utf-8") + b"\x1f" + _canonical(payload)
    ).hexdigest()


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HideRecord:
    carrier_id: str
    message_digest: str
    technique: str
    key_digest: str
    seq: int
    digest: str
    schema: str = SCHEMA
    version: str = VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "carrier_id": self.carrier_id,
            "message_digest": self.message_digest,
            "technique": self.technique,
            "key_digest": self.key_digest,
            "seq": self.seq,
            "digest": self.digest,
            "schema": self.schema,
            "version": self.version,
        }

    def verify(self) -> bool:
        expect = _digest_pin(
            (self.carrier_id, self.message_digest, self.technique, self.key_digest),
            "hide",
        )
        return self.digest == expect


@dataclass(frozen=True)
class ExtractOutcome:
    carrier_id: str
    outcome: str
    message_digest: str
    seq: int
    digest: str
    schema: str = SCHEMA
    version: str = VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "carrier_id": self.carrier_id,
            "outcome": self.outcome,
            "message_digest": self.message_digest,
            "seq": self.seq,
            "digest": self.digest,
            "schema": self.schema,
            "version": self.version,
        }

    def verify(self) -> bool:
        expect = _digest_pin(
            (self.carrier_id, self.outcome, self.message_digest), "extract"
        )
        return self.digest == expect


@dataclass(frozen=True)
class DetectionReport:
    carrier_id: str
    verdict: str
    anomaly_score: float
    features_digest: str
    seq: int
    digest: str
    schema: str = SCHEMA
    version: str = VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "carrier_id": self.carrier_id,
            "verdict": self.verdict,
            "anomaly_score": self.anomaly_score,
            "features_digest": self.features_digest,
            "seq": self.seq,
            "digest": self.digest,
            "schema": self.schema,
            "version": self.version,
        }

    def verify(self) -> bool:
        expect = _digest_pin(
            (
                self.carrier_id,
                self.verdict,
                repr(self.anomaly_score),
                self.features_digest,
            ),
            "detect",
        )
        return self.digest == expect


# ---------------------------------------------------------------------------
# Audit event builder
# ---------------------------------------------------------------------------


def steganography_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
    """Build one audit.ndjson/1 event. Raw message/carrier text never crosses this boundary."""
    if kind not in AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    banned = (
        "message",
        "text",
        "content",
        "payload",
        "raw",
        "body",
        "value",
        "secret",
        "plaintext",
        "covertext",
        "key",
    )
    for bad in banned:
        if bad in detail:
            raise AuditKindError(f"audit detail bans {bad!r}")
    _check_seq(seq)
    event = {
        "schema": AUDIT_SCHEMA,
        "module": "steganography",
        "kind": kind,
        "seq": seq,
        "detail": detail,
    }
    event["digest"] = _digest_pin((kind, seq, tuple(sorted(detail))), "audit-event")
    return event


# ---------------------------------------------------------------------------
# Steganography ledger
# ---------------------------------------------------------------------------


class Steganography:
    """Steganography decision bookkeeping: hide, extract, detect."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        # carrier_id -> HideRecord (insertion ordered)
        self._hides: Dict[str, HideRecord] = {}
        # list of ExtractOutcome (insertion ordered)
        self._extractions: List[ExtractOutcome] = []
        # list of DetectionReport (insertion ordered)
        self._detections: List[DetectionReport] = []
        self._audit_events: List[Dict[str, Any]] = []

    # -- seq discipline ----------------------------------------------------

    def _claim(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError(f"seq {seq} not strictly greater than {self._seq}")
        self._seq = seq
        return seq

    def _emit(self, audit_kind: str, seq: int, **detail: Any) -> None:
        self._audit_events.append(steganography_audit_event(audit_kind, seq, **detail))

    def _fail(self, seq: int, exc: SteganographyError, **detail: Any) -> None:
        self._emit(AUDIT_KINDS[-1], seq, error=type(exc).__name__, **detail)
        raise exc

    # -- mutations ----------------------------------------------------------

    def hide(
        self,
        carrier_id: str,
        message_digest: str,
        seq: int,
        technique: str = "lsb",
        key_digest: str = "",
    ) -> HideRecord:
        """Book the declared decision to hide a message in a carrier.

        The message travels as a ``sha256:<64hex>`` pin only — raw message
        text is refused fail-closed (must be a digest pin).
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                carrier_id = _check_id(carrier_id, "carrier_id")
                message_digest = _check_digest(message_digest, "message_digest")
                technique = _check_technique(technique)
                key_digest = _check_digest_opt(key_digest, "key_digest")
                if carrier_id in self._hides:
                    raise DuplicateHideError(
                        f"carrier {carrier_id!r} already hides a message"
                    )
            except SteganographyError as exc:
                self._fail(seq, exc, carrier_id=str(carrier_id))
            record = HideRecord(
                carrier_id=carrier_id,
                message_digest=message_digest,
                technique=technique,
                key_digest=key_digest,
                seq=seq,
                digest=_digest_pin(
                    (carrier_id, message_digest, technique, key_digest), "hide"
                ),
            )
            self._hides[carrier_id] = record
            self._emit(
                "message-hidden",
                seq,
                carrier_id=carrier_id,
                technique=technique,
            )
            return record

    def extract(
        self, carrier_id: str, seq: int, key_digest: str = ""
    ) -> ExtractOutcome:
        """Book one extraction attempt.

        The outcome is host-reported data: ``recovered`` (a hide is booked
        for this carrier) or ``no-payload`` — never proof of real recovery.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                carrier_id = _check_id(carrier_id, "carrier_id")
                key_digest = _check_digest_opt(key_digest, "key_digest")
            except SteganographyError as exc:
                self._fail(seq, exc, carrier_id=str(carrier_id))
            hidden = self._hides.get(carrier_id)
            if hidden is not None:
                outcome = "recovered"
                message_digest = hidden.message_digest
            else:
                outcome = "no-payload"
                message_digest = ""
            record = ExtractOutcome(
                carrier_id=carrier_id,
                outcome=outcome,
                message_digest=message_digest,
                seq=seq,
                digest=_digest_pin((carrier_id, outcome, message_digest), "extract"),
            )
            self._extractions.append(record)
            self._emit(
                "extracted",
                seq,
                carrier_id=carrier_id,
                outcome=outcome,
            )
            return record

    def detect(
        self,
        carrier_id: str,
        verdict: str,
        anomaly_score: float,
        seq: int,
        features_digest: str = "",
    ) -> DetectionReport:
        """Book one steganalysis verdict.

        ``verdict`` and ``anomaly_score`` are host-reported and booked as
        data — a ``suspicious`` verdict is a declared claim, never a finding
        of fact. Features travel as a digest pin only.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                carrier_id = _check_id(carrier_id, "carrier_id")
                verdict = _check_verdict(verdict)
                score = _check_score(anomaly_score)
                features_digest = _check_digest_opt(features_digest, "features_digest")
            except SteganographyError as exc:
                self._fail(seq, exc, carrier_id=str(carrier_id))
            record = DetectionReport(
                carrier_id=carrier_id,
                verdict=verdict,
                anomaly_score=score,
                features_digest=features_digest,
                seq=seq,
                digest=_digest_pin(
                    (carrier_id, verdict, repr(score), features_digest), "detect"
                ),
            )
            self._detections.append(record)
            self._emit(
                "detection-reported",
                seq,
                carrier_id=carrier_id,
                verdict=verdict,
                anomaly_score=repr(score),
            )
            return record

    # -- pure reads -----------------------------------------------------------

    def hide_record(self, carrier_id: str, seq: int) -> Optional[HideRecord]:
        """Pure read: the hide record for a carrier, or None."""
        _check_seq(seq)
        return self._hides.get(carrier_id)

    def extractions_for(self, carrier_id: str, seq: int) -> Tuple[ExtractOutcome, ...]:
        """Pure read: extraction outcomes booked for a carrier."""
        _check_seq(seq)
        return tuple(e for e in self._extractions if e.carrier_id == carrier_id)

    def detections_for(self, carrier_id: str, seq: int) -> Tuple[DetectionReport, ...]:
        """Pure read: detection reports booked for a carrier."""
        _check_seq(seq)
        return tuple(d for d in self._detections if d.carrier_id == carrier_id)

    def carrier_ids(self, seq: int) -> Tuple[str, ...]:
        """Pure read: carriers with a booked hide."""
        _check_seq(seq)
        return tuple(self._hides)

    def stats(self, seq: int) -> Dict[str, Any]:
        """Pure read: ledger counts."""
        _check_seq(seq)
        return {
            "hides": len(self._hides),
            "extractions": len(self._extractions),
            "detections": len(self._detections),
            "audit_events": len(self._audit_events),
            "schema": SCHEMA,
            "version": VERSION,
        }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        """Pure read: the audit event log."""
        _check_seq(seq)
        return tuple(self._audit_events)


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------


def main() -> None:
    st = Steganography()
    digest = _DIGEST_PREFIX + hashlib.sha256(b"meet at dawn").hexdigest()
    key = _DIGEST_PREFIX + hashlib.sha256(b"shared-secret").hexdigest()
    feat = _DIGEST_PREFIX + hashlib.sha256(b"rs-noise-stats").hexdigest()

    rec = st.hide("img-001.png", digest, 1, technique="lsb", key_digest=key)
    assert rec.verify()
    assert rec.technique == "lsb"
    assert st.stats(1)["hides"] == 1
    # no raw message text anywhere in the record
    assert b"meet at dawn" not in _canonical(rec.as_dict())

    ext = st.extract("img-001.png", 2)
    assert ext.outcome == "recovered"
    assert ext.message_digest == digest
    assert ext.verify()

    miss = st.extract("empty.png", 3)
    assert miss.outcome == "no-payload"
    assert miss.message_digest == ""

    rep = st.detect("img-001.png", "suspicious", 0.87, 4, features_digest=feat)
    assert rep.verdict == "suspicious"
    assert rep.anomaly_score == 0.87
    assert rep.verify()

    # duplicate hide refused
    try:
        st.hide("img-001.png", digest, 5)
    except DuplicateHideError:
        pass
    else:
        raise AssertionError("duplicate hide accepted")

    # raw message text refused fail-closed (must be a digest pin)
    try:
        st.hide("img-002.png", "the actual secret message", 6)
    except BadDigestError:
        pass
    else:
        raise AssertionError("raw message accepted")

    # bad technique refused
    try:
        st.hide("img-003.png", digest, 7, technique="invisible-ink")
    except BadTechniqueError:
        pass
    else:
        raise AssertionError("bad technique accepted")

    # bad verdict refused
    try:
        st.detect("img-001.png", "definitely-stego", 0.5, 8)
    except BadVerdictError:
        pass
    else:
        raise AssertionError("bad verdict accepted")

    # bad score refused
    try:
        st.detect("img-001.png", "clean", 1.5, 9)
    except BadScoreError:
        pass
    else:
        raise AssertionError("bad score accepted")

    # pure reads: same seq reused, no audit rows written
    before = len(st.audit_log(0))
    st.hide_record("img-001.png", 9)
    st.extractions_for("img-001.png", 9)
    st.detections_for("img-001.png", 9)
    st.carrier_ids(9)
    st.stats(9)
    assert len(st.audit_log(9)) == before

    # raw message digest never leaves the audit boundary as text
    for event in st.audit_log(9):
        assert "message" not in event["detail"]
        assert "text" not in event["detail"]

    # audit boundary bans raw-text keys
    try:
        steganography_audit_event("message-hidden", 9, carrier_id="x", message="secret")
    except AuditKindError:
        pass
    else:
        raise AssertionError("audit leak ban accepted")

    st2 = Steganography()
    rec2 = st2.hide("img-001.png", digest, 1, technique="lsb", key_digest=key)
    assert rec2.digest == rec.digest, "cross-instance digest determinism"

    # tamper rejection
    import dataclasses

    rec3 = st.hide("img-004.png", digest, 10, technique="zero-width")
    tampered = dataclasses.replace(rec3, technique="lsb")
    assert not tampered.verify(), "tampered record verifies"

    print("steganography OK: hide, extract, detect, pins, audit")


if __name__ == "__main__":
    main()
