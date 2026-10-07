"""watermark: AI-generated content watermarking decision ledger.

Simulated bookkeeping for watermark *decisions* (Kirchenbauer et al. 2023;
Christ et al. undetectable schemes; Aaronson-style pseudorandom marking):
this module records the declared embedding of marks into content, host-
reported detection attempts, and statistical verdicts computed from
host-reported match counts.  It embeds nothing in real text, detects
nothing in real data, and never sees key material: the raw secret key,
the raw content, and the raw candidate text travel only as ``sha256:``
digest pins.  A ``detected=True`` verdict means "the host-reported match
count crossed the declared threshold", never "this content is watermarked".

Public API:
    Watermark.register_key(key_id, seq, key_digest="")
    Watermark.embed(content_id, key_id, seq, content_digest="", bits="")
    Watermark.detect(candidate_digest, key_id, seq, matches, total)
    Watermark.verify(content_id, seq)
    Watermark.detected_ids() / key_ids / content_ids / stats / audit_log
    watermark_audit_event(kind, seq, detail=None)

Honest scope: simulated ledger.  Booking is a declaration; keys are
digest-pinned declarations that can never be used to actually mark or
detect anything.  The z-score statistic is exact-integer arithmetic over
host-reported counts (GIGO), never a claim about real watermark strength.
"""
from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field, FrozenInstanceError
from typing import Any, Dict, List, Optional, Tuple

try:  # standard sibling fallback
    from canonical_json import jcs_dumps as _jcs_dumps
except Exception:  # pragma: no cover - fallback path
    import json as _json

    def _jcs_dumps(obj: Any) -> str:
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False)


VERSION = "watermark.v1"
SCHEMA = "northstar.watermark.v1"
AUDIT_SCHEMA = "audit.ndjson/1"

_AUDIT_KINDS = (
    "key-registered",
    "embedded",
    "detected",
    "verified",
    "rejected",
)

# Raw material that must never cross the audit boundary: only ids,
# digests, counts, and verdicts travel.  Exact-key matching (no substring
# false positives).
_BANNED_KEYS = frozenset({
    "key", "secret", "content", "text", "candidate", "bits", "raw",
    "payload", "value", "data", "watermark_text", "message",
})

_DIGEST_RE = r"^[0-9a-f]{64}$"


# ---------------------------------------------------------------------------
# error taxonomy
# ---------------------------------------------------------------------------

class WatermarkError(Exception):
    """Base error for the watermark ledger."""


class BadIdError(WatermarkError):
    """Malformed identifier (not a non-empty str of bounded length)."""


class BadDigestError(WatermarkError):
    """Malformed digest (not ``sha256:<64hex>``)."""


class BadBitsError(WatermarkError):
    """Malformed watermark bit string."""


class BadCountsError(WatermarkError):
    """Malformed detection counts."""


class BadThresholdError(WatermarkError):
    """Malformed detection threshold."""


class DuplicateKeyError(WatermarkError):
    """A watermark key is already registered."""


class UnknownKeyError(WatermarkError):
    """No such registered key."""


class DuplicateContentError(WatermarkError):
    """Content id already embedded."""


class RetiredContentError(WatermarkError):
    """Content id was retired and may never be reused."""


class UnknownContentError(WatermarkError):
    """No such embedded content."""


class DuplicateDetectionError(WatermarkError):
    """Detection id already booked."""


class SeqOrderError(WatermarkError):
    """Seq not a strictly increasing int."""


class AuditKindError(WatermarkError):
    """Unknown audit kind or malformed audit row."""


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _digest_pin(data: str) -> str:
    return "sha256:" + hashlib.sha256(data.encode("utf-8")).hexdigest()


def _check_id(value: Any, name: str = "id") -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise BadIdError(f"bad {name}")
    if value.strip() != value or any(c.isspace() for c in value):
        raise BadIdError(f"bad {name}")
    return value


def _check_digest(value: Any, name: str = "digest") -> str:
    if not isinstance(value, str):
        raise BadDigestError(f"bad {name}")
    import re
    if not re.match(r"^sha256:[0-9a-f]{64}$", value):
        raise BadDigestError(f"bad {name}")
    return value


def _check_bits(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > 1024:
        raise BadBitsError("bad bits")
    if any(c not in "01" for c in value):
        raise BadBitsError("bad bits")
    return value


def _check_counts(matches: Any, total: Any) -> Tuple[int, int]:
    for v, name in ((matches, "matches"), (total, "total")):
        if isinstance(v, bool) or not isinstance(v, int) or v < 0:
            raise BadCountsError(f"bad {name}")
    if total <= 0:
        raise BadCountsError("total must be positive")
    if matches > total:
        raise BadCountsError("matches exceeds total")
    return matches, total


def _check_threshold(value: Any) -> int:
    # threshold expressed as a z-score threshold x1000 (exact int, no floats)
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise BadThresholdError("bad threshold")
    return value


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError("bad seq")
    return seq


def watermark_audit_event(kind: str, seq: int,
                          detail: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the watermark ledger."""
    if kind not in _AUDIT_KINDS:
        raise AuditKindError(f"unknown kind: {kind!r}")
    seq = _check_seq(seq)
    detail = dict(detail or {})
    for key in detail:
        if key in _BANNED_KEYS:
            raise AuditKindError(f"banned key in audit detail: {key!r}")
    row = {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "seq": seq,
        "module": "watermark",
        "detail": detail,
    }
    row["digest"] = _digest_pin(_jcs_dumps(row))
    return row


# ---------------------------------------------------------------------------
# frozen records
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class KeyRecord:
    key_id: str
    key_digest: str
    schema: str = SCHEMA
    digest: str = field(default="")

    def as_dict(self) -> Dict[str, Any]:
        return {"key_id": self.key_id, "key_digest": self.key_digest,
                "schema": self.schema, "digest": self.digest}

    def verify(self) -> bool:
        body = {"key_id": self.key_id, "key_digest": self.key_digest,
                "schema": self.schema}
        return self.digest == _digest_pin(_jcs_dumps(body))


@dataclass(frozen=True)
class EmbedRecord:
    content_id: str
    key_id: str
    content_digest: str
    bits_digest: str
    bit_count: int
    schema: str = SCHEMA
    digest: str = field(default="")

    def as_dict(self) -> Dict[str, Any]:
        return {"content_id": self.content_id, "key_id": self.key_id,
                "content_digest": self.content_digest,
                "bits_digest": self.bits_digest,
                "bit_count": self.bit_count,
                "schema": self.schema, "digest": self.digest}

    def verify(self) -> bool:
        body = {"content_id": self.content_id, "key_id": self.key_id,
                "content_digest": self.content_digest,
                "bits_digest": self.bits_digest, "bit_count": self.bit_count,
                "schema": self.schema}
        return self.digest == _digest_pin(_jcs_dumps(body))


@dataclass(frozen=True)
class DetectionRecord:
    detection_id: str
    candidate_digest: str
    key_id: str
    matches: int
    total: int
    threshold: int
    z_x1000: int
    detected: bool
    schema: str = SCHEMA
    digest: str = field(default="")

    def as_dict(self) -> Dict[str, Any]:
        return {"detection_id": self.detection_id,
                "candidate_digest": self.candidate_digest,
                "key_id": self.key_id, "matches": self.matches,
                "total": self.total, "threshold": self.threshold,
                "z_x1000": self.z_x1000, "detected": self.detected,
                "schema": self.schema, "digest": self.digest}

    def verify(self) -> bool:
        body = {"detection_id": self.detection_id,
                "candidate_digest": self.candidate_digest,
                "key_id": self.key_id, "matches": self.matches,
                "total": self.total, "threshold": self.threshold,
                "z_x1000": self.z_x1000, "detected": self.detected,
                "schema": self.schema}
        return self.digest == _digest_pin(_jcs_dumps(body))


@dataclass(frozen=True)
class VerifyReport:
    content_id: str
    ok: bool
    schema: str = SCHEMA
    digest: str = field(default="")

    def as_dict(self) -> Dict[str, Any]:
        return {"content_id": self.content_id, "ok": self.ok,
                "schema": self.schema, "digest": self.digest}

    def verify(self) -> bool:
        body = {"content_id": self.content_id, "ok": self.ok,
                "schema": self.schema}
        return self.digest == _digest_pin(_jcs_dumps(body))


# ---------------------------------------------------------------------------
# the ledger
# ---------------------------------------------------------------------------

class Watermark:
    """Deterministic single-host watermarking decision ledger."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = -1
        self._keys: Dict[str, KeyRecord] = {}
        self._embeds: Dict[str, EmbedRecord] = {}
        self._detections: Dict[str, DetectionRecord] = {}
        self._det_counter = 0
        self._audit: List[Dict[str, Any]] = []

    # -- seq discipline: claim-then-burn -------------------------------

    def _claim(self, seq: int) -> None:
        seq = _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError("seq must strictly increase")
        self._seq = seq

    def _emit(self, audit_kind: str, detail: Dict[str, Any]) -> None:
        self._audit.append(watermark_audit_event(audit_kind, self._seq,
                                                 detail))

    def _reject(self, detail: Dict[str, Any]) -> None:
        self._audit.append(watermark_audit_event("rejected", self._seq,
                                                 detail))

    # -- API ------------------------------------------------------------

    def register_key(self, key_id: str, seq: int,
                     key_digest: str = "") -> KeyRecord:
        """Declare a watermark key; raw key material never enters a record."""
        with self._lock:
            self._claim(seq)
            try:
                key_id = _check_id(key_id, "key_id")
                key_digest = _check_digest(key_digest, "key_digest") \
                    if key_digest else _digest_pin("watermark-key:" + key_id)
                if key_id in self._keys:
                    raise DuplicateKeyError(f"duplicate key: {key_id!r}")
                body = {"key_id": key_id, "key_digest": key_digest,
                        "schema": SCHEMA}
                rec = KeyRecord(key_id=key_id, key_digest=key_digest,
                                digest=_digest_pin(_jcs_dumps(body)))
                self._keys[key_id] = rec
                self._emit("key-registered", {"key_id": key_id,
                                              "key_digest": key_digest})
                return rec
            except WatermarkError:
                self._reject({"op": "register_key", "key_id": str(key_id)})
                raise

    def embed(self, content_id: str, key_id: str, seq: int,
              content_digest: str = "", bits: str = "") -> EmbedRecord:
        """Book the *decision* that content_id was watermarked under key_id.

        The watermark bits are digest-pinned; raw text and raw key material
        never enter a record.
        """
        with self._lock:
            self._claim(seq)
            try:
                content_id = _check_id(content_id, "content_id")
                key_id = _check_id(key_id, "key_id")
                if key_id not in self._keys:
                    raise UnknownKeyError(f"unknown key: {key_id!r}")
                if content_id in self._embeds:
                    raise DuplicateContentError(
                        f"duplicate content: {content_id!r}")
                content_digest = _check_digest(content_digest,
                                              "content_digest")
                bits = _check_bits(bits)
                bits_digest = _digest_pin("watermark-bits:" + bits)
                body = {"content_id": content_id, "key_id": key_id,
                        "content_digest": content_digest,
                        "bits_digest": bits_digest, "bit_count": len(bits),
                        "schema": SCHEMA}
                rec = EmbedRecord(content_id=content_id, key_id=key_id,
                                  content_digest=content_digest,
                                  bits_digest=bits_digest,
                                  bit_count=len(bits),
                                  digest=_digest_pin(_jcs_dumps(body)))
                self._embeds[content_id] = rec
                self._emit("embedded", {"content_id": content_id,
                                       "key_id": key_id,
                                       "bit_count": len(bits)})
                return rec
            except WatermarkError:
                self._reject({"op": "embed",
                              "content_id": str(content_id)})
                raise

    @staticmethod
    def z_score_x1000(matches: int, total: int) -> int:
        """Exact-integer z-score of *matches* under a fair-coin null, x1000.

        z = (matches - total/2) / sqrt(total/4).  Computed as
        floor(1000 * (2*matches - total) / sqrt(total)) with a deterministic
        integer sqrt, so the ledger never touches floats.
        """
        import math
        num = 1000 * (2 * matches - total)
        den = math.isqrt(total)
        if den == 0:
            return 0
        return num // den

    def detect(self, candidate_digest: str, key_id: str, seq: int,
               matches: int, total: int, threshold: int = 4000) -> DetectionRecord:
        """Book a detection attempt over host-reported match counts.

        The module computes the z-score (exact integer arithmetic) and books
        ``detected = z >= threshold`` **as data** — a booked verdict means
        the reported count crossed the threshold, never that the candidate
        really carries a watermark.
        """
        with self._lock:
            self._claim(seq)
            try:
                candidate_digest = _check_digest(candidate_digest,
                                                "candidate_digest")
                key_id = _check_id(key_id, "key_id")
                if key_id not in self._keys:
                    raise UnknownKeyError(f"unknown key: {key_id!r}")
                matches, total = _check_counts(matches, total)
                threshold = _check_threshold(threshold)
                z = self.z_score_x1000(matches, total)
                detected = z >= threshold
                self._det_counter += 1
                detection_id = f"det-{self._det_counter}"
                body = {"detection_id": detection_id,
                        "candidate_digest": candidate_digest,
                        "key_id": key_id, "matches": matches, "total": total,
                        "threshold": threshold, "z_x1000": z,
                        "detected": detected, "schema": SCHEMA}
                rec = DetectionRecord(
                    detection_id=detection_id,
                    candidate_digest=candidate_digest, key_id=key_id,
                    matches=matches, total=total, threshold=threshold,
                    z_x1000=z, detected=detected,
                    digest=_digest_pin(_jcs_dumps(body)))
                self._detections[detection_id] = rec
                self._emit("detected", {"detection_id": detection_id,
                                       "key_id": key_id, "matches": matches,
                                       "total": total, "threshold": threshold,
                                       "z_x1000": z, "detected": detected})
                return rec
            except WatermarkError:
                self._reject({"op": "detect", "key_id": str(key_id)})
                raise

    def verify(self, content_id: str, seq: int) -> VerifyReport:
        """Re-walk one embedded artifact's digest pins (tamper check)."""
        with self._lock:
            self._claim(seq)
            try:
                content_id = _check_id(content_id, "content_id")
                rec = self._embeds.get(content_id)
                if rec is None:
                    raise UnknownContentError(
                        f"unknown content: {content_id!r}")
                ok = rec.verify()
                body = {"content_id": content_id, "ok": ok,
                        "schema": SCHEMA}
                report = VerifyReport(
                    content_id=content_id, ok=ok,
                    digest=_digest_pin(_jcs_dumps(body)))
                self._emit("verified", {"content_id": content_id, "ok": ok})
                return report
            except WatermarkError:
                self._reject({"op": "verify",
                              "content_id": str(content_id)})
                raise

    # -- pure-read views (validate seq shape, never consume, no audit) --

    def key_record(self, key_id: str, seq: int) -> KeyRecord:
        with self._lock:
            _check_seq(seq)
            key_id = _check_id(key_id, "key_id")
            rec = self._keys.get(key_id)
            if rec is None:
                raise UnknownKeyError(f"unknown key: {key_id!r}")
            return rec

    def embed_record(self, content_id: str, seq: int) -> EmbedRecord:
        with self._lock:
            _check_seq(seq)
            content_id = _check_id(content_id, "content_id")
            rec = self._embeds.get(content_id)
            if rec is None:
                raise UnknownContentError(
                    f"unknown content: {content_id!r}")
            return rec

    def detection_record(self, detection_id: str, seq: int) -> DetectionRecord:
        with self._lock:
            _check_seq(seq)
            detection_id = _check_id(detection_id, "detection_id")
            rec = self._detections.get(detection_id)
            if rec is None:
                raise WatermarkError(f"unknown detection: {detection_id!r}")
            return rec

    def key_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            _check_seq(seq)
            return tuple(sorted(self._keys))

    def content_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            _check_seq(seq)
            return tuple(sorted(self._embeds))

    def detected_ids(self, seq: int) -> Tuple[str, ...]:
        """Detection ids whose booked verdict was ``detected=True``."""
        with self._lock:
            _check_seq(seq)
            return tuple(sorted(
                d for d, r in self._detections.items() if r.detected))

    def stats(self, seq: int) -> Dict[str, Any]:
        with self._lock:
            _check_seq(seq)
            return {"keys": len(self._keys), "embedded": len(self._embeds),
                    "detections": len(self._detections),
                    "detected": len([r for r in self._detections.values()
                                     if r.detected]),
                    "seq": self._seq}

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            _check_seq(seq)
            return tuple(self._audit)


def main() -> None:
    wm = Watermark()
    k = wm.register_key("k1", 1)
    assert k.verify()
    content_digest = "sha256:" + "ab" * 32
    e = wm.embed("doc-1", "k1", 2, content_digest=content_digest,
                 bits="1010101010")
    assert e.verify() and e.bit_count == 10
    # 9 of 10 matches under a fair-coin null: z = 8000//3 = 2666
    d = wm.detect(content_digest, "k1", 3, matches=9, total=10,
                  threshold=2000)
    assert d.detected and d.verify()
    d2 = wm.detect(content_digest, "k1", 4, matches=5, total=10)
    assert not d2.detected
    v = wm.verify("doc-1", 5)
    assert v.ok and v.verify()
    assert wm.detected_ids(6) == ("det-1",)
    print("watermark OK: register, embed, detect, verify, pins, audit")


if __name__ == "__main__":
    main()
