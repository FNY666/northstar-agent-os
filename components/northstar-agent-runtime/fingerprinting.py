"""Content fingerprinting: deterministic perceptual-hash-style ledger.

Research motivation: audio fingerprinting (Shazam-style landmark hashes,
Chromaprint) and image perceptual hashing (aHash/dHash/pHash) reduce a
content item to a compact feature fingerprint so that near-duplicates can
be matched without comparing raw bytes. This module books that
*fingerprint lifecycle* deterministically as a single-host ledger:

- ``hash(item_id, features, seq)`` -- books one fingerprint.
- ``match(fingerprint_id, candidate_features, seq, tolerance=...)``
  -- declares one matching decision (verdict as data).
- ``index(item_id, seq)`` -- declares the item searchable in the
  fast lookup index.

It runs no DSP, opens no sockets, and persists nothing -- "fingerprint"
here means a quantized-feature digest pinned by ``sha256:``, never a
proved content identity.

Public API:

- ``Fingerprinting()`` -- mutable, RLock-guarded ledger.
  - ``hash(item_id, features, seq)`` -> frozen ``FingerprintRecord``
    (``fp-N`` ids): books a fingerprint over a host-reported feature
    tuple (finite floats, bools refused). Features are quantized at a
    fixed resolution (``q = round(f * 256)``) and pinned by digest;
    raw features never enter a record.
  - ``match(fingerprint_id, candidate_features, seq,
    tolerance=0.25)`` -> frozen ``MatchReport``: declares one matching
    decision -- normalized quantized distance (fraction of differing
    buckets) as data, ``match = distance <= tolerance`` as data. The
    decision is booked with an audit row; host-reported features are
    the GIGO boundary.
  - ``index(item_id, seq)`` -> frozen ``IndexRecord``: books the item
    into the fast lookup index keyed by its fingerprint bucket prefix.
    Indexing an unknown item raises; double indexing raises.
  - ``fingerprint(item_id)`` / ``item_ids()`` / ``indexed_ids()`` /
    ``stats()`` / ``audit_log()`` -- pure read views; consume no seq.
- ``fingerprinting_audit_event(kind, detail, seq)`` --
  ``audit.ndjson/1`` records: ``"fingerprinting.hashed"``,
  ``"fingerprinting.matched"``, ``"fingerprinting.indexed"``,
  ``"fingerprinting.rejected"``.

Raw features never cross the audit boundary: ``detail`` may carry item
ids, feature counts, distances, tolerance, and digest pins -- never
``features``, ``candidate``, ``vector``, ``raw``, ``payload``,
``value`` or ``text``.

House discipline: caller int seqs strictly increasing on mutations
(failed mutations consume their seq; bool/negative/rewind refused),
RLock-guarded, fail-closed taxonomy, stdlib-only (``canonical_json``
sibling helper behind the standard try/except fallback).

Honest scope:

- This module books *declared* fingerprints, matching decisions and
  index entries; it proves no perceptual fact. A ``MatchReport`` says
  "the quantized feature distance is 0.125", never "the content is the
  same item" -- quantization is coarse on purpose, host features are
  GIGO, and collisions are inevitable by design.
- ``hash()`` does not listen to audio or look at pixels; the feature
  vector arrives fully formed from the host. Similarity verdicts are
  distance arithmetic, not identity judgments.
- Deleting an item is not offered: a fingerprint is a permanent
  booking; the ledger is append-only.

Version pin: ``fingerprinting.v1`` / schema pin
``northstar.fingerprinting.v1``.
"""

from __future__ import annotations

import hashlib
import math
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Sequence, Tuple

try:  # stdlib-first; canonical_json is the sibling JCS helper
    from canonical_json import jcs_dumps as _jcs_dumps  # type: ignore

    def _encode(value: object) -> bytes:
        out = _jcs_dumps(value)
        return out.encode("utf-8") if isinstance(out, str) else bytes(out)

except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    def _encode(value: object) -> bytes:  # type: ignore
        return _fallback_encode(value)


def _fallback_encode(value: object) -> bytes:
    """Minimal deterministic encoder (JCS-flavoured) used only when the
    sibling ``canonical_json`` helper is unavailable."""
    if value is None:
        return b"null"
    if isinstance(value, bool):
        return b"true" if value else b"false"
    if isinstance(value, int):
        return str(value).encode("ascii")
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("non-finite float")
        return repr(value).encode("ascii")
    if isinstance(value, str):
        return b'"' + value.encode("utf-8").replace(b"\\", b"\\\\").replace(
            b'"', b'\\"') + b'"'
    if isinstance(value, (list, tuple)):
        return b"[" + b",".join(_fallback_encode(v) for v in value) + b"]"
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda kv: str(kv[0]))
        return b"{" + b",".join(
            _fallback_encode(k) + b":" + _fallback_encode(v)
            for k, v in items
        ) + b"}"
    raise TypeError(f"not canonicalizable: {type(value).__name__}")


#: Module version.
FINGERPRINTING_VERSION = "fingerprinting.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.fingerprinting.v1"

#: Schema pin for audit rows produced by this module.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Hash domain separator so fingerprint digests cannot collide with
#: digests from other modules.
_HASH_DOMAIN = b"northstar.fingerprinting.v1\x00"

#: Feature quantization resolution: q = round(f * _QUANTIZE_SCALE).
_QUANTIZE_SCALE = 256

#: Upper bound on feature vector length (ledger-scale sanity limit).
_MAX_FEATURES = 4096

#: Upper bound on id length.
_MAX_ID_LEN = 256

#: Audit kinds this module may book.
AUDIT_KINDS = (
    "fingerprinting.hashed",
    "fingerprinting.matched",
    "fingerprinting.indexed",
    "fingerprinting.rejected",
)

#: Raw-feature keys that must never cross the audit boundary.
_BANNED_AUDIT_KEYS = frozenset(
    {"features", "candidate", "vector", "raw", "payload", "value", "text"}
)


class FingerprintingError(Exception):
    """Base error for content-fingerprinting misuse."""


class BadItemError(FingerprintingError):
    """Raised when an item id is malformed."""


class DuplicateItemError(FingerprintingError):
    """Raised when hashing an item id that already has a fingerprint."""


class UnknownItemError(FingerprintingError):
    """Raised when naming an item id with no booked fingerprint."""


class AlreadyIndexedError(FingerprintingError):
    """Raised when indexing an item that is already indexed."""


class BadFeaturesError(FingerprintingError):
    """Raised when a feature tuple is malformed."""


class BadToleranceError(FingerprintingError):
    """Raised when a match tolerance is out of range."""


class SeqOrderError(FingerprintingError):
    """Raised when a caller seq is not strictly increasing."""


class AuditKindError(FingerprintingError):
    """Raised when an unknown audit kind is requested."""


def _check_seq(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SeqOrderError(f"seq must be a non-negative int, got {value!r}")
    return value


def _check_item_id(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > _MAX_ID_LEN:
        raise BadItemError(
            f"item_id must be a non-empty str <= {_MAX_ID_LEN} chars"
        )
    return value


def _check_features(value: object) -> Tuple[float, ...]:
    """Validate a host-reported feature tuple; GIGO beyond this."""
    if isinstance(value, str) or not isinstance(value, Sequence) or not value:
        raise BadFeaturesError("features must be a non-empty sequence of numbers")
    if len(value) > _MAX_FEATURES:
        raise BadFeaturesError(
            f"features must have at most {_MAX_FEATURES} entries"
        )
    out: List[float] = []
    for entry in value:
        if isinstance(entry, bool) or not isinstance(entry, (int, float)):
            raise BadFeaturesError(f"feature must be a number, got {entry!r}")
        if not math.isfinite(float(entry)):
            raise BadFeaturesError(f"feature must be finite, got {entry!r}")
        out.append(float(entry))
    return tuple(out)


def _check_tolerance(value: object) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not 0.0 <= float(value) <= 1.0
    ):
        raise BadToleranceError(f"tolerance must be a float in [0,1], got {value!r}")
    return float(value)


def _quantize(features: Tuple[float, ...]) -> Tuple[int, ...]:
    """Coarse fixed-point quantization: the deterministic analogue of
    a perceptual-hash bucketizer."""
    return tuple(int(round(f * _QUANTIZE_SCALE)) for f in features)


def _digest_pin(item_id: str, quantized: Tuple[int, ...]) -> str:
    return "sha256:" + hashlib.sha256(
        _HASH_DOMAIN + _encode((item_id, quantized))
    ).hexdigest()


def _report_pin(fingerprint_id: str, distance: float, tolerance: float) -> str:
    return "sha256:" + hashlib.sha256(
        _HASH_DOMAIN + b"match\x00" + _encode((fingerprint_id, repr(distance), repr(tolerance)))
    ).hexdigest()


@dataclass(frozen=True)
class FingerprintRecord:
    """Immutable booking of one content fingerprint."""

    fingerprint_id: str
    item_id: str
    feature_count: int
    feature_digest: str
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "fingerprint_id": self.fingerprint_id,
            "item_id": self.item_id,
            "feature_count": self.feature_count,
            "feature_digest": self.feature_digest,
        }

    def verify(self, quantized: Tuple[int, ...]) -> bool:
        return self.feature_digest == _digest_pin(self.item_id, quantized)


@dataclass(frozen=True)
class MatchReport:
    """Immutable record of one declared matching decision."""

    fingerprint_id: str
    item_id: str
    distance: float
    tolerance: float
    match: bool
    digest: str
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "fingerprint_id": self.fingerprint_id,
            "item_id": self.item_id,
            "distance": self.distance,
            "tolerance": self.tolerance,
            "match": self.match,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class IndexRecord:
    """Immutable booking of one item entering the lookup index."""

    item_id: str
    fingerprint_id: str
    bucket_prefix: str
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "item_id": self.item_id,
            "fingerprint_id": self.fingerprint_id,
            "bucket_prefix": self.bucket_prefix,
        }


def fingerprinting_audit_event(kind: str, detail: Dict[str, Any], seq: int) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the fingerprinting ledger.

    Raw features never cross the boundary: ``detail`` may carry item
    ids, fingerprint ids, counts, distances, tolerance, and digest pins
    -- never ``features``, ``candidate``, ``vector``, ``raw``,
    ``payload``, ``value`` or ``text``.
    """
    if kind not in AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    seq = _check_seq(seq)
    if not isinstance(detail, dict):
        raise FingerprintingError("detail must be a dict")
    for key in detail:
        if key in _BANNED_AUDIT_KEYS:
            raise FingerprintingError(
                f"audit detail key banned from boundary: {key!r}"
            )
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "detail": dict(detail),
        "seq": seq,
    }


class Fingerprinting:
    """Content-fingerprinting ledger: hash/match/index as declared
    bookkeeping."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        self._fingerprints: Dict[str, FingerprintRecord] = {}  # fp id -> record
        self._by_item: Dict[str, str] = {}  # item id -> fp id
        self._quantized: Dict[str, Tuple[int, ...]] = {}  # fp id -> quantized
        self._indexed: Dict[str, IndexRecord] = {}  # item id -> index record
        self._counter = 0
        self._audit: List[Dict[str, Any]] = []

    # -- seq discipline -------------------------------------------------

    def _claim(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq {seq} did not exceed last seq {self._last_seq}"
            )
        self._last_seq = seq
        return seq

    def _reject(self, seq: int, reason: str, item_id: str = "") -> Dict[str, Any]:
        row = fingerprinting_audit_event(
            "fingerprinting.rejected", {"reason": reason, "item_id": item_id}, seq
        )
        self._audit.append(row)
        return row

    def _emit(self, audit_kind: str, detail: Dict[str, Any], seq: int) -> None:
        self._audit.append(fingerprinting_audit_event(audit_kind, detail, seq))

    # -- public API -----------------------------------------------------

    def hash(self, item_id: str, features: object, seq: int) -> FingerprintRecord:
        """Book one fingerprint for an item id.

        ``features`` is a host-reported numeric feature tuple (GIGO);
        bools, non-numbers and non-finite values are refused. Duplicate
        item ids are refused.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                item_id = _check_item_id(item_id)
                feats = _check_features(features)
            except FingerprintingError as exc:
                self._reject(seq, str(exc), str(item_id) if isinstance(item_id, str) else "")
                raise
            if item_id in self._by_item:
                self._reject(seq, "duplicate item", item_id)
                raise DuplicateItemError(f"item already fingerprinted: {item_id!r}")
            quantized = _quantize(feats)
            self._counter += 1
            fp_id = f"fp-{self._counter}"
            record = FingerprintRecord(
                fingerprint_id=fp_id,
                item_id=item_id,
                feature_count=len(feats),
                feature_digest=_digest_pin(item_id, quantized),
            )
            self._fingerprints[fp_id] = record
            self._by_item[item_id] = fp_id
            self._quantized[fp_id] = quantized
            self._emit(
                "fingerprinting.hashed",
                {
                    "fingerprint_id": fp_id,
                    "item_id": item_id,
                    "feature_count": len(feats),
                    "feature_digest": record.feature_digest,
                },
                seq,
            )
            return record

    def match(
        self,
        fingerprint_id: str,
        candidate_features: object,
        seq: int,
        tolerance: float = 0.25,
    ) -> MatchReport:
        """Declare one matching decision against a booked fingerprint.

        Distance is the fraction of differing quantized buckets; the
        verdict ``match = distance <= tolerance`` is booked as data,
        never raised. A wrong-length candidate or unknown fingerprint
        is refused fail-closed.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                record = self._fingerprints.get(fingerprint_id)
                if record is None:
                    raise UnknownItemError(
                        f"unknown fingerprint: {fingerprint_id!r}"
                    )
                feats = _check_features(candidate_features)
                stored = self._quantized[fingerprint_id]
                if len(feats) != len(stored):
                    raise BadFeaturesError(
                        f"candidate length {len(feats)} != stored {len(stored)}"
                    )
                tol = _check_tolerance(tolerance)
            except FingerprintingError as exc:
                self._reject(
                    seq, str(exc),
                    str(fingerprint_id) if isinstance(fingerprint_id, str) else "",
                )
                raise
            quantized = _quantize(feats)
            differing = sum(1 for a, b in zip(quantized, stored) if a != b)
            distance = differing / len(stored)
            verdict = distance <= tol
            report = MatchReport(
                fingerprint_id=fingerprint_id,
                item_id=record.item_id,
                distance=distance,
                tolerance=tol,
                match=verdict,
                digest=_report_pin(fingerprint_id, distance, tol),
            )
            self._emit(
                "fingerprinting.matched",
                {
                    "fingerprint_id": fingerprint_id,
                    "item_id": record.item_id,
                    "distance": distance,
                    "tolerance": tol,
                    "match": verdict,
                    "digest": report.digest,
                },
                seq,
            )
            return report

    def index(self, item_id: str, seq: int) -> IndexRecord:
        """Book an item into the fast lookup index keyed by its
        fingerprint bucket prefix (first quantized bucket, hex).

        The index entry is a declaration of searchability, not proof
        that any lookup ran faster.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                item_id = _check_item_id(item_id)
            except FingerprintingError as exc:
                self._reject(seq, str(exc))
                raise
            if item_id not in self._by_item:
                self._reject(seq, "unknown item", item_id)
                raise UnknownItemError(f"no fingerprint for item: {item_id!r}")
            if item_id in self._indexed:
                self._reject(seq, "already indexed", item_id)
                raise AlreadyIndexedError(f"item already indexed: {item_id!r}")
            fp_id = self._by_item[item_id]
            quantized = self._quantized[fp_id]
            prefix = format(quantized[0] % 256, "02x") if quantized else "00"
            record = IndexRecord(
                item_id=item_id,
                fingerprint_id=fp_id,
                bucket_prefix=prefix,
            )
            self._indexed[item_id] = record
            self._emit(
                "fingerprinting.indexed",
                {
                    "item_id": item_id,
                    "fingerprint_id": fp_id,
                    "bucket_prefix": prefix,
                },
                seq,
            )
            return record

    # -- pure read views --------------------------------------------------

    def fingerprint(self, fingerprint_id: str) -> FingerprintRecord:
        with self._lock:
            record = self._fingerprints.get(fingerprint_id)
            if record is None:
                raise UnknownItemError(f"unknown fingerprint: {fingerprint_id!r}")
            return record

    def fingerprint_id_for(self, item_id: str) -> str:
        with self._lock:
            fp_id = self._by_item.get(item_id)
            if fp_id is None:
                raise UnknownItemError(f"no fingerprint for item: {item_id!r}")
            return fp_id

    def item_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._by_item))

    def indexed_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._indexed))

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "schema": SCHEMA_PIN,
                "fingerprints": len(self._fingerprints),
                "indexed": len(self._indexed),
                "audit_rows": len(self._audit),
                "last_seq": self._last_seq,
            }

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return tuple(dict(row) for row in self._audit)


def main() -> None:  # pragma: no cover - self-check
    ledger = Fingerprinting()
    rec = ledger.hash("track-1", (0.1, 0.2, 0.3, 0.4), 0)
    assert rec.verify(_quantize((0.1, 0.2, 0.3, 0.4)))
    report = ledger.match(rec.fingerprint_id, (0.1, 0.2, 0.3, 0.4), 1)
    assert report.match and report.distance == 0.0
    ledger.index("track-1", 2)
    print("fingerprinting OK: hash, match, index, pins, audit")


if __name__ == "__main__":
    main()
