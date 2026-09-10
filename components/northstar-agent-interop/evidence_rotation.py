"""Crash-consistent segmented evidence log with digest-only compaction.

The log is append-only inside a segment. Rotation seals the active segment and
publishes a digest for it in an atomically replaced manifest; compaction then
replaces a sealed segment's records with that digest. Compaction therefore
degrades *readability*, never *provability*: a compacted segment can still be
referenced by digest and still anchors the chain, but its original records are
gone by design.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

SCHEMA = "northstar.evidence-rotation.v1"
MANIFEST_NAME = "manifest.json"
ACTIVE_NAME = "active.log"
ZERO = "sha256:" + "0" * 64
_SEGMENT_RE = re.compile(r"^segment-(\d{6})\.log$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_RESERVED = frozenset({"sequence", "previous_digest", "record_digest"})
_RECORD_FIELDS = frozenset({"sequence", "previous_digest", "payload", "record_digest"})
_MANIFEST_FIELDS = frozenset({"schema_version", "generation", "segments"})
_REF_FIELDS = frozenset({
    "segment_id", "first_sequence", "last_sequence", "record_count",
    "first_digest", "last_digest", "segment_digest", "compacted",
})


class RotationError(ValueError):
    """Malformed, conflicting, or unrecoverable rotation state."""


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise RotationError(f"{field} is invalid")
    return value


def _positive(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise RotationError(f"{field} is invalid")
    return value


def _canon(value: Any) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise RotationError("value is not canonical JSON") from exc


def _sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _payload(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RotationError("record payload must be an object")
    if set(value) & _RESERVED:
        raise RotationError("record payload must not carry reserved chain keys")
    return json.loads(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                 separators=(",", ":"), allow_nan=False))


def _record_digest(sequence: int, previous_digest: str, payload: dict[str, Any]) -> str:
    return _sha(_canon({"sequence": sequence, "previous_digest": previous_digest,
                        "payload": payload}))


def _segment_digest(records: list[dict[str, Any]]) -> str:
    return _sha(_canon({"records": [record["record_digest"] for record in records]}))


@dataclass(frozen=True)
class SegmentRef:
    segment_id: int
    first_sequence: int
    last_sequence: int
    record_count: int
    first_digest: str
    last_digest: str
    segment_digest: str
    compacted: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "segment_id": self.segment_id,
            "first_sequence": self.first_sequence,
            "last_sequence": self.last_sequence,
            "record_count": self.record_count,
            "first_digest": self.first_digest,
            "last_digest": self.last_digest,
            "segment_digest": self.segment_digest,
            "compacted": self.compacted,
        }

    @classmethod
    def from_dict(cls, value: Any) -> "SegmentRef":
        if not isinstance(value, dict) or set(value) != _REF_FIELDS:
            raise RotationError("segment reference fields invalid")
        if not isinstance(value["compacted"], bool):
            raise RotationError("segment compacted flag invalid")
        first = _positive(value["first_sequence"], "first_sequence")
        last = _positive(value["last_sequence"], "last_sequence")
        count = _positive(value["record_count"], "record_count")
        if last < first or count != last - first + 1:
            raise RotationError("segment sequence bounds inconsistent")
        return cls(_positive(value["segment_id"], "segment_id"), first, last, count,
                   _digest(value["first_digest"], "first_digest"),
                   _digest(value["last_digest"], "last_digest"),
                   _digest(value["segment_digest"], "segment_digest"),
                   value["compacted"])


@dataclass(frozen=True)
class RotationVerdict:
    state: str
    reasons: tuple[str, ...]
    segments: tuple[int, ...]


class SegmentedEvidenceLog:
    def __init__(self, root: str | Path, *, max_records_per_segment: int = 1024):
        _positive(max_records_per_segment, "max_records_per_segment")
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        self.max_records_per_segment = max_records_per_segment
        self.lock_path = self.root / "rotation.lock"
        self.manifest_path = self.root / MANIFEST_NAME
        self.active_path = self.root / ACTIVE_NAME
        with self._lock():
            self._manifest = self._load_manifest()
            self._reconcile()

    # -- locking and durability -------------------------------------------------
    @contextmanager
    def _lock(self):
        with self.lock_path.open("a+") as handle:
            os.chmod(self.lock_path, 0o600)
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def _fsync_dir(self) -> None:
        handle = os.open(self.root, os.O_RDONLY)
        try:
            os.fsync(handle)
        finally:
            os.close(handle)

    def segment_path(self, segment_id: int) -> Path:
        return self.root / ("segment-%06d.log" % segment_id)

    # -- manifest ---------------------------------------------------------------
    def _load_manifest(self) -> dict[str, Any]:
        if not self.manifest_path.exists():
            return {"schema_version": SCHEMA, "generation": 0, "segments": []}
        try:
            value = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RotationError("manifest is not readable JSON") from exc
        if not isinstance(value, dict) or set(value) != _MANIFEST_FIELDS:
            raise RotationError("manifest fields invalid")
        if value["schema_version"] != SCHEMA:
            raise RotationError("manifest schema_version invalid")
        generation = value["generation"]
        if not isinstance(generation, int) or isinstance(generation, bool) or generation < 0:
            raise RotationError("manifest generation invalid")
        raw = value["segments"]
        if not isinstance(raw, list):
            raise RotationError("manifest segments invalid")
        segments = [SegmentRef.from_dict(item) for item in raw]
        for index, ref in enumerate(segments):
            if ref.segment_id != index + 1:
                raise RotationError("manifest segment order is not contiguous")
            if index and ref.first_sequence != segments[index - 1].last_sequence + 1:
                raise RotationError("manifest segment sequences are not contiguous")
        return {"schema_version": SCHEMA, "generation": generation, "segments": segments}

    def _publish_manifest(self, segments: list[SegmentRef]) -> None:
        generation = self._manifest["generation"] + 1
        value = {"schema_version": SCHEMA, "generation": generation,
                 "segments": [ref.to_dict() for ref in segments]}
        tmp = self.root / (MANIFEST_NAME + ".tmp")
        with tmp.open("w", encoding="utf-8") as handle:
            handle.write(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                    separators=(",", ":")) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.manifest_path)
        self._fsync_dir()
        self._manifest = {"schema_version": SCHEMA, "generation": generation,
                          "segments": list(segments)}

    # -- records ----------------------------------------------------------------
    def _validate_record(self, value: Any) -> dict[str, Any]:
        if not isinstance(value, dict) or set(value) != _RECORD_FIELDS:
            raise RotationError("record fields invalid")
        sequence = _positive(value["sequence"], "sequence")
        previous = _digest(value["previous_digest"], "previous_digest")
        payload = _payload(value["payload"])
        digest = _digest(value["record_digest"], "record_digest")
        if _record_digest(sequence, previous, payload) != digest:
            raise RotationError("record digest mismatch")
        return {"sequence": sequence, "previous_digest": previous,
                "payload": payload, "record_digest": digest}

    def _read_records(self, path: Path) -> list[dict[str, Any]]:
        if not path.exists():
            return []
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise RotationError("segment is not readable") from exc
        records = []
        for line in raw.split(b"\n")[:-1]:
            if not line.strip():
                continue
            try:
                value = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise RotationError("complete record line is invalid JSON") from exc
            records.append(self._validate_record(value))
        return records

    @staticmethod
    def _public(record: dict[str, Any]) -> dict[str, Any]:
        return {**record["payload"], "sequence": record["sequence"],
                "previous_digest": record["previous_digest"],
                "record_digest": record["record_digest"]}

    @staticmethod
    def _next_identity(records: list[dict[str, Any]], segments: list[SegmentRef]) -> tuple[int, str]:
        if records:
            return records[-1]["sequence"] + 1, records[-1]["record_digest"]
        if segments:
            return segments[-1].last_sequence + 1, segments[-1].last_digest
        return 1, ZERO

    # -- recovery ---------------------------------------------------------------
    def _reconcile(self) -> bool:
        """Finish a rotation that crashed between manifest publish and rename."""
        repaired = False
        for ref in self._manifest["segments"]:
            if ref.compacted or self.segment_path(ref.segment_id).exists():
                continue
            if not self.active_path.exists():
                continue
            try:
                records = self._read_records(self.active_path)
            except RotationError:
                continue
            if len(records) != ref.record_count or _segment_digest(records) != ref.segment_digest:
                continue
            os.replace(self.active_path, self.segment_path(ref.segment_id))
            self._fsync_dir()
            repaired = True
        return repaired

    # -- public surface ---------------------------------------------------------
    @property
    def active_segment_id(self) -> int:
        segments = self._manifest["segments"]
        return segments[-1].segment_id + 1 if segments else 1

    @property
    def active_record_count(self) -> int:
        return len(self._read_records(self.active_path))

    def segments(self) -> list[SegmentRef]:
        return list(self._manifest["segments"])

    def append(self, payload: dict[str, Any]) -> int:
        payload = _payload(payload)
        with self._lock():
            if len(self._read_records(self.active_path)) >= self.max_records_per_segment:
                self._seal_active()
            records = self._read_records(self.active_path)
            sequence, previous = self._next_identity(records, self._manifest["segments"])
            digest = _record_digest(sequence, previous, payload)
            line = json.dumps({"sequence": sequence, "previous_digest": previous,
                               "payload": payload, "record_digest": digest},
                              ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            with self.active_path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(self.active_path, 0o600)
            return sequence

    def _seal_active(self) -> SegmentRef:
        records = self._read_records(self.active_path)
        if not records:
            raise RotationError("active segment is empty")
        segments = list(self._manifest["segments"])
        segment_id = segments[-1].segment_id + 1 if segments else 1
        ref = SegmentRef(segment_id, records[0]["sequence"], records[-1]["sequence"],
                         len(records), records[0]["record_digest"],
                         records[-1]["record_digest"], _segment_digest(records))
        self._publish_manifest(segments + [ref])
        os.replace(self.active_path, self.segment_path(segment_id))
        self._fsync_dir()
        return ref

    def rotate(self) -> SegmentRef:
        with self._lock():
            return self._seal_active()

    def compact(self, segment_id: int) -> SegmentRef:
        _positive(segment_id, "segment_id")
        with self._lock():
            segments = list(self._manifest["segments"])
            for index, ref in enumerate(segments):
                if ref.segment_id != segment_id:
                    continue
                if ref.compacted:
                    raise RotationError("segment is already compacted")
                updated = replace(ref, compacted=True)
                segments[index] = updated
                self._publish_manifest(segments)
                path = self.segment_path(segment_id)
                if path.exists():
                    path.unlink()
                    self._fsync_dir()
                return updated
            raise RotationError("segment is not sealed")

    def read_segment(self, segment_id: int) -> list[dict[str, Any]]:
        _positive(segment_id, "segment_id")
        with self._lock():
            for ref in self._manifest["segments"]:
                if ref.segment_id != segment_id:
                    continue
                if ref.compacted:
                    raise RotationError("segment is compacted and no longer readable")
                return [self._public(record)
                        for record in self._read_records(self.segment_path(segment_id))]
            raise RotationError("segment is not sealed")

    def read_all(self) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        with self._lock():
            for ref in self._manifest["segments"]:
                if ref.compacted:
                    continue
                records.extend(self._public(item)
                               for item in self._read_records(self.segment_path(ref.segment_id)))
            records.extend(self._public(item) for item in self._read_records(self.active_path))
        return records

    def verify(self) -> RotationVerdict:
        with self._lock():
            self._reconcile()
            reasons: list[str] = []
            unverifiable = False
            segments = list(self._manifest["segments"])
            known = {ref.segment_id for ref in segments}
            for path in sorted(self.root.glob("segment-*.log")):
                match = _SEGMENT_RE.match(path.name)
                if match and int(match.group(1)) not in known:
                    reasons.append("orphan_segment")
                    unverifiable = True
            if not self.manifest_path.exists() and known:
                reasons.append("manifest_missing")
                unverifiable = True
            expected, previous = 1, ZERO
            for ref in segments:
                if ref.compacted:
                    reasons.append("segment_compacted")
                    expected, previous = ref.last_sequence + 1, ref.last_digest
                    continue
                path = self.segment_path(ref.segment_id)
                if not path.exists():
                    reasons.append("segment_missing")
                    unverifiable = True
                    continue
                try:
                    records = self._read_records(path)
                except RotationError:
                    reasons.append("segment_digest_mismatch")
                    unverifiable = True
                    continue
                if (len(records) != ref.record_count
                        or records[0]["sequence"] != ref.first_sequence
                        or records[-1]["sequence"] != ref.last_sequence):
                    reasons.append("segment_bounds_mismatch")
                    unverifiable = True
                    continue
                if _segment_digest(records) != ref.segment_digest:
                    reasons.append("segment_digest_mismatch")
                    unverifiable = True
                    continue
                if records[0]["sequence"] != expected or records[0]["previous_digest"] != previous:
                    reasons.append("segment_chain_mismatch")
                    unverifiable = True
                    continue
                expected, previous = records[-1]["sequence"] + 1, records[-1]["record_digest"]
            try:
                active = self._read_records(self.active_path)
            except RotationError:
                reasons.append("active_segment_corrupt")
                unverifiable = True
                active = []
            for record in active:
                if record["sequence"] != expected or record["previous_digest"] != previous:
                    reasons.append("active_chain_mismatch")
                    unverifiable = True
                    break
                expected, previous = record["sequence"] + 1, record["record_digest"]
            state = "unverifiable" if unverifiable else ("digest-only" if "segment_compacted" in reasons else "replayable")
            return RotationVerdict(state, tuple(reasons), tuple(sorted(known)))


def verify_log(root: str | Path, **kwargs: Any) -> RotationVerdict:
    return SegmentedEvidenceLog(root, **kwargs).verify()


__all__ = ["MANIFEST_NAME", "RotationError", "RotationVerdict", "SCHEMA",
           "SegmentRef", "SegmentedEvidenceLog", "verify_log"]
