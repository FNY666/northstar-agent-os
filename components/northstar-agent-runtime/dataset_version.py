"""DVC-style dataset versioning: content-addressed commits, diffs, checkouts.

A dataset version store answers "which bytes were the dataset at step N,
what changed between N and M, and can I go back?". Each :meth:`DatasetVersion.commit`
binds a frozen dataset snapshot to a ``sha256:`` content digest; the
store keeps the full ordered version log, and the digest chain is
re-verifiable by :meth:`DatasetVersion.verify`.

Datasets are mappings or sequences of canonicalizable values. A
``commit`` never stores the caller's object by reference -- the store
canonicalizes and digests the payload, then keeps an internal
normalized copy. :meth:`DatasetVersion.checkout` hands back a fresh
deep copy, so two checkouts of the same version never alias, and
mutating a checkout can never move a pinned digest.

:meth:`DatasetVersion.diff` is structural, not textual: for mappings
it reports ``added`` / ``removed`` / ``changed`` keys (a changed value
carries both sides); for sequences it reports positional ``changed``
indices plus ``appended``/``truncated`` tails. Comparing two versions
of different shapes (mapping vs sequence) is refused -- the diff would
be meaningless, and refusing loudly beats inventing one.

Canonicalization reuses ``canonical_json`` when importable (falling
back to a local type-tagged encoder, same caveat: integral floats
beyond 2**53 cannot round-trip through JSON and are refused
fail-closed, mirroring ``secure_aggregation``'s ``_hexint`` guidance).

Honest scope: this is *version bookkeeping*, not a storage engine. It
proves that version N holds these digests and that diff(N, M) is the
structural difference -- it cannot prove the committed payloads were
true (the host chose them), cannot detect an uncommitted change (only
committed snapshots exist), and cannot bound who saw intermediate
versions. State is in-memory; persistence is the host's job.
"""

from __future__ import annotations

import copy
import hashlib
import math
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple


#: Version pin for this module's record shape.
DATASET_VERSION_VERSION = "dataset-version.v1"

#: Schema pin carried on audit records.
DATASET_VERSION_SCHEMA = "northstar.dataset-version.v1"

#: Largest integer exactly representable in a JSON float.
_MAX_SAFE_INTEGER = 2**53


try:  # Prefer the shared canonicalizer; fall back to a local encoder.
    from canonical_json import canonical_json as _canonical_json

    def _encode(value: Any) -> bytes:
        return _canonical_json(value).encode("utf-8")

except Exception:  # pragma: no cover - defensive fallback only
    _TAG_STR = b"\x01"
    _TAG_BYTES = b"\x02"
    _TAG_INT = b"\x03"
    _TAG_FLOAT = b"\x04"
    _TAG_BOOL = b"\x05"
    _TAG_NULL = b"\x06"
    _TAG_LIST = b"\x07"
    _TAG_MAP = b"\x08"

    def _encode(value: Any) -> bytes:
        if value is None:
            return _TAG_NULL
        if isinstance(value, bool):
            return _TAG_BOOL + (b"\x01" if value else b"\x00")
        if isinstance(value, int):
            return _TAG_INT + str(value).encode("ascii")
        if isinstance(value, float):
            if math.isnan(value) or math.isinf(value):
                raise DatasetVersionError("NaN/inf cannot be canonicalized")
            if value.is_integer() and abs(value) > _MAX_SAFE_INTEGER:
                raise DatasetVersionError(
                    "integral float beyond 2**53 cannot be canonicalized"
                )
            return _TAG_FLOAT + repr(value).encode("ascii")
        if isinstance(value, str):
            return _TAG_STR + value.encode("utf-8")
        if isinstance(value, (bytes, bytearray)):
            return _TAG_BYTES + bytes(value)
        if isinstance(value, Mapping):
            parts = b""
            for key in sorted(value.keys(), key=str):
                if not isinstance(key, str):
                    raise DatasetVersionError("mapping keys must be str")
                parts += _encode(key) + _encode(value[key])
            return _TAG_MAP + parts
        if isinstance(value, (list, tuple)):
            parts = b""
            for item in value:
                parts += _encode(item)
            return _TAG_LIST + parts
        raise DatasetVersionError(f"uncannonicalizable type {type(value).__name__}")


class DatasetVersionError(Exception):
    """Base error for dataset-versioning failures."""


class UnknownVersionError(DatasetVersionError):
    """Raised when a version index names no committed version."""


def _digest_of(value: Any) -> str:
    """Content digest pin (``sha256:``) of a canonicalized value."""
    return "sha256:" + hashlib.sha256(b"dataset-version.v1:" + _encode(value)).hexdigest()


def _normalize(value: Any) -> Any:
    """Validate + normalize a dataset payload (mappings or sequences)."""
    if isinstance(value, Mapping):
        out: Dict[str, Any] = {}
        for key in value.keys():
            if not isinstance(key, str):
                raise DatasetVersionError("dataset mapping keys must be str")
            if isinstance(key, bool):
                raise DatasetVersionError("dataset mapping keys must be str")
            if not key:
                raise DatasetVersionError("dataset mapping keys must be non-empty")
            out[key] = value[key]
        # Re-encode to fail closed on any nested non-canonicalizable value.
        _encode(value)
        return dict(out)
    if isinstance(value, (list, tuple)):
        _encode(list(value))
        return list(value)
    if value is None:
        raise DatasetVersionError("dataset cannot be None")
    if isinstance(value, bool):
        raise DatasetVersionError("dataset must be a mapping or sequence")
    raise DatasetVersionError("dataset must be a mapping or sequence")


@dataclass(frozen=True)
class VersionRecord:
    """One committed snapshot: index, digest pin, and committing seq."""

    version: int
    digest: str
    seq: int
    shape: str  # "mapping" or "sequence"

    def __post_init__(self) -> None:
        if isinstance(self.version, bool) or not isinstance(self.version, int):
            raise TypeError("version must be an int")
        if self.version < 0:
            raise ValueError("version must be non-negative")
        if not isinstance(self.digest, str) or not self.digest.startswith("sha256:"):
            raise ValueError("digest must be a sha256: pin")
        if isinstance(self.seq, bool) or not isinstance(self.seq, int) or self.seq < 0:
            raise ValueError("seq must be a non-negative int")
        if self.shape not in ("mapping", "sequence"):
            raise ValueError("shape must be 'mapping' or 'sequence'")

    def as_dict(self) -> dict:
        return {
            "schema": DATASET_VERSION_SCHEMA,
            "version": self.version,
            "digest": self.digest,
            "seq": self.seq,
            "shape": self.shape,
        }


@dataclass(frozen=True)
class KeyChange:
    """One changed mapping key: old and new values."""

    key: str
    old: Any
    new: Any

    def __post_init__(self) -> None:
        if not isinstance(self.key, str) or not self.key:
            raise ValueError("key must be a non-empty str")


@dataclass(frozen=True)
class DatasetDiff:
    """Structural difference between two versions of the same shape."""

    from_version: int
    to_version: int
    shape: str
    # Mapping diffs:
    added: Tuple[str, ...] = field(default=())
    removed: Tuple[str, ...] = field(default=())
    changed: Tuple[KeyChange, ...] = field(default=())
    # Sequence diffs (positional):
    changed_indices: Tuple[int, ...] = field(default=())
    appended: Tuple[int, ...] = field(default=())  # indices present only in `to`
    truncated: Tuple[int, ...] = field(default=())  # indices present only in `from`
    digest: str = ""

    def __post_init__(self) -> None:
        for name in ("from_version", "to_version"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be a non-negative int")
        if self.shape not in ("mapping", "sequence"):
            raise ValueError("shape must be 'mapping' or 'sequence'")
        if self.digest and not self.digest.startswith("sha256:"):
            raise ValueError("digest must be a sha256: pin")

    def is_empty(self) -> bool:
        """True when the two versions are structurally identical."""
        return not (
            self.added
            or self.removed
            or self.changed
            or self.changed_indices
            or self.appended
            or self.truncated
        )

    def as_dict(self) -> dict:
        return {
            "schema": DATASET_VERSION_SCHEMA,
            "from_version": self.from_version,
            "to_version": self.to_version,
            "shape": self.shape,
            "added": list(self.added),
            "removed": list(self.removed),
            "changed": [
                {"key": c.key, "old": c.old, "new": c.new} for c in self.changed
            ],
            "changed_indices": list(self.changed_indices),
            "appended": list(self.appended),
            "truncated": list(self.truncated),
            "digest": self.digest,
        }


class DatasetVersion:
    """Content-addressed, append-only version log for datasets."""

    def __init__(self, label: str) -> None:
        if not isinstance(label, str) or not label:
            raise DatasetVersionError("label must be a non-empty str")
        self._label = label
        self._snapshots: list = []  # normalized payloads, index == version
        self._records: list = []  # VersionRecord per snapshot

    def __len__(self) -> int:
        return len(self._records)

    @staticmethod
    def _check_seq(seq: int) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise DatasetVersionError("seq must be a non-negative int")

    @staticmethod
    def _shape_of(value: Any) -> str:
        return "mapping" if isinstance(value, Mapping) else "sequence"

    def commit(self, data: Any, seq: int) -> VersionRecord:
        """Freeze `data` as the next version; return its record."""
        self._check_seq(seq)
        normalized = _normalize(data)
        digest = _digest_of(normalized)
        record = VersionRecord(
            version=len(self._records),
            digest=digest,
            seq=seq,
            shape=self._shape_of(normalized),
        )
        self._snapshots.append(normalized)
        self._records.append(record)
        return record

    def _require(self, version: int) -> Tuple[Any, VersionRecord]:
        if isinstance(version, bool) or not isinstance(version, int):
            raise TypeError("version must be an int")
        if version < 0 or version >= len(self._records):
            raise UnknownVersionError(f"no such version {version}")
        return self._snapshots[version], self._records[version]

    def record(self, version: int) -> VersionRecord:
        """Return the record for a committed version."""
        return self._require(version)[1]

    def versions(self) -> Tuple[VersionRecord, ...]:
        """All committed version records, oldest first."""
        return tuple(self._records)

    def checkout(self, version: int) -> Any:
        """Return a fresh deep copy of the snapshot at `version`."""
        snapshot, _ = self._require(version)
        return copy.deepcopy(snapshot)

    def verify(self) -> bool:
        """Recompute every digest; False on the first mismatch."""
        for snapshot, record in zip(self._snapshots, self._records):
            if _digest_of(snapshot) != record.digest:
                return False
        return True

    def diff(self, v1: int, v2: int) -> DatasetDiff:
        """Structural diff between two committed versions."""
        snap1, rec1 = self._require(v1)
        snap2, rec2 = self._require(v2)
        if rec1.shape != rec2.shape:
            raise DatasetVersionError(
                f"cannot diff {rec1.shape} against {rec2.shape}"
            )
        if rec1.shape == "mapping":
            keys1 = set(snap1.keys())
            keys2 = set(snap2.keys())
            added = tuple(sorted(keys2 - keys1))
            removed = tuple(sorted(keys1 - keys2))
            changed = tuple(
                KeyChange(key=k, old=snap1[k], new=snap2[k])
                for k in sorted(keys1 & keys2)
                if _digest_of(snap1[k]) != _digest_of(snap2[k])
            )
            diff = DatasetDiff(
                from_version=v1,
                to_version=v2,
                shape="mapping",
                added=added,
                removed=removed,
                changed=changed,
            )
        else:
            n1, n2 = len(snap1), len(snap2)
            overlap = min(n1, n2)
            changed_indices = tuple(
                i
                for i in range(overlap)
                if _digest_of(snap1[i]) != _digest_of(snap2[i])
            )
            appended = tuple(range(n1, n2)) if n2 > n1 else ()
            truncated = tuple(range(n2, n1)) if n1 > n2 else ()
            diff = DatasetDiff(
                from_version=v1,
                to_version=v2,
                shape="sequence",
                changed_indices=changed_indices,
                appended=appended,
                truncated=truncated,
            )
        digest = "sha256:" + hashlib.sha256(
            ("dataset-version.v1:diff:" + repr(diff.as_dict())).encode("utf-8")
        ).hexdigest()
        object.__setattr__(diff, "digest", digest)
        return diff


def dataset_version_audit_event(kind: str, seq: int, **kwargs: Any) -> dict:
    """Shape a dataset-versioning lifecycle event as an ``audit.ndjson/1`` record."""
    valid = ("committed", "checked-out", "diffed", "verified", "rejected")
    if kind not in valid:
        raise ValueError(f"unknown audit kind {kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise ValueError("seq must be a non-negative int")
    event = {
        "schema": "audit.ndjson/1",
        "kind": f"dataset-version.{kind}",
        "module": DATASET_VERSION_SCHEMA,
        "version": DATASET_VERSION_VERSION,
        "seq": seq,
    }
    for key in ("label", "version", "digest", "from_version", "to_version"):
        if key in kwargs:
            event[key] = kwargs[key]
    return event


def main() -> None:
    store = DatasetVersion("demo")
    r0 = store.commit({"a": 1, "b": 2}, 0)
    r1 = store.commit({"a": 1, "b": 3, "c": 4}, 1)
    assert r0.version == 0 and r1.version == 1
    assert r0.digest != r1.digest
    d = store.diff(0, 1)
    assert d.added == ("c",)
    assert d.removed == ()
    assert len(d.changed) == 1 and d.changed[0].key == "b"
    assert store.diff(0, 0).is_empty() is True
    snap = store.checkout(0)
    assert snap == {"a": 1, "b": 2}
    snap["a"] = 999
    assert store.checkout(0) == {"a": 1, "b": 2}  # no aliasing
    assert store.verify() is True
    seq_store = DatasetVersion("seq")
    seq_store.commit([1, 2, 3], 0)
    seq_store.commit([1, 9, 3, 4], 1)
    sd = seq_store.diff(0, 1)
    assert sd.changed_indices == (1,)
    assert sd.appended == (3,)
    assert sd.truncated == ()
    print("dataset-version OK: commit, diff, checkout, verify")


if __name__ == "__main__":
    main()
