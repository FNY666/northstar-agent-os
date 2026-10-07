"""Partition manager: range-based sharding bookkeeping (split/merge/route).

Research note: range sharding (Kafka topic partitions, DynamoDB partition
ranges, Cosmos DB physical partitions) divides a key space into
contiguous, non-overlapping ranges. Each partition owns ``[key_low,
key_high)``; ``split`` divides a hot range at an interior key and
``merge`` reunites two *adjacent* ranges. Routing is a deterministic
ledger decision, not data movement — the host migrates bytes, this
module books who owns what.

* **Contiguous non-overlapping ranges** — the manager refuses to create
  a range that overlaps an existing one fail-closed. A key is owned by
  exactly one live partition, ever.
* **Split is interior-only** — the split key must satisfy
  ``key_low < split_key < key_high`` (strict). Splitting at a boundary
  or outside the range is refused; one of the children would be empty.
* **Merge is adjacency-only** — the two partitions must be exactly
  adjacent (``left.key_high == right.key_low``); merging gapped or
  overlapping ranges is refused. The merged partition owns the union.
* **Retired ids are never recycled** — split/merge retire their inputs;
  a retired id can never be re-created or re-used (operator replay
  safety).
* **Fail-closed** — malformed ids/keys, overlaps, non-adjacency,
  unknown ids, and out-of-order seqs raise
  (:class:`PartitionManagerError` and friends). Routing a key with no
  covering partition raises instead of defaulting to nowhere.
* **No wall-clock** — all sequencing is caller-supplied strictly
  increasing ``seq`` ints; failed mutations consume their seq so the
  ledger stays total.

Distinct from :mod:`consistent_hash` (hash-ring key-to-node placement):
this module owns *range topology* — who owns which key interval — while
the ring owns *point placement*. Both are routing instruments for the
host; neither moves data.

Honest scope: ``route`` answers "which partition id owns this key" from
the booked ranges; it cannot prove the partition's data is healthy, the
host applied the routing decision, or the key range maps to a real
store. A ``PartitionRecord`` books a *declared* range, never wire
truth. Cross-restart persistence is the host's job; this module holds
state in memory.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, Mapping, NoReturn, Tuple

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    _cj = None  # type: ignore

#: Module version pin for this module's record shape.
PARTITION_MANAGER_VERSION = "partition-manager.v1"

#: Schema pin carried by records.
PARTITION_MANAGER_SCHEMA = "northstar.partition-manager.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Digest prefix for all pins minted by this module.
_DIGEST_PREFIX = "sha256:"

#: Domain separator so partition pins cannot collide with other digests.
_DIGEST_DOMAIN = b"northstar.partition-manager.v1\x00"

#: Largest key string accepted (defensive cap; keys are booked, not streamed).
_MAX_KEY_LEN = 1024


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class PartitionManagerError(Exception):
    """Malformed input to the partition manager (programming error)."""


class BadPartitionError(PartitionManagerError):
    """Partition id or key bounds failed validation."""


class DuplicatePartitionError(PartitionManagerError):
    """Partition id already exists (or was retired)."""


class UnknownPartitionError(PartitionManagerError):
    """No live partition with that id."""


class OverlapError(PartitionManagerError):
    """New range overlaps an existing partition's range."""


class NotAdjacentError(PartitionManagerError):
    """Merge targets are not exactly adjacent."""


class BadSplitKeyError(PartitionManagerError):
    """Split key is not strictly inside the partition range."""


class NoCoverageError(PartitionManagerError):
    """No live partition covers the routed key."""


class SeqOrderError(PartitionManagerError):
    """Caller seq did not strictly increase."""


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _check_seq(value: Any, field_name: str = "seq") -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SeqOrderError(f"{field_name} must be a non-negative int")
    return value


def _check_partition_id(value: Any, field_name: str = "partition_id") -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadPartitionError(f"{field_name} must be a str")
    if not value or len(value) > _MAX_KEY_LEN:
        raise BadPartitionError(f"{field_name} must be non-empty (<= {_MAX_KEY_LEN} chars)")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
        raise BadPartitionError(f"{field_name} must not contain control characters")
    return value


def _check_key(value: Any, field_name: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadPartitionError(f"{field_name} must be a str")
    if len(value) > _MAX_KEY_LEN:
        raise BadPartitionError(f"{field_name} exceeds {_MAX_KEY_LEN} chars")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
        raise BadPartitionError(f"{field_name} must not contain control characters")
    return value


def _canonical(payload: Mapping[str, Any]) -> bytes:
    """Canonical bytes for digest pinning (JCS when available)."""
    if _cj is not None:
        try:
            return _cj.dumps(dict(payload)).encode("utf-8")  # type: ignore[attr-defined]
        except Exception:
            pass
    items = sorted(payload.items())
    return repr(items).encode("utf-8")


def _pin(payload: Mapping[str, Any]) -> str:
    digest = hashlib.sha256(_DIGEST_DOMAIN + _canonical(payload)).hexdigest()
    return _DIGEST_PREFIX + digest


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PartitionRecord:
    """One live partition's booked range ``[key_low, key_high)``."""

    partition_id: str
    key_low: str
    key_high: str
    seq: int
    prev_digest: str
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "partition_id": self.partition_id,
            "key_low": self.key_low,
            "key_high": self.key_high,
            "seq": self.seq,
            "prev_digest": self.prev_digest,
            "digest": self.digest,
            "schema": PARTITION_MANAGER_SCHEMA,
            "module_version": PARTITION_MANAGER_VERSION,
        }

    def verify(self) -> bool:
        """Recompute the digest pin; ``False`` means tamper/mutation."""
        expected = _pin(
            {
                "partition_id": self.partition_id,
                "key_low": self.key_low,
                "key_high": self.key_high,
                "seq": self.seq,
                "prev_digest": self.prev_digest,
            }
        )
        return expected == self.digest


@dataclass(frozen=True)
class SplitRecord:
    """A split mutation: ``parent`` retired, ``left``/``right`` created."""

    parent_id: str
    left_id: str
    right_id: str
    split_key: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "parent_id": self.parent_id,
            "left_id": self.left_id,
            "right_id": self.right_id,
            "split_key": self.split_key,
            "seq": self.seq,
            "digest": self.digest,
            "schema": PARTITION_MANAGER_SCHEMA,
            "module_version": PARTITION_MANAGER_VERSION,
        }


@dataclass(frozen=True)
class MergeRecord:
    """A merge mutation: ``left``/``right`` retired, ``merged_id`` created."""

    left_id: str
    right_id: str
    merged_id: str
    key_low: str
    key_high: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "left_id": self.left_id,
            "right_id": self.right_id,
            "merged_id": self.merged_id,
            "key_low": self.key_low,
            "key_high": self.key_high,
            "seq": self.seq,
            "digest": self.digest,
            "schema": PARTITION_MANAGER_SCHEMA,
            "module_version": PARTITION_MANAGER_VERSION,
        }


@dataclass(frozen=True)
class RouteReport:
    """Pure read view: which live partition owns ``key``."""

    key: str
    partition_id: str
    key_low: str
    key_high: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "partition_id": self.partition_id,
            "key_low": self.key_low,
            "key_high": self.key_high,
        }


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


KIND_CREATED = "partition-manager.partition-created"
KIND_SPLIT = "partition-manager.partition-split"
KIND_MERGED = "partition-manager.partition-merged"
KIND_REJECTED = "partition-manager.rejected"
_KINDS = (KIND_CREATED, KIND_SPLIT, KIND_MERGED, KIND_REJECTED)

#: Detail keys banned from the audit boundary (raw keys stay local).
_BANNED_DETAIL_KEYS = {"key"}


def partition_manager_audit_event(
    kind: str, seq: int, **detail: Any
) -> Mapping[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the partition manager.

    Raw routed keys are banned from the audit boundary — only partition
    ids, range bounds, and digest pins cross it.
    """
    if kind not in _KINDS:
        raise PartitionManagerError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    banned = _BANNED_DETAIL_KEYS.intersection(detail)
    if banned:
        raise PartitionManagerError(
            f"detail carries banned keys: {sorted(banned)}"
        )
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": "partition-manager",
        "module_version": PARTITION_MANAGER_VERSION,
        "seq": seq,
        "detail": dict(detail),
    }


# ---------------------------------------------------------------------------
# PartitionManager
# ---------------------------------------------------------------------------


class PartitionManager:
    """Deterministic range-sharding bookkeeping (split/merge/route).

    All mutations require a caller-supplied strictly increasing ``seq``.
    Failed mutations consume their seq (ledger position stays total).
    Reads validate the seq shape but do not consume it and write no
    audit rows.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        self._partitions: Dict[str, PartitionRecord] = {}
        self._retired: set[str] = set()
        self._split_records: list[SplitRecord] = []
        self._merge_records: list[MergeRecord] = []
        self._audit: list[Mapping[str, Any]] = []

    # -- seq discipline ---------------------------------------------------

    def _claim(self, seq: int) -> int:
        seq = _check_seq(seq)
        with self._lock:
            if seq <= self._last_seq:
                raise SeqOrderError(
                    f"seq must strictly increase (last={self._last_seq}, got={seq})"
                )
            self._last_seq = seq
        return seq

    def _fail(
        self, seq: int, exc: PartitionManagerError, **detail: Any
    ) -> "NoReturn":
        """Book a rejection audit row, then raise the given error."""
        # ``seq`` is already claimed by the caller path; record the refusal.
        with self._lock:
            self._audit.append(
                partition_manager_audit_event(
                    KIND_REJECTED, seq, reason=str(exc), **detail
                )
            )
        raise exc

    # -- views ------------------------------------------------------------

    def partition(self, partition_id: str) -> PartitionRecord:
        """Pure read view of one live partition."""
        _check_partition_id(partition_id)
        with self._lock:
            try:
                return self._partitions[partition_id]
            except KeyError:
                raise UnknownPartitionError(
                    f"no live partition: {partition_id!r}"
                ) from None

    def partition_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._partitions))

    def retired_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._retired))

    def stats(self) -> Mapping[str, Any]:
        with self._lock:
            return {
                "live_partitions": len(self._partitions),
                "retired_partitions": len(self._retired),
                "splits": len(self._split_records),
                "merges": len(self._merge_records),
                "audit_rows": len(self._audit),
                "last_seq": self._last_seq,
            }

    def audit_log(self) -> Tuple[Mapping[str, Any], ...]:
        with self._lock:
            return tuple(self._audit)

    # -- mutations --------------------------------------------------------

    def create(
        self, partition_id: str, key_low: str, key_high: str, seq: int
    ) -> PartitionRecord:
        """Book a new partition owning ``[key_low, key_high)``.

        The range must not overlap any live partition; retired ids are
        never recycled.
        """
        partition_id = _check_partition_id(partition_id)
        key_low = _check_key(key_low, "key_low")
        key_high = _check_key(key_high, "key_high")
        seq = self._claim(seq)
        if not key_low < key_high:
            self._fail(
                seq,
                BadPartitionError("key_low must be strictly less than key_high"),
                partition_id=partition_id,
            )
        with self._lock:
            if partition_id in self._partitions or partition_id in self._retired:
                self._fail(
                    seq,
                    DuplicatePartitionError(
                        f"partition id already used or retired: {partition_id!r}"
                    ),
                    partition_id=partition_id,
                )
            for existing in self._partitions.values():
                # Overlap iff low < existing.high and existing.low < high.
                if key_low < existing.key_high and existing.key_low < key_high:
                    self._fail(
                        seq,
                        OverlapError(
                            f"range [{key_low!r}, {key_high!r}) overlaps "
                            f"partition {existing.partition_id!r}"
                        ),
                        partition_id=partition_id,
                        overlaps=existing.partition_id,
                    )
            prev = self._last_chain_digest()
            record = PartitionRecord(
                partition_id=partition_id,
                key_low=key_low,
                key_high=key_high,
                seq=seq,
                prev_digest=prev,
                digest=_pin(
                    {
                        "partition_id": partition_id,
                        "key_low": key_low,
                        "key_high": key_high,
                        "seq": seq,
                        "prev_digest": prev,
                    }
                ),
            )
            self._partitions[partition_id] = record
            self._audit.append(
                partition_manager_audit_event(
                    KIND_CREATED,
                    seq,
                    partition_id=partition_id,
                    key_low=key_low,
                    key_high=key_high,
                    digest=record.digest,
                )
            )
            return record

    def split(
        self,
        partition_id: str,
        left_id: str,
        right_id: str,
        split_key: str,
        seq: int,
    ) -> Tuple[PartitionRecord, PartitionRecord]:
        """Split ``partition_id`` at ``split_key`` into ``left``/``right``.

        Children own ``[low, split_key)`` and ``[split_key, high)``; the
        parent is retired (never recycled).
        """
        partition_id = _check_partition_id(partition_id)
        left_id = _check_partition_id(left_id, "left_id")
        right_id = _check_partition_id(right_id, "right_id")
        split_key = _check_key(split_key, "split_key")
        seq = self._claim(seq)
        with self._lock:
            parent = self._partitions.get(partition_id)
            if parent is None:
                self._fail(
                    seq,
                    UnknownPartitionError(f"no live partition: {partition_id!r}"),
                    partition_id=partition_id,
                )
            if not parent.key_low < split_key < parent.key_high:
                self._fail(
                    seq,
                    BadSplitKeyError(
                        f"split_key must be strictly inside "
                        f"[{parent.key_low!r}, {parent.key_high!r})"
                    ),
                    partition_id=partition_id,
                )
            for child_id, field in ((left_id, "left_id"), (right_id, "right_id")):
                if child_id in self._partitions or child_id in self._retired:
                    self._fail(
                        seq,
                        DuplicatePartitionError(
                            f"{field} already used or retired: {child_id!r}"
                        ),
                        partition_id=partition_id,
                        child_id=child_id,
                    )
            if left_id == right_id:
                self._fail(
                    seq,
                    BadPartitionError("left_id and right_id must differ"),
                    partition_id=partition_id,
                )
            prev = self._last_chain_digest()
            left = PartitionRecord(
                partition_id=left_id,
                key_low=parent.key_low,
                key_high=split_key,
                seq=seq,
                prev_digest=prev,
                digest=_pin(
                    {
                        "partition_id": left_id,
                        "key_low": parent.key_low,
                        "key_high": split_key,
                        "seq": seq,
                        "prev_digest": prev,
                    }
                ),
            )
            right = PartitionRecord(
                partition_id=right_id,
                key_low=split_key,
                key_high=parent.key_high,
                seq=seq,
                prev_digest=left.digest,
                digest=_pin(
                    {
                        "partition_id": right_id,
                        "key_low": split_key,
                        "key_high": parent.key_high,
                        "seq": seq,
                        "prev_digest": left.digest,
                    }
                ),
            )
            del self._partitions[partition_id]
            self._retired.add(partition_id)
            self._partitions[left_id] = left
            self._partitions[right_id] = right
            self._split_records.append(
                SplitRecord(
                    parent_id=partition_id,
                    left_id=left_id,
                    right_id=right_id,
                    split_key=split_key,
                    seq=seq,
                    digest=_pin(
                        {
                            "parent_id": partition_id,
                            "left_id": left_id,
                            "right_id": right_id,
                            "split_key": split_key,
                            "seq": seq,
                        }
                    ),
                )
            )
            self._audit.append(
                partition_manager_audit_event(
                    KIND_SPLIT,
                    seq,
                    parent_id=partition_id,
                    left_id=left_id,
                    right_id=right_id,
                    split_key=split_key,
                    left_digest=left.digest,
                    right_digest=right.digest,
                )
            )
            return left, right

    def merge(self, left_id: str, right_id: str, merged_id: str, seq: int) -> PartitionRecord:
        """Merge two *adjacent* partitions into ``merged_id``.

        ``left`` must satisfy ``left.key_high == right.key_low`` exactly;
        both inputs are retired.
        """
        left_id = _check_partition_id(left_id, "left_id")
        right_id = _check_partition_id(right_id, "right_id")
        merged_id = _check_partition_id(merged_id, "merged_id")
        seq = self._claim(seq)
        with self._lock:
            left = self._partitions.get(left_id)
            right = self._partitions.get(right_id)
            if left is None or right is None:
                missing = left_id if left is None else right_id
                self._fail(
                    seq,
                    UnknownPartitionError(f"no live partition: {missing!r}"),
                    left_id=left_id, right_id=right_id,
                )
            if left_id == right_id:
                self._fail(
                    seq,
                    BadPartitionError("cannot merge a partition with itself"),
                    left_id=left_id, right_id=right_id,
                )
            if left.key_high != right.key_low:
                self._fail(
                    seq,
                    NotAdjacentError(
                        f"partitions not adjacent: {left_id!r} ends at "
                        f"{left.key_high!r}, {right_id!r} starts at {right.key_low!r}"
                    ),
                    left_id=left_id, right_id=right_id,
                )
            if merged_id in self._partitions or merged_id in self._retired:
                self._fail(
                    seq,
                    DuplicatePartitionError(
                        f"merged id already used or retired: {merged_id!r}"
                    ),
                    merged_id=merged_id,
                )
            prev = self._last_chain_digest()
            merged = PartitionRecord(
                partition_id=merged_id,
                key_low=left.key_low,
                key_high=right.key_high,
                seq=seq,
                prev_digest=prev,
                digest=_pin(
                    {
                        "partition_id": merged_id,
                        "key_low": left.key_low,
                        "key_high": right.key_high,
                        "seq": seq,
                        "prev_digest": prev,
                    }
                ),
            )
            del self._partitions[left_id]
            del self._partitions[right_id]
            self._retired.add(left_id)
            self._retired.add(right_id)
            self._partitions[merged_id] = merged
            self._merge_records.append(
                MergeRecord(
                    left_id=left_id,
                    right_id=right_id,
                    merged_id=merged_id,
                    key_low=merged.key_low,
                    key_high=merged.key_high,
                    seq=seq,
                    digest=_pin(
                        {
                            "left_id": left_id,
                            "right_id": right_id,
                            "merged_id": merged_id,
                            "seq": seq,
                        }
                    ),
                )
            )
            self._audit.append(
                partition_manager_audit_event(
                    KIND_MERGED,
                    seq,
                    left_id=left_id,
                    right_id=right_id,
                    merged_id=merged_id,
                    key_low=merged.key_low,
                    key_high=merged.key_high,
                    digest=merged.digest,
                )
            )
            return merged

    def route(self, key: str, seq: int) -> RouteReport:
        """Pure read view: which live partition owns ``key``.

        Bounds are ``[key_low, key_high)`` — low inclusive, high
        exclusive. Raises :class:`NoCoverageError` when no live
        partition covers the key. Consumes no seq, writes no audit row.
        """
        key = _check_key(key, "key")
        _check_seq(seq, "seq")
        with self._lock:
            for record in self._partitions.values():
                if record.key_low <= key < record.key_high:
                    return RouteReport(
                        key=key,
                        partition_id=record.partition_id,
                        key_low=record.key_low,
                        key_high=record.key_high,
                    )
        raise NoCoverageError(f"no live partition covers key {key!r}")

    # -- chain digest ---------------------------------------------------

    def _last_chain_digest(self) -> str:
        """Digest of the most recent partition record (genesis if none)."""
        # Must be called with the lock held.
        if not self._partitions and not self._split_records and not self._merge_records:
            return _DIGEST_PREFIX + "0" * 64
        chain: list[str] = []
        for record in self._partitions.values():
            chain.append(record.digest)
        return sorted(chain)[-1] if chain else _DIGEST_PREFIX + "0" * 64


def main() -> None:
    """Self-check: create, route, split, route again, merge, verify."""
    pm = PartitionManager()
    p0 = pm.create("p0", "a", "z", 0)
    assert p0.verify()
    assert pm.route("m", 1).partition_id == "p0"
    # Low inclusive, high exclusive.
    assert pm.route("a", 2).partition_id == "p0"
    left, right = pm.split("p0", "p1", "p2", "n", 3)
    assert left.key_low == "a" and left.key_high == "n"
    assert right.key_low == "n" and right.key_high == "z"
    assert pm.route("m", 4).partition_id == "p1"
    assert pm.route("n", 5).partition_id == "p2"
    merged = pm.merge("p1", "p2", "p3", 6)
    assert merged.key_low == "a" and merged.key_high == "z"
    assert pm.route("q", 7).partition_id == "p3"
    assert "p0" in pm.retired_ids() and "p1" in pm.retired_ids()
    print("partition-manager OK: create, route, split, merge, retire, pins")


if __name__ == "__main__":
    main()
