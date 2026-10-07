"""LSM tree: write-optimized key/value store (memtable + immutable SSTables).

Research note: log-structured merge trees (O'Neil et al. 1996; LevelDB,
RocksDB, Cassandra) trade read amplification for write throughput — writes
land in an in-memory memtable and are flushed as immutable sorted runs
(SSTables) that are later merged by compaction. For an agent runtime this
is the natural shape of the *write-ahead* side of durable state: the
durable audit writer (see :mod:`audit_durability`) owns crash recovery;
this module owns the *indexing* contract — point lookups over a
write-heavy key space with explicit deletion semantics.

* **Memtable first** — every ``put``/``delete`` lands in the memtable.
  Reads check the memtable before any SSTable, so the freshest write
  always wins.
* **Flush on threshold** — when the memtable exceeds
  ``memtable_entry_threshold`` entries it is frozen into an immutable
  SSTable (newest first). Flushing is deterministic and caller-driven;
  there is no background thread.
* **Tombstones** — ``delete`` writes a tombstone marker, not a removal.
  A tombstone in the memtable or a newer SSTable hides the value in all
  older SSTables. Tombstones are reclaimed only by ``compact``.
* **Compaction** — merges every SSTable into one, keeping the newest
  live value per key and dropping tombstones and shadowed entries.
  The merge is total and deterministic (sorted key order).
* **No wall-clock** — all sequencing is caller-supplied integers; the
  module is deterministic and replayable.
* **Fail-closed** — empty or non-string keys, non-bytes/str values and
  malformed inputs raise; a ``get`` on a missing key returns ``None``,
  never a default.

Honest scope: this is the *state machine* of an LSM tree, not a storage
engine — it is in-memory (host snapshots for crash recovery), has no
WAL of its own (pair with the durable audit writer for that), no bloom
filters over SSTables, no leveled compaction tiers, and no concurrency
control beyond a re-entrant lock around public methods. A ``get``
returns the newest *recorded* value, never proof the key was durably
stored.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Dict, List, Mapping, Optional, Tuple, Union

#: Module version.
LSM_TREE_VERSION = "lsm-tree.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.lsm-tree.v1"

#: Tombstone marker for deleted keys. Never exposed to callers as a value.
_TOMBSTONE = b"\x00__lsm_tombstone__\x00"


class LSMTreeError(Exception):
    """Malformed input to the LSM tree (programming error)."""


def _check_key(key: object) -> str:
    if isinstance(key, bool) or not isinstance(key, str):
        raise LSMTreeError(f"key must be a non-empty str, got {type(key).__name__}")
    if not key:
        raise LSMTreeError("key must be non-empty")
    return key


def _check_value(value: object) -> bytes:
    if isinstance(value, bool):
        raise LSMTreeError("value must be bytes or str, not bool")
    if isinstance(value, str):
        return value.encode("utf-8")
    if isinstance(value, bytes):
        return value
    raise LSMTreeError(f"value must be bytes or str, got {type(value).__name__}")


def _check_seq(seq: object) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise LSMTreeError(f"seq must be a non-negative int, got {seq!r}")
    return seq


def _digest(entries: Tuple[Tuple[str, bytes], ...]) -> str:
    body = "\x00".join(f"{k}\x01{v.hex()}" for k, v in entries)
    return "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class SSTable:
    """One immutable sorted run.

    ``entries`` is sorted by key ascending. Tombstoned entries are kept
    until compaction; they shadow older runs.
    """

    table_id: str
    entries: Tuple[Tuple[str, bytes], ...]
    created_seq: int
    digest: str

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "table_id": self.table_id,
            "entry_count": len(self.entries),
            "created_seq": self.created_seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class CompactionReport:
    """Outcome of one ``compact`` call."""

    tables_merged: int
    live_keys: int
    tombstones_dropped: int
    shadowed_dropped: int
    new_digest: str
    seq: int

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "tables_merged": self.tables_merged,
            "live_keys": self.live_keys,
            "tombstones_dropped": self.tombstones_dropped,
            "shadowed_dropped": self.shadowed_dropped,
            "new_digest": self.new_digest,
            "seq": self.seq,
        }


@dataclass(frozen=True)
class TreeStats:
    """Point-in-time counters."""

    puts: int
    deletes: int
    gets: int
    flushes: int
    compactions: int
    memtable_entries: int
    sstable_count: int
    live_keys: int

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "puts": self.puts,
            "deletes": self.deletes,
            "gets": self.gets,
            "flushes": self.flushes,
            "compactions": self.compactions,
            "memtable_entries": self.memtable_entries,
            "sstable_count": self.sstable_count,
            "live_keys": self.live_keys,
        }


def lsm_audit_event(kind: str, seq: int, detail: Optional[Mapping[str, object]] = None) -> dict:
    """Shape an ``audit.ndjson/1``-style record for an LSM tree event."""
    _check_seq(seq)
    if kind not in ("put", "delete", "get", "flush", "compact"):
        raise LSMTreeError(f"unknown audit kind: {kind!r}")
    event = {
        "schema": SCHEMA_PIN,
        "kind": f"lsm-{kind}",
        "audit_seq": seq,
    }
    if detail is not None:
        event["detail"] = dict(detail)
    return event


class LSMTree:
    """Write-optimized key/value store: memtable + immutable SSTables."""

    def __init__(self, memtable_entry_threshold: int = 100) -> None:
        if isinstance(memtable_entry_threshold, bool) or not isinstance(
            memtable_entry_threshold, int
        ):
            raise LSMTreeError("memtable_entry_threshold must be an int")
        if memtable_entry_threshold < 1:
            raise LSMTreeError("memtable_entry_threshold must be >= 1")
        self._threshold = memtable_entry_threshold
        self._memtable: Dict[str, bytes] = {}
        self._sstables: List[SSTable] = []  # newest first
        self._lock = threading.RLock()
        self._puts = 0
        self._deletes = 0
        self._gets = 0
        self._flushes = 0
        self._compactions = 0
        self._table_seq = 0

    def put(self, key: str, value: Union[str, bytes]) -> None:
        """Write a key. Overwrites any previous value (memtable or SSTable)."""
        key = _check_key(key)
        raw = _check_value(value)
        with self._lock:
            self._memtable[key] = raw
            self._puts += 1
            if len(self._memtable) >= self._threshold:
                self._flush_locked()

    def delete(self, key: str) -> None:
        """Delete a key by writing a tombstone. Idempotent."""
        key = _check_key(key)
        with self._lock:
            self._memtable[key] = _TOMBSTONE
            self._deletes += 1
            if len(self._memtable) >= self._threshold:
                self._flush_locked()

    def get(self, key: str) -> Optional[bytes]:
        """Newest value for ``key``, or ``None`` if absent or deleted."""
        key = _check_key(key)
        with self._lock:
            self._gets += 1
            if key in self._memtable:
                value = self._memtable[key]
                return None if value == _TOMBSTONE else value
            for table in self._sstables:
                value = _lookup_sorted(table.entries, key)
                if value is not None:
                    return None if value == _TOMBSTONE else value
            return None

    def flush(self) -> Optional[SSTable]:
        """Force the memtable into a new SSTable. Returns None if empty."""
        with self._lock:
            return self._flush_locked()

    def _flush_locked(self) -> Optional[SSTable]:
        if not self._memtable:
            return None
        entries = tuple(sorted(self._memtable.items()))
        self._table_seq += 1
        table = SSTable(
            table_id=f"sstable-{self._table_seq:06d}",
            entries=entries,
            created_seq=self._table_seq,
            digest=_digest(entries),
        )
        self._sstables.insert(0, table)
        self._memtable = {}
        self._flushes += 1
        return table

    def compact(self, seq: int = 0) -> CompactionReport:
        """Merge all SSTables into one; drop tombstones and shadowed entries."""
        _check_seq(seq)
        with self._lock:
            merged = len(self._sstables)
            if merged == 0:
                return CompactionReport(
                    tables_merged=0,
                    live_keys=0,
                    tombstones_dropped=0,
                    shadowed_dropped=0,
                    new_digest=_digest(()),
                    seq=seq,
                )
            # Newest run wins per key: walk newest-first, first sighting sticks.
            seen: Dict[str, bytes] = {}
            tombstones = 0
            shadowed = 0
            for table in self._sstables:
                for key, value in table.entries:
                    if key in seen:
                        shadowed += 1
                        continue
                    seen[key] = value
                    if value == _TOMBSTONE:
                        tombstones += 1
            live = tuple(
                sorted((k, v) for k, v in seen.items() if v != _TOMBSTONE)
            )
            self._table_seq += 1
            table = SSTable(
                table_id=f"sstable-{self._table_seq:06d}",
                entries=live,
                created_seq=self._table_seq,
                digest=_digest(live),
            )
            self._sstables = [table]
            self._compactions += 1
            return CompactionReport(
                tables_merged=merged,
                live_keys=len(live),
                tombstones_dropped=tombstones,
                shadowed_dropped=shadowed,
                new_digest=table.digest,
                seq=seq,
            )

    def stats(self) -> TreeStats:
        """Point-in-time counters (frozen)."""
        with self._lock:
            live_keys = len({k for k in self._memtable if self._memtable[k] != _TOMBSTONE})
            for table in self._sstables:
                live_keys += sum(1 for _, v in table.entries if v != _TOMBSTONE)
            return TreeStats(
                puts=self._puts,
                deletes=self._deletes,
                gets=self._gets,
                flushes=self._flushes,
                compactions=self._compactions,
                memtable_entries=len(self._memtable),
                sstable_count=len(self._sstables),
                live_keys=live_keys,
            )


def _lookup_sorted(entries: Tuple[Tuple[str, bytes], ...], key: str) -> Optional[bytes]:
    """Binary search over a sorted SSTable run."""
    lo, hi = 0, len(entries)
    while lo < hi:
        mid = (lo + hi) // 2
        if entries[mid][0] < key:
            lo = mid + 1
        else:
            hi = mid
    if lo < len(entries) and entries[lo][0] == key:
        return entries[lo][1]
    return None


def main() -> None:
    tree = LSMTree(memtable_entry_threshold=2)
    tree.put("a", "1")
    tree.put("b", "2")  # triggers flush (threshold 2)
    assert tree.get("a") == b"1"
    tree.put("a", "3")
    tree.delete("b")
    assert tree.get("b") is None  # tombstone hides flushed value
    report = tree.compact(seq=1)
    assert report.live_keys == 1
    assert tree.get("a") == b"3"
    print("lsm-tree OK: put/get/delete, flush, tombstone, compact")


if __name__ == "__main__":
    main()
