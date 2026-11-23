"""Write-through cache: every write lands on the backing store and the cache.

Research note: write-back caches acknowledge a write after touching only the
cache and defer the store write (dirty pages flush later — faster writes, but
a crash loses acknowledged data). *Write-through* does the opposite: each
``write()`` completes the backing-store write *before* it is considered
done, so the store is never stale and a crash can lose at most the cache
contents (which are just a copy). The price is write latency — every write
pays the store's cost. Classic systems material (e.g. Hennessy & Patterson,
*Computer Architecture*) frames it as the coherence-safe half of the
write-policy design space: no dirty state, no flush protocol, no ambiguity
about what the store holds.

* **Atomic visibility** — ``write(key, value, seq)`` is all-or-nothing.
  The store write goes first; if it fails, the cache is left untouched and
  :class:`StoreError` is raised. A successful ``write`` means the store and
  the cache agree on the value — there is never a window where the cache
  has a value the store lacks.
* **Read-through** — ``read(key, seq)`` serves from the cache on a hit. On
  a miss it consults the store, populates the cache (evicting the
  least-recently-used entry when full), and returns the value; a store miss
  is returned as data (``hit=False``), never raised.
* **Coherence audit** — ``sync(seq)`` walks the cache and re-checks every
  cached entry against the store, reporting per-key digests and the list of
  divergent keys (normally empty). Divergence means the host mutated the
  store behind the cache — the module books that fact, it does not repair
  it (repair is a policy decision that belongs to the caller).
* **Fail-closed** — empty/non-str keys, ``None`` values, bad seqs, and a
  failing backing store are errors, not silent skips.
* **Deterministic** — LRU ordering uses an internal monotone counter, never
  wall-clock, never hash order. The store interface is host-injectable; the
  default in-memory store is digest-deterministic across instances.

Honest scope: this is *bookkeeping* for a write-through contract, not a
storage engine. It cannot prove the host's store is durable, replicate
writes, or detect the host lying about values (a cached value is whatever
the host last ``write``-ed). Store reads/writes are host code — GIGO on
the host. In a multi-process deployment this module provides zero coherence
between two ``WriteThroughCache`` objects sharing a store; only the store
itself can arbitrate that. A coherent ``sync`` means "nothing we know is
contradicted", never "the data is correct".

Version pin: write-through-cache.v1
Schema pin: northstar.write-through-cache.v1
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

#: Module version.
WRITE_THROUGH_CACHE_VERSION = "write-through-cache.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.write-through-cache.v1"

#: Audit schema for emitted events.
AUDIT_SCHEMA = "audit.ndjson/1"


class WriteThroughCacheError(Exception):
    """Malformed use of the write-through contract (programming error)."""


class BadKeyError(WriteThroughCacheError):
    """Key is not a usable non-empty str."""


class BadValueError(WriteThroughCacheError):
    """Value is None or otherwise un-bookable."""


class StoreError(WriteThroughCacheError):
    """The backing store raised during a write/read-through."""


class SeqOrderError(WriteThroughCacheError):
    """Caller seq did not strictly increase where required."""


def _check_key(key: Any) -> str:
    if isinstance(key, bool) or not isinstance(key, str):
        raise BadKeyError(f"key must be a str, got {type(key).__name__}")
    if not key:
        raise BadKeyError("key must not be empty")
    if len(key) > 4096:
        raise BadKeyError("key too long (>4096 chars)")
    return key


def _check_value(value: Any) -> Any:
    if value is None:
        raise BadValueError("value must not be None")
    return value


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"seq must be an int, got {type(seq).__name__}")
    if seq < 0:
        raise SeqOrderError(f"seq must be >= 0, got {seq}")
    return seq


def _digest_key(key: str) -> str:
    return "sha256:" + hashlib.sha256(key.encode("utf-8")).hexdigest()


def _digest_value(value: Any) -> str:
    return "sha256:" + hashlib.sha256(repr(value).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class WriteRecord:
    """One completed write-through write (frozen record)."""

    version: str
    key_digest: str
    value_digest: str
    overwritten: bool
    seq: int

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "version": self.version,
            "key_digest": self.key_digest,
            "value_digest": self.value_digest,
            "overwritten": self.overwritten,
            "seq": self.seq,
        }


@dataclass(frozen=True)
class ReadOutcome:
    """One read result (frozen record). A miss is data, never raised."""

    version: str
    key_digest: str
    hit: bool
    from_store: bool
    seq: int
    value: Any = None

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "version": self.version,
            "key_digest": self.key_digest,
            "hit": self.hit,
            "from_store": self.from_store,
            "seq": self.seq,
            "value": self.value if self.hit else None,
        }


@dataclass(frozen=True)
class SyncRecord:
    """One coherence check over the cache vs the store (frozen record)."""

    version: str
    checked: int
    divergent_key_digests: Tuple[str, ...]
    state_digest: str
    seq: int

    @property
    def coherent(self) -> bool:
        return not self.divergent_key_digests

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "version": self.version,
            "checked": self.checked,
            "coherent": self.coherent,
            "divergent_key_digests": list(self.divergent_key_digests),
            "state_digest": self.state_digest,
            "seq": self.seq,
        }


@dataclass(frozen=True)
class CacheStats:
    """Counters snapshot (frozen record)."""

    version: str
    capacity: int
    size: int
    hits: int
    misses: int
    writes: int
    read_throughs: int
    evictions: int
    store_failures: int

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "version": self.version,
            "capacity": self.capacity,
            "size": self.size,
            "hits": self.hits,
            "misses": self.misses,
            "writes": self.writes,
            "read_throughs": self.read_throughs,
            "evictions": self.evictions,
            "store_failures": self.store_failures,
        }


@dataclass
class _Entry:
    """One cached entry (mutable internals; never exposed)."""

    value: Any
    last_used: int


class _MemoryStore:
    """Default backing store: a plain dict (simulated, single host)."""

    def __init__(self) -> None:
        self._data: Dict[str, Any] = {}

    def write(self, key: str, value: Any) -> None:
        self._data[key] = value

    def read(self, key: str) -> Tuple[bool, Any]:
        if key in self._data:
            return True, self._data[key]
        return False, None


class WriteThroughCache:
    """Write-through cache with host-injectable backing store.

    ``store_write(key, value)`` and ``store_read(key) -> (found, value)``
    are host callables; defaults simulate a single-host dict store. A
    raising store callable is a :class:`StoreError` (fail-closed).
    """

    def __init__(
        self,
        name: str,
        capacity: int,
        store_write: Optional[Callable[[str, Any], None]] = None,
        store_read: Optional[Callable[[str], Tuple[bool, Any]]] = None,
    ) -> None:
        if isinstance(name, bool) or not isinstance(name, str) or not name:
            raise WriteThroughCacheError("name must be a non-empty str")
        if isinstance(capacity, bool) or not isinstance(capacity, int):
            raise WriteThroughCacheError(f"capacity must be an int, got {type(capacity).__name__}")
        if capacity <= 0:
            raise WriteThroughCacheError(f"capacity must be positive, got {capacity}")
        if capacity > 1_000_000:
            raise WriteThroughCacheError("capacity exceeds guardrail (>1_000_000)")
        self._name = name
        self._capacity = capacity
        self._entries: Dict[str, _Entry] = {}
        self._clock = 0  # monotone LRU ordering counter (no wall-clock)
        self._last_seq = -1
        self._hits = 0
        self._misses = 0
        self._writes = 0
        self._read_throughs = 0
        self._evictions = 0
        self._store_failures = 0
        self._audit: List[dict] = []
        if store_write is None or store_read is None:
            memory = _MemoryStore()
            self._store_write: Callable[[str, Any], None] = memory.write
            self._store_read: Callable[[str], Tuple[bool, Any]] = memory.read
        else:
            self._store_write = store_write
            self._store_read = store_read

    @property
    def name(self) -> str:
        return self._name

    @property
    def capacity(self) -> int:
        return self._capacity

    def _tick(self) -> int:
        self._clock += 1
        return self._clock

    def _use_seq(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must strictly increase, got {seq} after {self._last_seq}"
            )
        self._last_seq = seq
        return seq

    def _emit(self, kind: str, seq: int, **detail: Any) -> None:
        record = {
            "schema": AUDIT_SCHEMA,
            "kind": f"write-through-cache.{kind}",
            "module": WRITE_THROUGH_CACHE_VERSION,
            "seq": seq,
        }
        record.update(detail)
        self._audit.append(record)

    def _store_write_checked(self, key: str, value: Any, seq: int) -> None:
        try:
            self._store_write(key, value)
        except WriteThroughCacheError:
            raise
        except Exception as exc:  # host store failed -> fail-closed
            self._store_failures += 1
            self._emit("rejected", seq, key_digest=_digest_key(key), reason="store-write-failed")
            raise StoreError(f"backing store write failed for {key!r}") from exc

    def _store_read_checked(self, key: str, seq: int) -> Tuple[bool, Any]:
        try:
            found, value = self._store_read(key)
        except WriteThroughCacheError:
            raise
        except Exception as exc:
            self._store_failures += 1
            self._emit("rejected", seq, key_digest=_digest_key(key), reason="store-read-failed")
            raise StoreError(f"backing store read failed for {key!r}") from exc
        if not isinstance(found, bool):
            raise StoreError("store_read must return (bool, value)")
        return found, value

    def _evict_victim(self) -> str:
        """Least-recently-used key (never called when empty)."""
        return min(self._entries, key=lambda k: self._entries[k].last_used)

    def write(self, key: str, value: Any, seq: int) -> WriteRecord:
        """Write through: store first, then cache. All-or-nothing.

        If the store write raises, the cache is left untouched and
        :class:`StoreError` is raised — a completed ``write`` always means
        store and cache agree.
        """
        key = _check_key(key)
        value = _check_value(value)
        self._use_seq(seq)
        # Store first: a store failure must not leave a cache-only value.
        self._store_write_checked(key, value, seq)
        overwritten = key in self._entries
        if not overwritten and len(self._entries) >= self._capacity:
            victim = self._evict_victim()
            del self._entries[victim]
            self._evictions += 1
            self._emit(
                "evicted",
                seq,
                key_digest=_digest_key(victim),
                reason="capacity",
            )
        self._entries[key] = _Entry(value=value, last_used=self._tick())
        self._writes += 1
        self._emit(
            "write",
            seq,
            key_digest=_digest_key(key),
            value_digest=_digest_value(value),
            overwritten=overwritten,
        )
        return WriteRecord(
            version=WRITE_THROUGH_CACHE_VERSION,
            key_digest=_digest_key(key),
            value_digest=_digest_value(value),
            overwritten=overwritten,
            seq=seq,
        )

    def read(self, key: str, seq: int) -> ReadOutcome:
        """Read from cache; on a miss, read through from the store.

        A miss in both cache and store is data (``hit=False``), never
        raised. A read-through populates the cache.
        """
        key = _check_key(key)
        self._use_seq(seq)
        entry = self._entries.get(key)
        if entry is not None:
            entry.last_used = self._tick()
            self._hits += 1
            self._emit("read", seq, key_digest=_digest_key(key), hit=True, from_store=False)
            return ReadOutcome(
                version=WRITE_THROUGH_CACHE_VERSION,
                key_digest=_digest_key(key),
                hit=True,
                from_store=False,
                seq=seq,
                value=entry.value,
            )
        self._misses += 1
        found, value = self._store_read_checked(key, seq)
        if not found:
            self._emit("read", seq, key_digest=_digest_key(key), hit=False, from_store=False)
            return ReadOutcome(
                version=WRITE_THROUGH_CACHE_VERSION,
                key_digest=_digest_key(key),
                hit=False,
                from_store=False,
                seq=seq,
            )
        if len(self._entries) >= self._capacity:
            victim = self._evict_victim()
            del self._entries[victim]
            self._evictions += 1
            self._emit("evicted", seq, key_digest=_digest_key(victim), reason="capacity")
        self._entries[key] = _Entry(value=value, last_used=self._tick())
        self._read_throughs += 1
        self._emit("read", seq, key_digest=_digest_key(key), hit=True, from_store=True)
        return ReadOutcome(
            version=WRITE_THROUGH_CACHE_VERSION,
            key_digest=_digest_key(key),
            hit=True,
            from_store=True,
            seq=seq,
            value=value,
        )

    def sync(self, seq: int) -> SyncRecord:
        """Re-check every cached entry against the store (coherence audit).

        Divergence means the host mutated the store behind the cache. The
        divergence is *booked* as data; this module does not repair it.
        """
        self._use_seq(seq)
        divergent: List[str] = []
        pins: List[str] = []
        for key in sorted(self._entries):
            found, stored = self._store_read_checked(key, seq)
            cached_digest = _digest_value(self._entries[key].value)
            pins.append(_digest_key(key) + "=" + cached_digest)
            if not found or _digest_value(stored) != cached_digest:
                divergent.append(_digest_key(key))
        state_digest = "sha256:" + hashlib.sha256(
            "|".join(pins).encode("utf-8")
        ).hexdigest()
        record = SyncRecord(
            version=WRITE_THROUGH_CACHE_VERSION,
            checked=len(self._entries),
            divergent_key_digests=tuple(divergent),
            state_digest=state_digest,
            seq=seq,
        )
        self._emit(
            "sync",
            seq,
            checked=record.checked,
            coherent=record.coherent,
            state_digest=state_digest,
        )
        return record

    def stats(self) -> CacheStats:
        return CacheStats(
            version=WRITE_THROUGH_CACHE_VERSION,
            capacity=self._capacity,
            size=len(self._entries),
            hits=self._hits,
            misses=self._misses,
            writes=self._writes,
            read_throughs=self._read_throughs,
            evictions=self._evictions,
            store_failures=self._store_failures,
        )

    def audit_log(self) -> Tuple[dict, ...]:
        return tuple(self._audit)


def write_through_cache_audit_event(kind: str, seq: int, **fields: Any) -> dict:
    """Shape an ``audit.ndjson/1`` record for a write-through event."""
    allowed = {"write", "read", "sync", "evicted", "rejected"}
    if kind not in allowed:
        raise WriteThroughCacheError(f"unknown audit kind {kind!r}; allowed: {sorted(allowed)}")
    _check_seq(seq)
    record = {
        "schema": AUDIT_SCHEMA,
        "kind": f"write-through-cache.{kind}",
        "module": WRITE_THROUGH_CACHE_VERSION,
        "seq": seq,
    }
    for k, v in fields.items():
        if k in {"value", "values"}:
            raise WriteThroughCacheError("raw values are never logged; pass digests")
        record[k] = v
    return record


def main() -> None:
    c = WriteThroughCache("wt", capacity=2)
    rec = c.write("a", 1, seq=1)
    assert not rec.overwritten
    out = c.read("a", seq=2)
    assert out.hit and not out.from_store and out.value == 1
    # Miss in both cache and store is data.
    assert not c.read("ghost", seq=3).hit
    # Write-through: store holds the value too.
    rec = c.write("a", 2, seq=4)
    assert rec.overwritten
    fresh = WriteThroughCache("wt2", capacity=2)
    # Seed the shared default-store contract by writing through a host store.
    backing: Dict[str, Any] = {}
    shared = WriteThroughCache(
        "shared",
        capacity=1,
        store_write=lambda k, v: backing.__setitem__(k, v),
        store_read=lambda k: (k in backing, backing.get(k)),
    )
    shared.write("x", "vx", seq=1)
    reader = WriteThroughCache(
        "reader",
        capacity=1,
        store_write=lambda k, v: backing.__setitem__(k, v),
        store_read=lambda k: (k in backing, backing.get(k)),
    )
    out = reader.read("x", seq=1)  # cache miss -> read-through
    assert out.hit and out.from_store and out.value == "vx"
    # Store-first ordering: a failing store leaves the cache untouched.
    def boom_write(k: str, v: Any) -> None:
        raise RuntimeError("store down")

    flaky = WriteThroughCache(
        "flaky", capacity=2, store_write=boom_write,
        store_read=lambda k: (False, None),
    )
    try:
        flaky.write("z", 9, seq=1)
    except StoreError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected StoreError")
    assert not flaky.read("z", seq=2).hit  # cache untouched
    # Coherence audit.
    synced = shared.sync(seq=2)
    assert synced.coherent and synced.checked == 1
    backing["x"] = "tampered"  # host mutates store behind the cache
    synced = shared.sync(seq=3)
    assert not synced.coherent
    assert synced.divergent_key_digests == (_digest_key("x"),)
    print("write-through-cache OK: write, read, read-through, sync, fail-closed")


if __name__ == "__main__":
    main()
