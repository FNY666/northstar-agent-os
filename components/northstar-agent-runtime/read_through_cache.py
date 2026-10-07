"""Read-through cache: the cache itself loads from the backing store on miss.

Research note: caching patterns split on *who* handles a miss. In
*cache-aside* (lazy loading) the application checks the cache, and on a
miss queries the database itself and then populates the cache — the
application owns the miss path. In *read-through* the cache owns the miss
path: the application only ever calls :meth:`ReadThroughCache.load`, and
on a miss the cache invokes a ``loader`` against the backing store, fills
itself, and returns the value. The caller cannot distinguish a hit from a
loader-served miss except by latency. Read-through keeps every read on one
code path (fewer miss-handling bugs, at the cost that the cache must know
how to reach the store). This module is read-through only, not
write-through: :meth:`fill` writes the cache alone, never the store.

* **load(key, seq)** — the single read path. Hit: return the cached value.
  Miss (absent or TTL-stale): invoke the host-supplied ``loader``; on
  success fill the cache and return the value; on loader failure the miss
  *stays a miss* — the failure is booked as data, never raised.
* **fill(key, value, seq)** — explicit insert/overwrite (operator or
  warm-up path); evicts the LRU victim when at capacity.
* **evict(key, seq)** — explicit invalidation; True when something was
  removed.
* **TTL** — entries carry the logical seq at fill time; with
  ``ttl_seqs > 0`` an entry is stale once ``seq - filled_at >= ttl_seqs``
  and a ``load`` re-fetches it through the loader. ``ttl_seqs=0``
  disables expiry. No wall-clock is read anywhere; recency uses a monotone
  counter, so eviction order is fully deterministic.
* **Fail-closed** — bad keys/values/capacities/TTLs/seqs and a
  non-callable loader are programming errors and raise
  :class:`ReadThroughCacheError`. A *loader* failure is not a programming
  error: it is host-reported store behavior and is returned as data.

Honest scope: this is *bookkeeping* for a read-through interface, not a
storage engine. The loader is host-supplied and GIGO — the module cannot
verify that a loaded value is fresh, correct, or came from a real store;
the default loader simulates an empty store (every load misses). A quiet
cache means "no known contract violation", never "the data is fresh". No
coherence across instances is provided: two ``ReadThroughCache`` objects
with the same name are two unrelated caches.

Version pin: read-through-cache.v1
Schema pin: northstar.read-through-cache.v1
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

#: Module version.
READ_THROUGH_CACHE_VERSION = "read-through-cache.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.read-through-cache.v1"

#: Schema pin for audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

_MAX_KEY_LEN = 4096
_MAX_CAPACITY = 1_000_000


class ReadThroughCacheError(Exception):
    """Malformed use of the read-through cache contract (programming error)."""


class BadKeyError(ReadThroughCacheError):
    """Key failed validation (non-str, empty, or too long)."""


class BadCapacityError(ReadThroughCacheError):
    """Capacity failed validation (non-int, non-positive, or over guardrail)."""


class BadValueError(ReadThroughCacheError):
    """A None value was supplied (values must not be None)."""


class BadLoaderError(ReadThroughCacheError):
    """The loader argument was neither None nor callable."""


class BadTTLError(ReadThroughCacheError):
    """ttl_seqs failed validation (non-int or negative)."""


class SeqOrderError(ReadThroughCacheError):
    """seq failed validation (non-int or negative)."""


class LoaderMissError(ReadThroughCacheError):
    """Raised by the default loader: the simulated store holds nothing.

    Never escapes :meth:`ReadThroughCache.load`; it is converted to a
    miss-as-data outcome.
    """


def _default_loader(key: str) -> Any:
    """Simulated backing store: empty, so every load misses."""
    raise LoaderMissError("default loader simulates an empty backing store")


def _check_key(key: Any) -> str:
    if isinstance(key, bool) or not isinstance(key, str):
        raise BadKeyError(f"key must be a str, got {type(key).__name__}")
    if not key:
        raise BadKeyError("key must not be empty")
    if len(key) > _MAX_KEY_LEN:
        raise BadKeyError(f"key too long (>{_MAX_KEY_LEN} chars)")
    return key


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"seq must be an int, got {type(seq).__name__}")
    if seq < 0:
        raise SeqOrderError(f"seq must be >= 0, got {seq}")
    return seq


def _check_capacity(capacity: Any) -> int:
    if isinstance(capacity, bool) or not isinstance(capacity, int):
        raise BadCapacityError(
            f"capacity must be an int, got {type(capacity).__name__}"
        )
    if capacity <= 0:
        raise BadCapacityError(f"capacity must be positive, got {capacity}")
    if capacity > _MAX_CAPACITY:
        raise BadCapacityError(f"capacity exceeds guardrail (>{_MAX_CAPACITY})")
    return capacity


def _check_ttl(ttl_seqs: Any) -> int:
    if isinstance(ttl_seqs, bool) or not isinstance(ttl_seqs, int):
        raise BadTTLError(
            f"ttl_seqs must be an int, got {type(ttl_seqs).__name__}"
        )
    if ttl_seqs < 0:
        raise BadTTLError(f"ttl_seqs must be >= 0, got {ttl_seqs}")
    return ttl_seqs


def _check_loader(loader: Any) -> Callable[[str], Any]:
    if loader is None:
        return _default_loader
    if not callable(loader):
        raise BadLoaderError(
            f"loader must be callable or None, got {type(loader).__name__}"
        )
    return loader


def _digest_key(key: str) -> str:
    return "sha256:" + hashlib.sha256(key.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class LoadOutcome:
    """Result of one ``load`` call (frozen record).

    ``hit`` is True only when the value was served from the cache without
    touching the loader. ``loaded`` is True when the loader supplied the
    value on this call. ``source`` is one of ``"cache"``, ``"loader"``,
    ``"miss"``. ``error`` carries a loader-failure kind as data (never
    raised); it is None on success.
    """

    version: str
    key_digest: str
    hit: bool
    loaded: bool
    source: str
    value: Any = None
    error: Optional[str] = None

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "version": self.version,
            "key_digest": self.key_digest,
            "hit": self.hit,
            "loaded": self.loaded,
            "source": self.source,
            "value": self.value if (self.hit or self.loaded) else None,
            "error": self.error,
        }


@dataclass(frozen=True)
class FillRecord:
    """Result of one ``fill`` call (frozen record)."""

    version: str
    key_digest: str
    evicted_key_digest: Optional[str]

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "version": self.version,
            "key_digest": self.key_digest,
            "evicted_key_digest": self.evicted_key_digest,
        }


@dataclass(frozen=True)
class EvictionRecord:
    """One eviction (frozen record)."""

    version: str
    key_digest: str
    reason: str  # "capacity" | "explicit" | "expired"

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "version": self.version,
            "key_digest": self.key_digest,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class CacheStats:
    """Counter snapshot (frozen record)."""

    version: str
    name: str
    capacity: int
    size: int
    hits: int
    misses: int
    loads: int
    load_failures: int
    fills: int
    evictions: int
    hit_rate: Optional[float]

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "version": self.version,
            "name": self.name,
            "capacity": self.capacity,
            "size": self.size,
            "hits": self.hits,
            "misses": self.misses,
            "loads": self.loads,
            "load_failures": self.load_failures,
            "fills": self.fills,
            "evictions": self.evictions,
            "hit_rate": self.hit_rate,
        }


@dataclass
class _Entry:
    """One cached entry (mutable internals; never exposed)."""

    value: Any
    last_used: int
    inserted_at: int
    filled_at_seq: int


class ReadThroughCache:
    """Read-through cache: the cache owns the miss path.

    On a miss (absent key or TTL-stale entry) ``load`` invokes the
    host-supplied loader, fills the cache with the result, and returns it.
    Loader failures are data, never raised. Eviction is LRU over a
    monotone counter — deterministic, no wall-clock.
    """

    def __init__(
        self,
        name: str,
        capacity: int,
        loader: Optional[Callable[[str], Any]] = None,
        ttl_seqs: int = 0,
    ) -> None:
        if isinstance(name, bool) or not isinstance(name, str) or not name:
            raise ReadThroughCacheError("name must be a non-empty str")
        self._name = name
        self._capacity = _check_capacity(capacity)
        self._loader = _check_loader(loader)
        self._ttl_seqs = _check_ttl(ttl_seqs)
        self._entries: Dict[str, _Entry] = {}
        self._clock = 0  # monotone ordering counter (no wall-clock)
        self._hits = 0
        self._misses = 0
        self._loads = 0
        self._load_failures = 0
        self._fills = 0
        self._evictions = 0
        self._eviction_log: List[EvictionRecord] = []

    @property
    def name(self) -> str:
        return self._name

    @property
    def capacity(self) -> int:
        return self._capacity

    @property
    def ttl_seqs(self) -> int:
        return self._ttl_seqs

    def _tick(self) -> int:
        self._clock += 1
        return self._clock

    def _victim(self) -> str:
        """Pick the LRU victim deterministically (never called when empty)."""
        return min(
            self._entries,
            key=lambda k: (self._entries[k].last_used, self._entries[k].inserted_at),
        )

    def _is_stale(self, entry: _Entry, seq: int) -> bool:
        if self._ttl_seqs <= 0:
            return False
        return seq - entry.filled_at_seq >= self._ttl_seqs

    def _drop(self, key: str, reason: str) -> None:
        del self._entries[key]
        self._evictions += 1
        self._eviction_log.append(
            EvictionRecord(
                version=READ_THROUGH_CACHE_VERSION,
                key_digest=_digest_key(key),
                reason=reason,
            )
        )

    def load(self, key: str, seq: int) -> LoadOutcome:
        """Read ``key``; on miss the loader fills the cache (failures are data)."""
        _check_key(key)
        _check_seq(seq)
        entry = self._entries.get(key)
        if entry is not None and not self._is_stale(entry, seq):
            entry.last_used = self._tick()
            self._hits += 1
            return LoadOutcome(
                version=READ_THROUGH_CACHE_VERSION,
                key_digest=_digest_key(key),
                hit=True,
                loaded=False,
                source="cache",
                value=entry.value,
            )
        if entry is not None:
            # TTL-stale: drop it, then take the miss path.
            self._drop(key, reason="expired")
        self._misses += 1
        try:
            value = self._loader(key)
        except Exception as exc:  # loader failure is data, never raised
            self._load_failures += 1
            return LoadOutcome(
                version=READ_THROUGH_CACHE_VERSION,
                key_digest=_digest_key(key),
                hit=False,
                loaded=False,
                source="miss",
                error=type(exc).__name__,
            )
        if value is None:
            self._load_failures += 1
            return LoadOutcome(
                version=READ_THROUGH_CACHE_VERSION,
                key_digest=_digest_key(key),
                hit=False,
                loaded=False,
                source="miss",
                error="LoaderReturnedNone",
            )
        self._loads += 1
        self.fill(key, value, seq)
        return LoadOutcome(
            version=READ_THROUGH_CACHE_VERSION,
            key_digest=_digest_key(key),
            hit=False,
            loaded=True,
            source="loader",
            value=value,
        )

    def fill(self, key: str, value: Any, seq: int) -> FillRecord:
        """Explicitly insert or overwrite ``key`` (cache only, not the store)."""
        _check_key(key)
        _check_seq(seq)
        if value is None:
            raise BadValueError("value must not be None")
        now = self._tick()
        evicted: Optional[str] = None
        if key in self._entries:
            entry = self._entries[key]
            entry.value = value
            entry.last_used = now
            entry.filled_at_seq = seq
        else:
            if len(self._entries) >= self._capacity:
                evicted = self._victim()
                self._drop(evicted, reason="capacity")
            self._entries[key] = _Entry(
                value=value, last_used=now, inserted_at=now, filled_at_seq=seq
            )
        self._fills += 1
        return FillRecord(
            version=READ_THROUGH_CACHE_VERSION,
            key_digest=_digest_key(key),
            evicted_key_digest=_digest_key(evicted) if evicted is not None else None,
        )

    def evict(self, key: str, seq: int) -> bool:
        """Explicitly invalidate ``key``; True when something was removed."""
        _check_key(key)
        _check_seq(seq)
        if key not in self._entries:
            return False
        self._drop(key, reason="explicit")
        return True

    def contains(self, key: str) -> bool:
        """Membership test without touching recency or counters."""
        _check_key(key)
        return key in self._entries

    def stats(self) -> CacheStats:
        lookups = self._hits + self._misses
        return CacheStats(
            version=READ_THROUGH_CACHE_VERSION,
            name=self._name,
            capacity=self._capacity,
            size=len(self._entries),
            hits=self._hits,
            misses=self._misses,
            loads=self._loads,
            load_failures=self._load_failures,
            fills=self._fills,
            evictions=self._evictions,
            hit_rate=(self._hits / lookups) if lookups else None,
        )

    def eviction_log(self) -> Tuple[EvictionRecord, ...]:
        return tuple(self._eviction_log)


def read_through_cache_audit_event(kind: str, seq: int, **fields: Any) -> dict:
    """Shape an ``audit.ndjson/1`` record for a read-through cache event."""
    allowed = {"hit", "miss", "loaded", "filled", "evicted", "expired", "rejected"}
    if kind not in allowed:
        raise ReadThroughCacheError(
            f"unknown audit kind {kind!r}; allowed: {sorted(allowed)}"
        )
    _check_seq(seq)
    record = {
        "schema": AUDIT_SCHEMA,
        "kind": f"read-through-cache.{kind}",
        "module": READ_THROUGH_CACHE_VERSION,
        "seq": seq,
    }
    for k, v in fields.items():
        if k == "value":
            raise ReadThroughCacheError("raw values are never logged; pass digests")
        record[k] = v
    return record


def main() -> None:
    calls: List[str] = []

    def loader(key: str) -> str:
        calls.append(key)
        return f"v:{key}"

    c = ReadThroughCache("rt", capacity=2, loader=loader)
    first = c.load("a", seq=1)  # miss -> loader fills
    assert not first.hit and first.loaded and first.value == "v:a", first
    assert first.source == "loader"
    second = c.load("a", seq=2)  # hit, loader not called again
    assert second.hit and not second.loaded and calls == ["a"], (second, calls)

    c.fill("b", "B", seq=3)
    c.load("a", seq=4)  # refresh recency of "a"
    rec = c.fill("c", "C", seq=5)  # evicts "b" (LRU)
    assert rec.evicted_key_digest == _digest_key("b"), rec
    assert not c.contains("b")

    # TTL expiry re-fetches through the loader.
    t = ReadThroughCache("ttl", capacity=4, loader=loader, ttl_seqs=3)
    t.load("k", seq=10)  # filled_at=10
    assert t.load("k", seq=12).hit  # 12-10=2 < 3, fresh
    stale = t.load("k", seq=13)  # 13-10=3 >= 3, stale -> reload
    assert stale.loaded and stale.value == "v:k", stale

    # Loader failure is data, never raised.
    def bad_loader(key: str) -> str:
        raise RuntimeError("store down")

    f = ReadThroughCache("f", capacity=2, loader=bad_loader)
    failed = f.load("x", seq=1)
    assert not failed.hit and not failed.loaded, failed
    assert failed.source == "miss" and failed.error == "RuntimeError", failed
    assert not f.contains("x")

    # Default loader simulates an empty store.
    d = ReadThroughCache("d", capacity=2)
    assert d.load("z", seq=1).error == "LoaderMissError"

    assert c.evict("a", seq=6) is True
    assert c.evict("a", seq=7) is False
    print("read-through-cache OK: load, fill, evict, lru, ttl, loader-failure")


if __name__ == "__main__":
    main()
