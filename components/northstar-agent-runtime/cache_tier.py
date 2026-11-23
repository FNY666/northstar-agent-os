"""Multi-level cache: LRU/LFU eviction policies with deterministic bookkeeping.

Research note: *caches* trade space for latency by keeping hot data close to
the consumer. Two textbook eviction policies cover most single-node needs:
*LRU* (least-recently-used — evicts the entry untouched longest; provably
k-competitive against the offline optimum under the paging model, Sleator &
Tarjan 1985) and *LFU* (least-frequently-used — evicts the entry with the
lowest access count; better than LRU under skewed popularity like Zipf, worse
under shifting working sets). Real hierarchies add *levels*: a small fast L1
in front of a larger slower L2 (the memory-hierarchy idea going back to
Wilkes' slave memories, 1965), so a miss in L1 can still be served from L2
without touching the origin.

* **One tier, one policy** — :class:`CacheTier` owns a fixed ``capacity``
  and exactly one policy (``LRU`` or ``LFU``). The policy is frozen at
  construction: mixing policies inside one tier makes the eviction choice
  un-auditable.
* **Multi-level** — :class:`MultiLevelCache` orders tiers L1..Ln. ``get``
  walks down the hierarchy; a hit below L1 is *promoted* back up
  (read-through), so the next lookup is fast. ``put`` writes to L1 and the
  evicted *victim* spills down to L2, then L3 (victim-caching, Jouppi 1990);
  nothing is silently dropped while a lower tier still has room.
* **Fail-closed** — empty/non-str keys, ``None`` values, non-positive
  capacities, unknown policies, and bool numerics in numeric arguments are
  programming errors and raise :class:`CacheTierError` instead of corrupting
  accounting.
* **Deterministic** — recency/frequency ordering uses an internal monotone
  counter (LFU ties break by least-recently-used, then by insertion order),
  never wall-clock, never hashing order. The same call sequence produces the
  same eviction sequence on every run, so tests and audits replay exactly.

Honest scope: this is *bookkeeping* for a cache interface, not a storage
engine. It cannot observe a real working set, prove a hit would have been a
miss elsewhere, or detect the host lying about values (a cached value is
whatever the host last ``put``). LFU frequency counts *interface calls*, not
true popularity; promotion copies host-reported values upward verbatim. In a
multi-process deployment this module provides zero coherence — two
``CacheTier`` objects with the same name are two unrelated caches. A quiet
cache means "no known contract violation", never "the data is fresh".

Version pin: cache-tier.v1
Schema pin: northstar.cache-tier.v1
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

#: Module version.
CACHE_TIER_VERSION = "cache-tier.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.cache-tier.v1"


class CacheTierError(Exception):
    """Malformed use of the cache contract (programming error)."""


class EvictionPolicy:
    """Eviction-policy constants (frozen at tier construction)."""

    LRU = "lru"
    LFU = "lfu"

    ALL = (LRU, LFU)


def _check_key(key: Any) -> str:
    if isinstance(key, bool) or not isinstance(key, str):
        raise CacheTierError(f"key must be a str, got {type(key).__name__}")
    if not key:
        raise CacheTierError("key must not be empty")
    if len(key) > 4096:
        raise CacheTierError("key too long (>4096 chars)")
    return key


def _check_capacity(capacity: Any) -> int:
    if isinstance(capacity, bool) or not isinstance(capacity, int):
        raise CacheTierError(f"capacity must be an int, got {type(capacity).__name__}")
    if capacity <= 0:
        raise CacheTierError(f"capacity must be positive, got {capacity}")
    if capacity > 1_000_000:
        raise CacheTierError("capacity exceeds guardrail (>1_000_000)")
    return capacity


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise CacheTierError(f"seq must be an int, got {type(seq).__name__}")
    if seq < 0:
        raise CacheTierError(f"seq must be >= 0, got {seq}")
    return seq


def _digest_key(key: str) -> str:
    return "sha256:" + hashlib.sha256(key.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class GetOutcome:
    """Result of one ``get`` call (frozen record)."""

    version: str
    key_digest: str
    hit: bool
    tier: Optional[str]
    value: Any = None

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "version": self.version,
            "key_digest": self.key_digest,
            "hit": self.hit,
            "tier": self.tier,
            "value": self.value if self.hit else None,
        }


@dataclass(frozen=True)
class PutRecord:
    """Result of one ``put`` call (frozen record)."""

    version: str
    key_digest: str
    tier: str
    evicted_key_digest: Optional[str]

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "version": self.version,
            "key_digest": self.key_digest,
            "tier": self.tier,
            "evicted_key_digest": self.evicted_key_digest,
        }


@dataclass(frozen=True)
class EvictionRecord:
    """One eviction (frozen record)."""

    version: str
    tier: str
    key_digest: str
    policy: str
    reason: str

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "version": self.version,
            "tier": self.tier,
            "key_digest": self.key_digest,
            "policy": self.policy,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class CacheStats:
    """Per-tier counters snapshot (frozen record)."""

    version: str
    tier: str
    policy: str
    capacity: int
    size: int
    hits: int
    misses: int
    puts: int
    evictions: int
    hit_rate: Optional[float]

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "version": self.version,
            "tier": self.tier,
            "policy": self.policy,
            "capacity": self.capacity,
            "size": self.size,
            "hits": self.hits,
            "misses": self.misses,
            "puts": self.puts,
            "evictions": self.evictions,
            "hit_rate": self.hit_rate,
        }


@dataclass
class _Entry:
    """One cached entry (mutable internals; never exposed)."""

    value: Any
    freq: int
    last_used: int
    inserted_at: int


class CacheTier:
    """One cache level with a fixed capacity and a frozen eviction policy.

    LRU evicts the least-recently-used entry; LFU evicts the
    least-frequently-used entry (ties broken by least-recently-used, then by
    earliest insertion — fully deterministic).
    """

    def __init__(self, name: str, capacity: int, policy: str = EvictionPolicy.LRU) -> None:
        if isinstance(name, bool) or not isinstance(name, str) or not name:
            raise CacheTierError("name must be a non-empty str")
        _check_capacity(capacity)
        if policy not in EvictionPolicy.ALL:
            raise CacheTierError(f"policy must be one of {EvictionPolicy.ALL}, got {policy!r}")
        self._name = name
        self._capacity = capacity
        self._policy = policy
        self._entries: Dict[str, _Entry] = {}
        self._clock = 0  # monotone ordering counter (no wall-clock)
        self._hits = 0
        self._misses = 0
        self._puts = 0
        self._evictions = 0
        self._eviction_log: List[EvictionRecord] = []

    @property
    def name(self) -> str:
        return self._name

    @property
    def capacity(self) -> int:
        return self._capacity

    @property
    def policy(self) -> str:
        return self._policy

    def _tick(self) -> int:
        self._clock += 1
        return self._clock

    def _victim(self) -> str:
        """Pick the eviction victim deterministically (never called when empty)."""
        if self._policy == EvictionPolicy.LRU:
            return min(
                self._entries,
                key=lambda k: (self._entries[k].last_used, self._entries[k].inserted_at),
            )
        return min(
            self._entries,
            key=lambda k: (
                self._entries[k].freq,
                self._entries[k].last_used,
                self._entries[k].inserted_at,
            ),
        )

    def put(self, key: str, value: Any, seq: int) -> PutRecord:
        """Insert or overwrite ``key``; evicts a victim when full."""
        _check_key(key)
        _check_seq(seq)
        if value is None:
            raise CacheTierError("value must not be None")
        now = self._tick()
        evicted: Optional[str] = None
        if key in self._entries:
            entry = self._entries[key]
            entry.value = value
            entry.freq += 1
            entry.last_used = now
        else:
            if len(self._entries) >= self._capacity:
                victim = self._victim()
                del self._entries[victim]
                evicted = victim
                self._evictions += 1
                self._eviction_log.append(
                    EvictionRecord(
                        version=CACHE_TIER_VERSION,
                        tier=self._name,
                        key_digest=_digest_key(victim),
                        policy=self._policy,
                        reason="capacity",
                    )
                )
            self._entries[key] = _Entry(value=value, freq=1, last_used=now, inserted_at=now)
        self._puts += 1
        return PutRecord(
            version=CACHE_TIER_VERSION,
            key_digest=_digest_key(key),
            tier=self._name,
            evicted_key_digest=_digest_key(evicted) if evicted is not None else None,
        )

    def _put_spill(self, key: str, value: Any, seq: int) -> Tuple[PutRecord, Optional[Tuple[str, Any]]]:
        """Internal put that also returns the evicted (key, value) for spillover.

        The public :meth:`put` never exposes evicted values (they are gone
        from the tier); the multi-level cache needs them to spill a victim
        down one level, so it uses this internal variant.
        """
        _check_key(key)
        _check_seq(seq)
        if value is None:
            raise CacheTierError("value must not be None")
        now = self._tick()
        spilled: Optional[Tuple[str, Any]] = None
        if key in self._entries:
            entry = self._entries[key]
            entry.value = value
            entry.freq += 1
            entry.last_used = now
        else:
            if len(self._entries) >= self._capacity:
                victim = self._victim()
                victim_entry = self._entries.pop(victim)
                spilled = (victim, victim_entry.value)
                self._evictions += 1
                self._eviction_log.append(
                    EvictionRecord(
                        version=CACHE_TIER_VERSION,
                        tier=self._name,
                        key_digest=_digest_key(victim),
                        policy=self._policy,
                        reason="capacity",
                    )
                )
            self._entries[key] = _Entry(value=value, freq=1, last_used=now, inserted_at=now)
        self._puts += 1
        record = PutRecord(
            version=CACHE_TIER_VERSION,
            key_digest=_digest_key(key),
            tier=self._name,
            evicted_key_digest=_digest_key(spilled[0]) if spilled is not None else None,
        )
        return record, spilled

    def get(self, key: str, seq: int) -> GetOutcome:
        """Look up ``key``; a hit refreshes recency/frequency."""
        _check_key(key)
        _check_seq(seq)
        entry = self._entries.get(key)
        if entry is None:
            self._misses += 1
            return GetOutcome(
                version=CACHE_TIER_VERSION,
                key_digest=_digest_key(key),
                hit=False,
                tier=None,
            )
        now = self._tick()
        entry.freq += 1
        entry.last_used = now
        self._hits += 1
        return GetOutcome(
            version=CACHE_TIER_VERSION,
            key_digest=_digest_key(key),
            hit=True,
            tier=self._name,
            value=entry.value,
        )

    def evict(self, key: str, seq: int) -> bool:
        """Explicitly remove ``key``; True when something was removed."""
        _check_key(key)
        _check_seq(seq)
        if key not in self._entries:
            return False
        del self._entries[key]
        self._evictions += 1
        self._eviction_log.append(
            EvictionRecord(
                version=CACHE_TIER_VERSION,
                tier=self._name,
                key_digest=_digest_key(key),
                policy=self._policy,
                reason="explicit",
            )
        )
        return True

    def contains(self, key: str) -> bool:
        """Membership test without touching recency/frequency or counters."""
        _check_key(key)
        return key in self._entries

    def stats(self) -> CacheStats:
        lookups = self._hits + self._misses
        return CacheStats(
            version=CACHE_TIER_VERSION,
            tier=self._name,
            policy=self._policy,
            capacity=self._capacity,
            size=len(self._entries),
            hits=self._hits,
            misses=self._misses,
            puts=self._puts,
            evictions=self._evictions,
            hit_rate=(self._hits / lookups) if lookups else None,
        )

    def eviction_log(self) -> Tuple[EvictionRecord, ...]:
        return tuple(self._eviction_log)


class MultiLevelCache:
    """L1..Ln hierarchy: read-through promotion, victim spillover on writes.

    ``get`` walks tiers in order and promotes a below-L1 hit back up through
    the faster tiers. ``put`` writes to L1; each evicted victim spills into
    the next tier instead of being dropped (until the last tier, whose victim
    is genuinely lost). ``evict`` removes a key from every tier.
    """

    def __init__(self, tiers: Sequence[CacheTier]) -> None:
        tiers = list(tiers)
        if not tiers:
            raise CacheTierError("tiers must be a non-empty sequence")
        if any(not isinstance(t, CacheTier) for t in tiers):
            raise CacheTierError("tiers must all be CacheTier instances")
        names = [t.name for t in tiers]
        if len(set(names)) != len(names):
            raise CacheTierError(f"tier names must be unique, got {names}")
        self._tiers: Tuple[CacheTier, ...] = tuple(tiers)

    @property
    def tiers(self) -> Tuple[CacheTier, ...]:
        return self._tiers

    def get(self, key: str, seq: int) -> GetOutcome:
        """Walk L1..Ln; promote a below-L1 hit back up."""
        _check_key(key)
        _check_seq(seq)
        for i, tier in enumerate(self._tiers):
            outcome = tier.get(key, seq)
            if outcome.hit:
                # Promote into the faster tiers above the hit tier.
                for upper in self._tiers[:i]:
                    upper.put(key, outcome.value, seq)
                return outcome
        return GetOutcome(
            version=CACHE_TIER_VERSION,
            key_digest=_digest_key(key),
            hit=False,
            tier=None,
        )

    def put(self, key: str, value: Any, seq: int) -> PutRecord:
        """Write to L1; spill each evicted victim down one tier."""
        _check_key(key)
        _check_seq(seq)
        if value is None:
            raise CacheTierError("value must not be None")
        first_record: Optional[PutRecord] = None
        current_key, current_value = key, value
        for tier in self._tiers:
            record, spilled = tier._put_spill(current_key, current_value, seq)
            if first_record is None:
                first_record = record
            if spilled is None:
                break
            current_key, current_value = spilled
        assert first_record is not None
        return first_record

    def evict(self, key: str, seq: int) -> bool:
        """Remove ``key`` from every tier; True if removed anywhere."""
        _check_key(key)
        _check_seq(seq)
        removed = False
        for tier in self._tiers:
            if tier.evict(key, seq):
                removed = True
        return removed

    def stats(self) -> Tuple[CacheStats, ...]:
        return tuple(t.stats() for t in self._tiers)


def cache_tier_audit_event(kind: str, seq: int, **fields: Any) -> dict:
    """Shape an ``audit.ndjson/1`` record for a cache event."""
    allowed = {"put", "got", "evicted", "promoted", "rejected"}
    if kind not in allowed:
        raise CacheTierError(f"unknown audit kind {kind!r}; allowed: {sorted(allowed)}")
    _check_seq(seq)
    record = {
        "schema": "audit.ndjson/1",
        "kind": f"cache-tier.{kind}",
        "module": CACHE_TIER_VERSION,
        "seq": seq,
    }
    for k, v in fields.items():
        if k in {"value"}:
            raise CacheTierError("raw values are never logged; pass digests")
        record[k] = v
    return record


def main() -> None:
    tier = CacheTier("l1", capacity=2, policy=EvictionPolicy.LRU)
    tier.put("a", 1, seq=1)
    tier.put("b", 2, seq=2)
    assert tier.get("a", seq=3).hit
    rec = tier.put("c", 3, seq=4)  # evicts "b" (LRU)
    assert rec.evicted_key_digest == _digest_key("b"), rec
    assert not tier.get("b", seq=5).hit

    lfu = CacheTier("l2", capacity=2, policy=EvictionPolicy.LFU)
    lfu.put("x", 1, seq=1)
    lfu.put("y", 2, seq=2)
    lfu.get("x", seq=3)
    lfu.get("x", seq=4)
    rec = lfu.put("z", 3, seq=5)  # evicts "y" (freq 1 < 3)
    assert rec.evicted_key_digest == _digest_key("y"), rec

    multi = MultiLevelCache(
        [CacheTier("l1", 1, EvictionPolicy.LRU), CacheTier("l2", 2, EvictionPolicy.LRU)]
    )
    multi.put("k", "v", seq=1)
    assert multi.get("k", seq=2).tier == "l1"
    multi.put("k2", "v2", seq=3)  # evicts k from l1
    assert not multi.tiers[0].contains("k")
    print("cache-tier OK: lru, lfu, multilevel, fail-closed")


if __name__ == "__main__":
    main()
