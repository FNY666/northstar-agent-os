"""Cache-aside (lazy-loading) pattern: application-managed cache/origin coherence.

Research note: the *cache-aside* (a.k.a. lazy-loading) pattern — documented in
the classic caching literature (e.g. the "cache-aside" strategy in Microsoft's
cloud design patterns and the Nygard/Sadalage treatment of cache topologies)
— keeps coherence logic in the *application* rather than in the cache:

* **Read path** — the application looks in the cache first. On a miss it
  loads from the origin (database), populates the cache, and returns the
  value. The cache never talks to the origin itself.
* **Write path** — the application writes to the origin first, then
  *invalidates* (delete-on-write) or *updates* (write-through) the cached
  entry. Delete-on-write is the classic default: it avoids the stale-read
  race where a concurrent reader repopulates the cache with the old value
  between a cache-update and the origin write.
* **Invalidation** — entries can be evicted explicitly (manual invalidation,
  TTL expiry) without touching the origin.

This module books that coordination as a deterministic single-host state
machine. It is deliberately distinct from:

* ``cache_tier`` — eviction *policies* (LRU/LFU) and multi-level promotion;
* ``config_management`` — a KV store with leases, watches and locks;
* ``cdn_manager`` — edge purge/prefetch bookkeeping.

Here the cache is a bounded FIFO map (oldest-``set`` evicted first —
deterministic, no recency bookkeeping needed for the pattern itself), the
origin is a host-injectable ``writer``/``loader`` pair (default: a
deterministic in-memory simulator), and TTLs are expressed in *logical seqs*,
never wall-clock.

* **Fail-closed** — malformed keys/values/TTLs/strategies and non-callable
  ``loader``/``writer`` are programming errors and raise. A host backend that
  *raises* is booked as a failed write/load — as data, never as an
  exception (the cdn_manager/edge_compute discipline): the record says what
  happened, the caller decides.
* **Deterministic** — eviction is FIFO by ``set`` seq (ties by key), expiry
  is by logical seq, digests are type-tagged canonical JSON. The same call
  sequence replays identically.
* **Audit-safe** — raw keys and values never cross the audit boundary; only
  key digests, value digests and verdict flags are logged.

Honest scope: this is *bookkeeping* for the cache-aside contract, not a
storage engine and not a coherence protocol. It cannot prove the origin
really holds what the writer claimed, detect the host lying about loaded
values, or prevent the classic delete-on-write race across processes — with
two ``CacheAside`` objects the "delete" is local fiction. A quiet ledger
means "no known contract violation", never "the cache is coherent".

Version pin: cache-aside.v1
Schema pin: northstar.cache-aside.v1
"""

from __future__ import annotations

import base64
import hashlib
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import
    import json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Version pin for this module's record shape.
CACHE_ASIDE_VERSION = "cache-aside.v1"

#: Schema pin carried by records.
CACHE_ASIDE_SCHEMA = "northstar.cache-aside.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Pin: write strategies for the ``set`` path.
STRATEGY_INVALIDATE = "invalidate"
STRATEGY_UPDATE = "update"
_STRATEGIES = (STRATEGY_INVALIDATE, STRATEGY_UPDATE)

#: Pin: maximum key length (house ceiling, matches cache_tier).
MAX_KEY_LEN = 4096

#: Pin: maximum capacity guardrail.
MAX_CAPACITY = 1_000_000

#: Audit kinds.
_AUDIT_KINDS = ("got", "set", "invalidated", "expired", "rejected")


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class CacheAsideError(Exception):
    """Base error for the cache-aside contract (programming error)."""


class BadKeyError(CacheAsideError):
    """Key is not a non-empty str within the length guardrail."""


class BadValueError(CacheAsideError):
    """Value is None or not a digest-safe type."""


class BadTTLError(CacheAsideError):
    """TTL is not a non-negative int."""


class BadStrategyError(CacheAsideError):
    """Write strategy is outside the pinned vocabulary."""


class BadCapacityError(CacheAsideError):
    """Capacity is not a positive int within the guardrail."""


class BadBackendError(CacheAsideError):
    """Loader/writer is not callable."""


class SeqOrderError(CacheAsideError):
    """Seq did not strictly increase (or is not a non-negative int)."""


class AuditKindError(CacheAsideError):
    """Unknown audit kind."""


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _check_key(key: Any) -> str:
    if isinstance(key, bool) or not isinstance(key, str):
        raise BadKeyError(f"key must be a str, got {type(key).__name__}")
    if not key:
        raise BadKeyError("key must not be empty")
    if len(key) > MAX_KEY_LEN:
        raise BadKeyError(f"key too long (>{MAX_KEY_LEN} chars)")
    return key


def _check_capacity(capacity: Any) -> int:
    if isinstance(capacity, bool) or not isinstance(capacity, int):
        raise BadCapacityError(
            f"capacity must be an int, got {type(capacity).__name__}"
        )
    if capacity <= 0:
        raise BadCapacityError(f"capacity must be positive, got {capacity}")
    if capacity > MAX_CAPACITY:
        raise BadCapacityError(f"capacity exceeds guardrail (>{MAX_CAPACITY})")
    return capacity


def _check_ttl(ttl: Any, name: str = "ttl") -> int:
    if isinstance(ttl, bool) or not isinstance(ttl, int):
        raise BadTTLError(f"{name} must be an int, got {type(ttl).__name__}")
    if ttl < 0:
        raise BadTTLError(f"{name} must be >= 0, got {ttl}")
    return ttl


def _check_strategy(strategy: Any) -> str:
    if strategy not in _STRATEGIES:
        raise BadStrategyError(
            f"strategy must be one of {_STRATEGIES}, got {strategy!r}"
        )
    return strategy


def _check_backend(fn: Any, name: str) -> Callable:
    if not callable(fn):
        raise BadBackendError(f"{name} must be callable, got {type(fn).__name__}")
    return fn


def _tag(value: Any) -> Any:
    """Type-tag a value for digest determinism (bool != int; |n| < 2^53)."""
    if isinstance(value, bool):
        return {"t": "bool", "v": value}
    if isinstance(value, int):
        if abs(value) >= 2**53:
            raise BadValueError("integer outside safe range (|n| >= 2^53)")
        return {"t": "int", "v": value}
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise BadValueError("non-finite float refused")
        return {"t": "float", "v": repr(value)}
    if isinstance(value, str):
        return {"t": "str", "v": value}
    if isinstance(value, bytes):
        return {"t": "bytes", "v": base64.b64encode(value).decode("ascii")}
    if isinstance(value, (list, tuple)):
        return {"t": "list", "v": [_tag(v) for v in value]}
    if isinstance(value, dict):
        if not all(isinstance(k, str) for k in value):
            raise BadValueError("dict keys must be str")
        return {"t": "dict", "v": {k: _tag(value[k]) for k in sorted(value)}}
    raise BadValueError(f"value of type {type(value).__name__} is not digest-safe")


def _check_value(value: Any) -> Any:
    if value is None:
        raise BadValueError("value must not be None")
    _tag(value)  # validates digest-safety
    return value


def _digest(tag: str, *parts: Any) -> str:
    payload = [CACHE_ASIDE_VERSION, tag, *[_tag(p) for p in parts]]
    return "sha256:" + hashlib.sha256(jcs_canonical_json(payload)).hexdigest()


def _key_digest(key: str) -> str:
    return _digest("key", key)


def _value_digest(value: Any) -> str:
    return _digest("value", value)


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GetResult:
    """One cache-aside ``get`` verdict (frozen). Misses and failed loads
    are data, never exceptions."""

    key_digest: str
    hit: bool
    loaded: bool
    evicted_key_digest: Optional[str]
    seq: int
    digest: str
    value: Any = field(default=None, compare=False)
    schema: str = CACHE_ASIDE_SCHEMA
    version: str = CACHE_ASIDE_VERSION

    def verify(self) -> bool:
        return self.digest == _digest(
            "get", self.key_digest, self.hit, self.loaded,
            self.evicted_key_digest or "", self.seq,
        )


@dataclass(frozen=True)
class SetRecord:
    """One cache-aside ``set`` (write path) booking (frozen). A writer that
    raised is booked as ``written=False`` — as data."""

    key_digest: str
    value_digest: str
    written: bool
    strategy: str
    cache_action: str  # "invalidated" | "updated" | "none"
    evicted_key_digest: Optional[str]
    seq: int
    digest: str
    schema: str = CACHE_ASIDE_SCHEMA
    version: str = CACHE_ASIDE_VERSION

    def verify(self) -> bool:
        return self.digest == _digest(
            "set", self.key_digest, self.value_digest, self.written,
            self.strategy, self.cache_action,
            self.evicted_key_digest or "", self.seq,
        )


@dataclass(frozen=True)
class InvalidateRecord:
    """One explicit invalidation (frozen). Idempotent: invalidating an
    absent key succeeds with ``existed=False``."""

    key_digest: str
    existed: bool
    seq: int
    digest: str
    schema: str = CACHE_ASIDE_SCHEMA
    version: str = CACHE_ASIDE_VERSION

    def verify(self) -> bool:
        return self.digest == _digest(
            "invalidate", self.key_digest, self.existed, self.seq
        )


@dataclass(frozen=True)
class ExpireReport:
    """One TTL sweep (frozen)."""

    expired_key_digests: Tuple[str, ...]
    count: int
    seq: int
    digest: str
    schema: str = CACHE_ASIDE_SCHEMA
    version: str = CACHE_ASIDE_VERSION

    def verify(self) -> bool:
        return self.digest == _digest(
            "expire", list(self.expired_key_digests), self.count, self.seq
        )


@dataclass(frozen=True)
class StatsReport:
    """Pure read view over the counters (frozen). ``size`` counts live
    (non-expired) entries at the view's seq."""

    hits: int
    misses: int
    sets: int
    invalidations: int
    expirations: int
    loads: int
    evictions: int
    size: int
    capacity: int
    seq: int
    digest: str
    schema: str = CACHE_ASIDE_SCHEMA
    version: str = CACHE_ASIDE_VERSION

    def verify(self) -> bool:
        return self.digest == _digest(
            "stats", self.hits, self.misses, self.sets, self.invalidations,
            self.expirations, self.loads, self.evictions, self.size,
            self.capacity, self.seq,
        )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def cache_aside_audit_event(kind: str, seq: int, **fields: Any) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the cache-aside module.

    Raw keys and values never cross the audit boundary — pass digests.
    """
    if kind not in _AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError("seq must be a non-negative int")
    banned = {"key", "value", "keys", "values"}
    if any(k in fields for k in banned):
        raise CacheAsideError("raw keys/values are banned from the audit boundary")
    record: Dict[str, Any] = {
        "schema": AUDIT_SCHEMA,
        "kind": f"cache-aside.{kind}",
        "module": CACHE_ASIDE_VERSION,
        "seq": seq,
    }
    record.update(fields)
    return record


# ---------------------------------------------------------------------------
# The ledger
# ---------------------------------------------------------------------------


class _Entry:
    """One cached entry (mutable, lock-guarded)."""

    __slots__ = ("value", "set_seq", "expiry_seq")

    def __init__(self, value: Any, set_seq: int, expiry_seq: Optional[int]):
        self.value = value
        self.set_seq = set_seq
        self.expiry_seq = expiry_seq


class CacheAside:
    """Cache-aside (lazy-loading) coordination ledger.

    The application (this class) owns coherence between a bounded in-memory
    cache and a backing origin. ``loader``/``writer`` are host-injectable;
    the defaults are a deterministic in-memory simulator (the "origin" is a
    plain dict) so the module is usable standalone.
    """

    def __init__(self, capacity: int = 1000, default_ttl: int = 0) -> None:
        self._lock = threading.RLock()
        self._capacity = _check_capacity(capacity)
        self._default_ttl = _check_ttl(default_ttl, "default_ttl")
        self._entries: Dict[str, _Entry] = {}
        self._origin: Dict[str, Any] = {}
        self._last_seq = -1
        self._hits = 0
        self._misses = 0
        self._sets = 0
        self._invalidations = 0
        self._expirations = 0
        self._loads = 0
        self._evictions = 0
        self._audit: List[Dict[str, Any]] = []

    # -- seq discipline ----------------------------------------------------

    def _claim_seq(self, seq: Any) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise SeqOrderError("seq must be a non-negative int")
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must be strictly increasing (got {seq}, last {self._last_seq})"
            )
        self._last_seq = seq
        return seq

    def _read_seq(self, seq: Any) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise SeqOrderError("seq must be a non-negative int")

    # -- default simulated origin ------------------------------------------

    def _default_loader(self, key: str) -> Any:
        return self._origin.get(key)

    def _default_writer(self, key: str, value: Any) -> bool:
        self._origin[key] = value
        return True

    # -- internals ----------------------------------------------------------

    def _evict_if_full_locked(self, seq: int) -> Optional[str]:
        """Evict the oldest entry (FIFO by set_seq, ties by key) if the
        cache is full. Returns the evicted key digest, or None."""
        if len(self._entries) < self._capacity:
            return None
        victim = min(self._entries, key=lambda k: (self._entries[k].set_seq, k))
        digest = _key_digest(victim)
        del self._entries[victim]
        self._evictions += 1
        return digest

    def _store_locked(
        self, key: str, value: Any, seq: int, ttl: int
    ) -> Optional[str]:
        expiry = seq + ttl if ttl > 0 else None
        evicted = self._evict_if_full_locked(seq)
        self._entries[key] = _Entry(value, seq, expiry)
        return evicted

    def _live_locked(self, key: str, seq: int) -> Optional[_Entry]:
        """Return the entry if present and not expired at ``seq``; lazily
        evict expired entries."""
        entry = self._entries.get(key)
        if entry is None:
            return None
        if entry.expiry_seq is not None and entry.expiry_seq <= seq:
            del self._entries[key]
            self._expirations += 1
            self._audit.append(
                cache_aside_audit_event(
                    "expired", seq, key_digest=_key_digest(key)
                )
            )
            return None
        return entry

    def _emit_locked(self, kind: str, seq: int, **fields: Any) -> None:
        self._audit.append(cache_aside_audit_event(kind, seq, **fields))

    # -- read path ----------------------------------------------------------

    def get(
        self,
        key: str,
        seq: int,
        loader: Optional[Callable[[str], Any]] = None,
    ) -> GetResult:
        """Cache-aside read: cache first; on miss, load from the origin via
        ``loader`` (default: the simulated origin), populate the cache, and
        return. Loader failures and ``None`` returns are booked as
        ``loaded=False`` — as data."""
        _check_key(key)
        if loader is not None:
            _check_backend(loader, "loader")
        self._claim_seq(seq)
        key_d = _key_digest(key)
        with self._lock:
            entry = self._live_locked(key, seq)
            if entry is not None:
                self._hits += 1
                self._emit_locked("got", seq, key_digest=key_d, hit=True,
                                 loaded=False)
                return GetResult(
                    key_digest=key_d, hit=True, loaded=False,
                    evicted_key_digest=None, seq=seq,
                    digest=_digest("get", key_d, True, False, "", seq),
                    value=entry.value,
                )
            self._misses += 1
            loaded_value: Any = None
            loaded = False
            if loader is not None:
                load = loader
            else:
                load = self._default_loader
            try:
                loaded_value = load(key)
            except Exception:
                loaded_value = None
            if loaded_value is not None:
                try:
                    _check_value(loaded_value)
                except BadValueError:
                    loaded_value = None
            evicted: Optional[str] = None
            if loaded_value is not None:
                evicted = self._store_locked(key, loaded_value, seq,
                                            self._default_ttl)
                self._loads += 1
                loaded = True
            self._emit_locked("got", seq, key_digest=key_d, hit=False,
                             loaded=loaded)
            return GetResult(
                key_digest=key_d, hit=False, loaded=loaded,
                evicted_key_digest=evicted, seq=seq,
                digest=_digest("get", key_d, False, loaded, evicted or "", seq),
                value=loaded_value if loaded else None,
            )

    # -- write path ---------------------------------------------------------

    def set(
        self,
        key: str,
        value: Any,
        seq: int,
        writer: Optional[Callable[[str, Any], Any]] = None,
        strategy: str = STRATEGY_INVALIDATE,
        ttl: Optional[int] = None,
    ) -> SetRecord:
        """Cache-aside write: origin first, then the cache.

        ``writer`` (default: the simulated origin) persists the value; a
        writer that raises is booked as ``written=False`` — as data — and
        the cache is left untouched. On a successful write, ``strategy``
        decides the cache step: ``"invalidate"`` deletes the cached entry
        (classic delete-on-write), ``"update"`` overwrites it.
        """
        _check_key(key)
        _check_value(value)
        _check_strategy(strategy)
        if writer is not None:
            _check_backend(writer, "writer")
        use_ttl = self._default_ttl if ttl is None else _check_ttl(ttl)
        self._claim_seq(seq)
        key_d = _key_digest(key)
        val_d = _value_digest(value)
        write = writer if writer is not None else self._default_writer
        written = False
        try:
            write(key, value)
            written = True
        except Exception:
            written = False
        action = "none"
        evicted: Optional[str] = None
        with self._lock:
            if written:
                self._sets += 1
                if strategy == STRATEGY_INVALIDATE:
                    if key in self._entries:
                        del self._entries[key]
                        self._invalidations += 1
                    action = "invalidated"
                else:  # STRATEGY_UPDATE
                    # Overwrite even an expired entry: set() owns the value.
                    self._entries.pop(key, None)
                    evicted = self._evict_if_full_locked(seq)
                    self._entries[key] = _Entry(
                        value, seq, seq + use_ttl if use_ttl > 0 else None
                    )
                    action = "updated"
            self._emit_locked(
                "set", seq, key_digest=key_d, value_digest=val_d,
                written=written, strategy=strategy, cache_action=action,
            )
            return SetRecord(
                key_digest=key_d, value_digest=val_d, written=written,
                strategy=strategy, cache_action=action,
                evicted_key_digest=evicted, seq=seq,
                digest=_digest("set", key_d, val_d, written, strategy,
                              action, evicted or "", seq),
            )

    # -- invalidation --------------------------------------------------------

    def invalidate(self, key: str, seq: int) -> InvalidateRecord:
        """Explicitly evict ``key``. Idempotent: an absent key succeeds
        with ``existed=False``."""
        _check_key(key)
        self._claim_seq(seq)
        key_d = _key_digest(key)
        with self._lock:
            existed = key in self._entries
            if existed:
                del self._entries[key]
                self._invalidations += 1
            self._emit_locked("invalidated", seq, key_digest=key_d,
                             existed=existed)
            return InvalidateRecord(
                key_digest=key_d, existed=existed, seq=seq,
                digest=_digest("invalidate", key_d, existed, seq),
            )

    def expire(self, seq: int) -> ExpireReport:
        """Deterministic TTL sweep: evict every entry whose ``expiry_seq``
        is at or before ``seq``."""
        self._claim_seq(seq)
        with self._lock:
            expired = sorted(
                k for k, e in self._entries.items()
                if e.expiry_seq is not None and e.expiry_seq <= seq
            )
            digests = tuple(_key_digest(k) for k in expired)
            for k in expired:
                del self._entries[k]
            self._expirations += len(expired)
            self._emit_locked("expired", seq, count=len(expired))
            return ExpireReport(
                expired_key_digests=digests, count=len(expired), seq=seq,
                digest=_digest("expire", list(digests), len(expired), seq),
            )

    # -- views ----------------------------------------------------------------

    def stats(self, seq: int) -> StatsReport:
        """Pure read view over the counters (seq validated, not consumed).
        ``size`` counts live entries at ``seq``."""
        self._read_seq(seq)
        with self._lock:
            size = sum(
                1 for e in self._entries.values()
                if e.expiry_seq is None or e.expiry_seq > seq
            )
            return StatsReport(
                hits=self._hits, misses=self._misses, sets=self._sets,
                invalidations=self._invalidations,
                expirations=self._expirations, loads=self._loads,
                evictions=self._evictions, size=size,
                capacity=self._capacity, seq=seq,
                digest=_digest("stats", self._hits, self._misses, self._sets,
                              self._invalidations, self._expirations,
                              self._loads, self._evictions, size,
                              self._capacity, seq),
            )

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        """Return the booked audit events (oldest first)."""
        with self._lock:
            return tuple(self._audit)


def main() -> None:
    ca = CacheAside(capacity=2)
    # read path: miss, then load from the simulated origin
    r = ca.get("a", seq=1)
    assert not r.hit and not r.loaded and r.value is None, r
    ca.set("a", "va", seq=2)  # writes origin, invalidates (nothing cached)
    r = ca.get("a", seq=3)  # miss -> loads from origin -> hit booked
    assert r.loaded and r.value == "va" and r.verify(), r
    r = ca.get("a", seq=4)  # now a real cache hit
    assert r.hit and not r.loaded, r

    # write path, delete-on-write: cache entry gone after set()
    ca.set("a", "va2", seq=5, strategy="invalidate")
    r = ca.get("a", seq=6, loader=lambda k: None)  # miss, no loader value
    assert not r.hit and not r.loaded, r

    # write path, update: cache entry refreshed
    ca.set("a", "va3", seq=7, strategy="update")
    assert ca.get("a", seq=8).value == "va3"

    # writer failure is data
    def boom(k: str, v: Any) -> bool:
        raise RuntimeError("origin down")

    rec = ca.set("b", "vb", seq=9, writer=boom)
    assert not rec.written and rec.cache_action == "none" and rec.verify(), rec

    # invalidation is idempotent
    inv = ca.invalidate("nope", seq=10)
    assert not inv.existed and inv.verify(), inv

    # ttl expiry sweep
    ca.set("t", "vt", seq=11, strategy="update", ttl=2)
    rep = ca.expire(seq=13)
    assert rep.count == 1 and rep.verify(), rep

    # capacity eviction is FIFO and deterministic
    small = CacheAside(capacity=1)
    small.set("x", 1, seq=1, strategy="update")
    rec = small.set("y", 2, seq=2, strategy="update")
    assert rec.evicted_key_digest is not None
    assert small.stats(seq=3).evictions == 1

    st = ca.stats(seq=14)
    assert st.verify() and st.hits >= 1 and st.sets >= 1, st
    print("cache-aside OK: get, set, invalidate, expire, evict, pins, audit")


if __name__ == "__main__":
    main()
