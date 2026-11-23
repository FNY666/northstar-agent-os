"""Connection pool: bounded acquire/release bookkeeping for reusable connections.

Research note: connection pooling is a classic resource-management pattern —
establishing a new connection (TCP handshake, TLS negotiation, auth) is
expensive, so a bounded set of connections is created once and handed out on
demand. The load-bearing invariants are:

* **Bounded size** — ``max_size`` caps total live connections; when every
  connection is borrowed, ``acquire`` raises ``PoolExhaustedError`` instead of
  silently exceeding the budget (the backpressure surface).
* **No double-use** — a connection is either idle or borrowed, never both;
  releasing an unknown or already-idle handle raises instead of corrupting
  the ledger (double-release is a programming error, surfaced as one).
* **Idle eviction** — idle connections carry a caller-supplied ``last_used``
  tick; ``evict_idle`` drops every idle handle older than a caller-supplied
  cutoff. The pool never reads the wall clock, so the host (which knows
  "now") supplies the cutoff.
* **Invalidation** — a borrowed connection that turned out broken is
  ``invalidate``d, dropping it from the pool instead of returning a poisoned
  handle to the idle set.

Honest scope: this module books *handle ids*, not sockets. ``acquire``
mints deterministic ``conn-<n>`` ids; the host binds each id to a real
transport. The pool cannot verify a host-reported release is well-behaved
(a caller that holds a released handle and keeps writing is invisible here);
``released=True`` means "the ledger no longer considers it borrowed", never
"the peer stopped using it". Eviction closes nothing — the host owns the
actual socket lifecycle.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from typing import Any

#: Module version.
CONNECTION_POOL_VERSION = "connection-pool.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.connection-pool.v1"


class ConnectionPoolError(Exception):
    """Base class for connection-pool errors."""


class PoolConfigError(ConnectionPoolError):
    """Invalid pool configuration (programming error)."""


class PoolExhaustedError(ConnectionPoolError):
    """Raised when acquire() is called with no idle handle and size == max_size."""


class UnknownConnectionError(ConnectionPoolError):
    """Raised when a handle id is not known to the pool."""


class NotBorrowedError(ConnectionPoolError):
    """Raised when releasing/invalidating a handle that is not borrowed."""


def _check_seq(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ConnectionPoolError(f"{name} must be a non-negative int")
    return value


def _check_max_size(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise PoolConfigError("max_size must be a positive int")
    return value


def _check_conn_id(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise ConnectionPoolError("conn_id must be a non-empty str")
    return value


def _digest(body: dict[str, Any]) -> str:
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ConnectionHandle:
    """A borrowed handle. The id is bookkeeping; the host binds the transport."""

    conn_id: str
    borrow_seq: int
    digest: str
    version: str = CONNECTION_POOL_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> dict[str, Any]:
        return {
            "conn_id": self.conn_id,
            "borrow_seq": self.borrow_seq,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class EvictionReport:
    """Outcome of an evict_idle() call."""

    cutoff_seq: int
    evicted: tuple[str, ...]
    remaining_idle: int
    digest: str
    version: str = CONNECTION_POOL_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> dict[str, Any]:
        return {
            "cutoff_seq": self.cutoff_seq,
            "evicted": list(self.evicted),
            "remaining_idle": self.remaining_idle,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class PoolStats:
    """Point-in-time pool counters."""

    max_size: int
    borrowed: int
    idle: int
    created: int
    acquired_total: int
    released_total: int
    evicted_total: int
    invalidated_total: int
    exhausted_total: int
    version: str = CONNECTION_POOL_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> dict[str, Any]:
        return {
            "max_size": self.max_size,
            "borrowed": self.borrowed,
            "idle": self.idle,
            "created": self.created,
            "acquired_total": self.acquired_total,
            "released_total": self.released_total,
            "evicted_total": self.evicted_total,
            "invalidated_total": self.invalidated_total,
            "exhausted_total": self.exhausted_total,
            "version": self.version,
            "schema": self.schema,
        }


class ConnectionPool:
    """Bounded pool of connection handle ids (RLock-guarded)."""

    def __init__(self, max_size: int):
        self._max_size = _check_max_size(max_size)
        self._lock = threading.RLock()
        self._idle: dict[str, int] = {}  # conn_id -> last_used_seq (LIFO-ish: max key reused)
        self._borrowed: dict[str, int] = {}  # conn_id -> borrow_seq
        self._counter = 0
        self._created = 0
        self._acquired_total = 0
        self._released_total = 0
        self._evicted_total = 0
        self._invalidated_total = 0
        self._exhausted_total = 0

    def _mint(self) -> str:
        self._counter += 1
        return f"conn-{self._counter}"

    def acquire(self, seq: Any) -> ConnectionHandle:
        """Borrow one connection. Raises PoolExhaustedError when none available."""
        seq = _check_seq(seq, "seq")
        with self._lock:
            if self._idle:
                # Reuse the most recently used idle handle (deterministic: max last_used, then id).
                conn_id = max(self._idle, key=lambda c: (self._idle[c], c))
                del self._idle[conn_id]
            elif len(self._borrowed) < self._max_size:
                conn_id = self._mint()
                self._created += 1
            else:
                self._exhausted_total += 1
                raise PoolExhaustedError(
                    f"pool exhausted: {len(self._borrowed)} borrowed, max_size={self._max_size}"
                )
            self._borrowed[conn_id] = seq
            self._acquired_total += 1
            digest = _digest({"conn_id": conn_id, "borrow_seq": seq, "op": "acquire"})
            return ConnectionHandle(conn_id=conn_id, borrow_seq=seq, digest=digest)

    def release(self, conn_id: Any, seq: Any) -> None:
        """Return a borrowed handle to the idle set."""
        conn_id = _check_conn_id(conn_id)
        seq = _check_seq(seq, "seq")
        with self._lock:
            if conn_id not in self._borrowed and conn_id not in self._idle:
                raise UnknownConnectionError(f"unknown connection: {conn_id!r}")
            if conn_id in self._idle:
                raise NotBorrowedError(f"connection {conn_id!r} is not borrowed (already idle)")
            del self._borrowed[conn_id]
            self._idle[conn_id] = seq
            self._released_total += 1

    def invalidate(self, conn_id: Any, seq: Any) -> None:
        """Drop a borrowed handle (broken connection) — it never returns to idle."""
        conn_id = _check_conn_id(conn_id)
        _check_seq(seq, "seq")
        with self._lock:
            if conn_id not in self._borrowed and conn_id not in self._idle:
                raise UnknownConnectionError(f"unknown connection: {conn_id!r}")
            if conn_id in self._idle:
                raise NotBorrowedError(f"connection {conn_id!r} is not borrowed (idle)")
            del self._borrowed[conn_id]
            self._invalidated_total += 1

    def evict_idle(self, idle_before_seq: Any, seq: Any) -> EvictionReport:
        """Evict idle handles with last_used_seq < idle_before_seq.

        The caller supplies the cutoff (the pool has no wall clock).
        """
        idle_before_seq = _check_seq(idle_before_seq, "idle_before_seq")
        seq = _check_seq(seq, "seq")
        with self._lock:
            evicted = tuple(sorted(c for c, used in self._idle.items() if used < idle_before_seq))
            for conn_id in evicted:
                del self._idle[conn_id]
            self._evicted_total += len(evicted)
            digest = _digest(
                {"evicted": list(evicted), "cutoff_seq": idle_before_seq, "op": "evict_idle"}
            )
            return EvictionReport(
                cutoff_seq=idle_before_seq,
                evicted=evicted,
                remaining_idle=len(self._idle),
                digest=digest,
            )

    def is_borrowed(self, conn_id: Any) -> bool:
        conn_id = _check_conn_id(conn_id)
        with self._lock:
            return conn_id in self._borrowed

    def is_idle(self, conn_id: Any) -> bool:
        conn_id = _check_conn_id(conn_id)
        with self._lock:
            return conn_id in self._idle

    def stats(self) -> PoolStats:
        with self._lock:
            return PoolStats(
                max_size=self._max_size,
                borrowed=len(self._borrowed),
                idle=len(self._idle),
                created=self._created,
                acquired_total=self._acquired_total,
                released_total=self._released_total,
                evicted_total=self._evicted_total,
                invalidated_total=self._invalidated_total,
                exhausted_total=self._exhausted_total,
            )


_AUDIT_KINDS = ("acquired", "released", "evicted", "invalidated", "rejected")


def connection_pool_audit_event(
    kind: str, seq: Any, conn_id: str | None = None, detail: Any = None
) -> dict[str, Any]:
    """Shape a pool event as an ``audit.ndjson/1``-style record."""
    seq = _check_seq(seq, "seq")
    if kind not in _AUDIT_KINDS:
        raise ConnectionPoolError(f"unknown audit kind: {kind!r}")
    record: dict[str, Any] = {
        "event": "connection-pool",
        "kind": kind,
        "audit_seq": seq,
        "version": CONNECTION_POOL_VERSION,
        "schema": SCHEMA_PIN,
    }
    if conn_id is not None:
        record["conn_id"] = _check_conn_id(conn_id)
    if detail is not None:
        record["detail"] = detail
    return record


def main() -> None:
    """Self-check: acquire/release/exhaust/evict/invalidate."""
    pool = ConnectionPool(max_size=2)
    a = pool.acquire(1)
    b = pool.acquire(2)
    assert a.conn_id != b.conn_id
    assert pool.stats().borrowed == 2
    try:
        pool.acquire(3)
        raise AssertionError("expected PoolExhaustedError")
    except PoolExhaustedError:
        pass
    pool.release(a.conn_id, 4)
    c = pool.acquire(5)
    assert c.conn_id == a.conn_id, "idle handle should be reused"
    pool.invalidate(b.conn_id, 6)
    pool.release(c.conn_id, 7)  # last_used=7
    d = pool.acquire(8)  # reuse again
    pool.release(d.conn_id, 9)
    report = pool.evict_idle(idle_before_seq=10, seq=11)
    assert report.evicted == (d.conn_id,), report.evicted
    assert report.remaining_idle == 0
    stats = pool.stats()
    assert stats.created == 2 and stats.exhausted_total == 1
    print("connection-pool OK: acquire, reuse, exhaust, invalidate, evict")


if __name__ == "__main__":
    main()
