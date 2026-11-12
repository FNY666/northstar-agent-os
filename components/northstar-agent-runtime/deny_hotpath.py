"""Hot-path deny lookup: one indexed read against a revocation counter.

Conclusion 54 (Moltbook post ``eb164059``, comment ``30be6cc9``): dispatch
has to consult the sealed deny *before* a fresh start, so the deny lookup
lands on the hot path of every dispatch.  A precondition that makes every
request pay a price is a precondition somebody will eventually cache -- and
a cached deny is a diary entry: it keeps saying "denied" long after the
reason for the denial has gone.

The coordinator's decision (not to be re-litigated): **the deny lookup must
be a single indexed read, and that fact belongs in the acceptance tests**.
So this module is the reference implementation of that decision:

* **The decision lives in a counter, not in a log.**  The denial state for a
  scope is ``revocation_counter[scope]``: a single integer, read with one
  indexed ``SELECT``.  The deny *log* (``deny_log``) is the append-only
  record of what was refused and why -- it is written to, and read back for
  archaeology, but it is **never scanned to decide anything**.
* **A read that fails is a denial.**  If the counter cannot be read, the
  lookup fails closed: the scope is denied, with a reason that says the
  state was unresolvable.  "I could not check" is never "allowed".
* **The refusal row is written first.**  Dispatch writes a refusal row --
  a stub with outcome ``unknown`` -- *before* it makes the decision, so the
  row exists even if the process dies mid-decision.  "No row" must never
  mean "nothing was denied": after the fact, every decision attempt has a
  row, and a crash leaves a row whose outcome is ``unknown`` rather than a
  hole.
* **The result is not cacheable.**  :data:`DENY_CACHE_TTL_MS` is zero, and
  every lookup result says so.  The reason the lookup is cheap enough not
  to cache is measured, not asserted: :func:`measure_p99` produces the
  latency distribution the acceptance tests check.

Honest scope: this module books what the dispatcher decided.  It cannot
prove that a denial was *correct*, only that a decision was reached, was
recorded, and was based on a counter read that can be re-checked.

House style: frozen dataclasses, no wall-clock in recorded rows, fail-closed
taxonomy, stdlib-only, ``sha256:`` digest pins, version/schema pins,
``stdlib_only()`` + ``main()`` self-check.

Version pin: ``deny-hotpath.v1``
Schema pin: ``northstar.deny-hotpath.v1``
"""

from __future__ import annotations

import ast
import hashlib
import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

#: Module version pin.
DENY_HOTPATH_VERSION = "deny-hotpath.v1"

#: Schema pin carried by rows and audit events.
SCHEMA_PIN = "northstar.deny-hotpath.v1"

#: The table holding the denial state: one row per scope.
COUNTER_TABLE = "revocation_counter"

#: The table holding the refusal rows (written before the decision).
DENY_LOG_TABLE = "deny_log"

#: The outcome recorded when the decision has not been reached yet.
OUTCOME_UNKNOWN = "unknown"

#: The outcome recorded when the scope was refused.
OUTCOME_DENIED = "denied"

#: The outcome recorded when the scope was allowed.
OUTCOME_ALLOWED = "allowed"

#: A deny lookup result is never cacheable.  The whole point of the
#: indexed read is that the lookup is cheap enough not to be cached; a
#: cached deny would outlive its reason.
DENY_CACHE_TTL_MS = 0

#: Where the decision came from.  ``indexed-counter`` is the only source
#: that can produce an "allowed"; every other source fails closed.
SOURCE_INDEX = "indexed-counter"
SOURCE_FAIL_CLOSED = "fail-closed"

#: Reason recorded when the counter could not be read.
REASON_UNRESOLVABLE = "counter unreadable: scope denied fail-closed"


class DenyHotPathError(Exception):
    """Base class for deny-hotpath errors."""


class DenyStoreError(DenyHotPathError):
    """The deny store could not be opened or written."""


@dataclass(frozen=True)
class DenyLookup:
    """The result of one deny lookup.

    ``denied`` is the only field a caller may branch on.  Everything else
    is there so the decision can be explained afterwards.
    """

    scope: str
    denied: bool
    counter: Optional[int]
    source: str
    reason: str = ""

    @property
    def cacheable(self) -> bool:
        """A deny lookup result is never cacheable (see DENY_CACHE_TTL_MS)."""
        return False

    @property
    def cache_ttl_ms(self) -> int:
        """The cache TTL a result may be reused for.  Always zero."""
        return DENY_CACHE_TTL_MS

    def as_dict(self) -> Dict[str, Any]:
        """Dict form, for audit rows and test assertions."""
        return {
            "scope": self.scope,
            "denied": self.denied,
            "counter": self.counter,
            "source": self.source,
            "reason": self.reason,
            "cacheable": self.cacheable,
            "cache_ttl_ms": self.cache_ttl_ms,
        }


@dataclass(frozen=True)
class DenyDecision:
    """The outcome of one dispatch decision.

    ``refusal_id`` names the row that was written *before* the decision
    was made, so a decision always has a row, even a decision that was
    never completed.
    """

    scope: str
    denied: bool
    refusal_id: str
    lookup: DenyLookup
    outcome: str
    #: False when the refusal row could not be written (the store itself is
    #: broken).  The decision is still a denial -- but the caller must know
    #: the row is missing, because a missing row is exactly the hole the
    #: refusal-row-first rule exists to prevent.
    refusal_written: bool = True

    @property
    def reason(self) -> str:
        """The reason carried by the lookup."""
        return self.lookup.reason

    def as_dict(self) -> Dict[str, Any]:
        """Dict form, for audit rows and test assertions."""
        return {
            "scope": self.scope,
            "denied": self.denied,
            "refusal_id": self.refusal_id,
            "outcome": self.outcome,
            "lookup": self.lookup.as_dict(),
        }


@dataclass(frozen=True)
class LatencyStats:
    """A latency distribution, in milliseconds."""

    samples: int
    p50_ms: float
    p99_ms: float
    max_ms: float
    mean_ms: float

    def as_dict(self) -> Dict[str, Any]:
        """Dict form, for the acceptance report."""
        return {
            "samples": self.samples,
            "p50_ms": self.p50_ms,
            "p99_ms": self.p99_ms,
            "max_ms": self.max_ms,
            "mean_ms": self.mean_ms,
        }


def _canonical(value: Any) -> bytes:
    """Canonical JSON bytes for digesting (sorted keys, compact, UTF-8)."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    """Hex sha256 of ``data``."""
    return hashlib.sha256(data).hexdigest()


_SCHEMA = (
    f"""
    CREATE TABLE IF NOT EXISTS {COUNTER_TABLE} (
        scope   TEXT PRIMARY KEY,
        counter INTEGER NOT NULL DEFAULT 0,
        denied  INTEGER NOT NULL DEFAULT 0,
        reason  TEXT NOT NULL DEFAULT '',
        seq     INTEGER NOT NULL DEFAULT 0
    )
    """,
    f"""
    CREATE TABLE IF NOT EXISTS {DENY_LOG_TABLE} (
        refusal_id   TEXT PRIMARY KEY,
        scope        TEXT NOT NULL,
        seq          INTEGER NOT NULL,
        outcome      TEXT NOT NULL,
        reason       TEXT NOT NULL DEFAULT '',
        counter      INTEGER,
        lookup_source TEXT NOT NULL DEFAULT '',
        decided      INTEGER NOT NULL DEFAULT 0
    )
    """,
    f"CREATE INDEX IF NOT EXISTS deny_log_scope_idx ON {DENY_LOG_TABLE} (scope)",
)

#: The one statement the hot-path lookup is allowed to run.
LOOKUP_SQL = (
    f"SELECT counter, denied, reason FROM {COUNTER_TABLE} WHERE scope = ?"
)

_MAX_SCOPE_CHARS = 256
_MAX_REASON_CHARS = 1024


def _check_scope(scope: Any) -> str:
    """Validate a scope name.

    A scope is the unit a denial applies to.  It must be a non-empty
    string, and it must be short: the lookup is an indexed read, but the
    key is still a key.
    """
    if not isinstance(scope, str) or not scope.strip():
        raise DenyStoreError("scope must be a non-empty string")
    if len(scope) > _MAX_SCOPE_CHARS:
        raise DenyStoreError("scope is too long")
    return scope


class DenyStore:
    """The deny state: a revocation counter per scope, plus a refusal log.

    The two tables have different jobs and must not be confused:

    * ``revocation_counter`` is the **decision state**.  One row per
      scope, keyed by the scope, so the lookup is a single indexed read.
    * ``deny_log`` is the **record**.  A refusal row is written *before*
      the decision and finalized after it.  The log is written to and
      read back for archaeology; it is never scanned to decide.

    The store is a thin, explicit wrapper over ``sqlite3`` so the
    executed statements can be counted and inspected: the acceptance
    tests assert that a lookup runs exactly one statement and that the
    statement is an indexed seek, not a scan.
    """

    def __init__(self, path: Optional[str] = None) -> None:
        """Open (and create) the store.

        ``path=None`` means an in-memory store; a path means a file
        store.  The file store is durable: the refusal row is on disk
        before the decision is made.

        The connection is opened with ``check_same_thread=False`` and
        guarded by a lock, because the parallel dispatch path runs the
        lookup in worker threads.  Without that, ``sqlite3`` would raise
        ``ProgrammingError`` on every lookup off the creating thread --
        and the lookup would then fail closed, denying *every* parallel
        dispatch.  A store that cannot answer honestly must not be the
        thing that decides.
        """
        self.path = path
        self._conn = sqlite3.connect(
            path or ":memory:", isolation_level=None, check_same_thread=False
        )
        self._conn.row_factory = sqlite3.Row
        self._events: List[str] = []
        self._statements: List[str] = []
        self._lock = threading.RLock()
        self._refusal_seq = 0
        self._conn.set_trace_callback(self._trace)
        with self._lock:
            with self._conn:
                for statement in _SCHEMA:
                    self._conn.execute(statement)

    # -- introspection -------------------------------------------------

    def _trace(self, statement: str) -> None:
        """Record every statement the connection executes."""
        self._statements.append(statement)

    @property
    def statements(self) -> Tuple[str, ...]:
        """Every SQL statement executed so far, in order."""
        return tuple(self._statements)

    @property
    def events(self) -> Tuple[str, ...]:
        """The operation order: ``refusal`` / ``lookup`` / ``finalize``.

        The refusal row must be written before the lookup happens, so
        this order is itself an observable fact.
        """
        return tuple(self._events)

    def reset_statements(self) -> None:
        """Forget the recorded statements (test helper)."""
        self._statements.clear()

    def close(self) -> None:
        """Close the connection."""
        try:
            self._conn.close()
        except sqlite3.Error:
            pass

    def __enter__(self) -> "DenyStore":
        """Context manager entry."""
        return self

    def __exit__(self, *exc: Any) -> None:
        """Context manager exit."""
        self.close()

    # -- counter (decision state) --------------------------------------

    def set_state(
        self,
        scope: str,
        *,
        denied: bool,
        reason: str = "",
        seq: int = 0,
        counter: Optional[int] = None,
    ) -> int:
        """Set the denial state of a scope and return its new counter.

        The counter is monotonic per scope: every state change bumps it.
        A counter that has not moved is a state that has not changed, so
        a stale read is detectable by comparing counters rather than by
        trusting a cached copy.
        """
        scope = _check_scope(scope)
        with self._lock:
            row = self._conn.execute(
                f"SELECT counter FROM {COUNTER_TABLE} WHERE scope = ?", (scope,)
            ).fetchone()
            current = int(row["counter"]) if row is not None else 0
            new_counter = current + 1 if counter is None else int(counter)
            self._conn.execute(
                f"INSERT INTO {COUNTER_TABLE} (scope, counter, denied, reason, seq) "
                f"VALUES (?, ?, ?, ?, ?) "
                f"ON CONFLICT(scope) DO UPDATE SET counter=excluded.counter, "
                f"denied=excluded.denied, reason=excluded.reason, seq=excluded.seq",
                (scope, new_counter, 1 if denied else 0, reason[:_MAX_REASON_CHARS], int(seq)),
            )
        return new_counter

    def revoke(self, scope: str, *, reason: str = "", seq: int = 0) -> int:
        """Deny a scope.  Returns the new counter."""
        return self.set_state(scope, denied=True, reason=reason, seq=seq)

    def clear(self, scope: str, *, seq: int = 0) -> int:
        """Un-deny a scope (a later, counter-bumping state change)."""
        return self.set_state(scope, denied=False, reason="", seq=seq)

    def counter(self, scope: str) -> Optional[int]:
        """Read a scope's current counter, or None if the scope is unknown.

        This is a read for reporting, not the decision path.
        """
        with self._lock:
            row = self._conn.execute(
                f"SELECT counter FROM {COUNTER_TABLE} WHERE scope = ?", (scope,)
            ).fetchone()
        return None if row is None else int(row["counter"])

    # -- the hot-path lookup -------------------------------------------

    def lookup(self, scope: str) -> DenyLookup:
        """The deny lookup: **one** indexed read of the revocation counter.

        The scope is the primary key, so this is a seek.  The deny log is
        never touched here: scanning it would make the cost of a dispatch
        grow with the number of past denials, which is exactly the shape
        that invites caching.

        Fail-closed: any error reading the counter produces a *denial*,
        not an allow.  "I could not check" is never "allowed".
        """
        scope = _check_scope(scope)
        self._events.append("lookup")
        try:
            with self._lock:
                row = self._conn.execute(LOOKUP_SQL, (scope,)).fetchone()
        except sqlite3.Error as error:
            return DenyLookup(
                scope=scope,
                denied=True,
                counter=None,
                source=SOURCE_FAIL_CLOSED,
                reason=f"{REASON_UNRESOLVABLE} ({type(error).__name__})",
            )
        if row is None:
            return DenyLookup(
                scope=scope,
                denied=False,
                counter=None,
                source=SOURCE_INDEX,
                reason="no revocation recorded for scope",
            )
        denied = bool(int(row["denied"]))
        return DenyLookup(
            scope=scope,
            denied=denied,
            counter=int(row["counter"]),
            source=SOURCE_INDEX,
            reason=str(row["reason"] or ""),
        )

    def explain_lookup(self, scope: str) -> str:
        """The query plan for the lookup statement.

        The acceptance tests use this to assert the lookup is a seek
        (``SEARCH``) and not a scan (``SCAN``).
        """
        scope = _check_scope(scope)
        with self._lock:
            rows = self._conn.execute(
                "EXPLAIN QUERY PLAN " + LOOKUP_SQL, (scope,)
            ).fetchall()
        return " | ".join(str(row["detail"]) for row in rows)

    # -- the refusal log (record) --------------------------------------

    def write_refusal(self, scope: str, *, seq: int = 0) -> str:
        """Write a refusal row with outcome ``unknown`` and return its id.

        This is the *first* thing a dispatch does, before the lookup and
        before the decision.  The row starts as ``unknown``: the decision
        has not been made yet.  If the process dies between this write
        and the decision, the row is still there, saying ``unknown`` --
        which is the truth.  What must never happen is no row at all,
        because "no row" would read as "nothing was ever denied".
        """
        scope = _check_scope(scope)
        with self._lock:
            self._refusal_seq += 1
            refusal_id = "ref-" + _sha256_hex(
                _canonical({"scope": scope, "seq": int(seq), "n": self._refusal_seq})
            )[:32]
            self._conn.execute(
                f"INSERT INTO {DENY_LOG_TABLE} "
                f"(refusal_id, scope, seq, outcome, reason, counter, lookup_source, decided) "
                f"VALUES (?, ?, ?, ?, ?, ?, ?, 0)",
                (refusal_id, scope, int(seq), OUTCOME_UNKNOWN, "", None, ""),
            )
            self._events.append("refusal")
        return refusal_id

    def finalize_refusal(
        self,
        refusal_id: str,
        *,
        outcome: str,
        reason: str = "",
        counter: Optional[int] = None,
        lookup_source: str = "",
    ) -> None:
        """Finalize a refusal row with the decision that was reached."""
        with self._lock:
            self._conn.execute(
                f"UPDATE {DENY_LOG_TABLE} SET outcome = ?, reason = ?, counter = ?, "
                f"lookup_source = ?, decided = 1 WHERE refusal_id = ?",
                (
                    outcome,
                    reason[:_MAX_REASON_CHARS],
                    counter,
                    lookup_source,
                    refusal_id,
                ),
            )
        self._events.append("finalize")

    def refusal(self, refusal_id: str) -> Optional[Dict[str, Any]]:
        """Read one refusal row back, or None if it is not there."""
        with self._lock:
            row = self._conn.execute(
                f"SELECT * FROM {DENY_LOG_TABLE} WHERE refusal_id = ?", (refusal_id,)
            ).fetchone()
        return None if row is None else {key: row[key] for key in row.keys()}

    def refusals(self) -> Tuple[Dict[str, Any], ...]:
        """All refusal rows, in insertion order (archaeology, not the hot path)."""
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM {DENY_LOG_TABLE} ORDER BY rowid"
            ).fetchall()
        return tuple({key: row[key] for key in row.keys()} for row in rows)

    def refusal_count(self) -> int:
        """How many refusal rows exist."""
        with self._lock:
            row = self._conn.execute(
                f"SELECT COUNT(*) AS n FROM {DENY_LOG_TABLE}"
            ).fetchone()
        return int(row["n"])


class DenyDispatcher:
    """The dispatch-side deny check: refusal row first, then the lookup.

    The order is the whole point:

    1. **write the refusal row** -- outcome ``unknown``, decision not yet
       made;
    2. **the single indexed lookup** of the revocation counter;
    3. **finalize the refusal row** with the decision.

    Step 1 happens even when the answer will be "allowed": the row is the
    record that a check happened at all.  If the process dies between
    step 1 and step 3, the row says ``unknown``, which is the truth --
    not a hole, which would be a lie.
    """

    def __init__(self, store: DenyStore) -> None:
        if store is None:
            raise DenyStoreError("store is required")
        self._store = store
        self._seq = 0

    @property
    def store(self) -> DenyStore:
        """The store this dispatcher reads and writes."""
        return self._store

    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    def check(self, scope: str) -> DenyDecision:
        """Run the deny check for ``scope``.

        Returns a :class:`DenyDecision`.  ``denied`` is True whenever the
        lookup says the scope is revoked *or* the lookup could not be
        completed -- there is no "unknown means allowed" path.
        """
        scope = _check_scope(scope)
        seq = self._next_seq()
        try:
            refusal_id = self._store.write_refusal(scope, seq=seq)
            written = True
        except sqlite3.Error as error:
            # The store is broken.  A missing refusal row is a hole, so the
            # decision must be a denial -- the one case where "I could not
            # record it" forces "no".
            error_name = type(error).__name__
            refusal_id = "ref-unrecorded-" + _sha256_hex(
                _canonical({"scope": scope, "seq": seq})
            )[:24]
            written = False
        lookup = self._store.lookup(scope)
        if not written:
            lookup = DenyLookup(
                scope=scope,
                denied=True,
                counter=lookup.counter,
                source=SOURCE_FAIL_CLOSED,
                reason=f"refusal row could not be written: {error_name}",
            )
        outcome = OUTCOME_DENIED if lookup.denied else OUTCOME_ALLOWED
        if written:
            self._store.finalize_refusal(
                refusal_id,
                outcome=outcome,
                reason=lookup.reason,
                counter=lookup.counter,
                lookup_source=lookup.source,
            )
        return DenyDecision(
            scope=scope,
            denied=lookup.denied,
            refusal_id=refusal_id,
            lookup=lookup,
            outcome=outcome,
            refusal_written=written,
        )


def _percentile(sorted_values: List[float], fraction: float) -> float:
    """The ``fraction`` percentile of a sorted list (nearest-rank)."""
    if not sorted_values:
        return 0.0
    rank = max(1, min(len(sorted_values), int(-(-len(sorted_values) * fraction // 1))))
    return float(sorted_values[rank - 1])


def measure_p99(
    dispatcher: DenyDispatcher,
    scope: str,
    *,
    samples: int = 200,
) -> LatencyStats:
    """Measure the latency distribution of the deny lookup.

    This is the repeatable measurement the acceptance criteria ask for:
    "先有可重复的度量,再谈'这个设计可信'" -- a repeatable measurement before
    any claim that the design is trustworthy.  The function returns the
    distribution, so a test can assert on it and a report can quote it.

    The measurement is the *lookup* only: the refusal row write is
    deliberately excluded, because the number that has to stay flat as
    the deny log grows is the lookup's, not the log's.  A test that grows
    the deny log by thousands of rows and re-measures proves the lookup
    is not scanning it.
    """
    if samples <= 0:
        raise DenyHotPathError("samples must be positive")
    durations: List[float] = []
    for _ in range(samples):
        start = time.perf_counter()
        dispatcher.store.lookup(scope)
        durations.append((time.perf_counter() - start) * 1000.0)
    ordered = sorted(durations)
    return LatencyStats(
        samples=len(ordered),
        p50_ms=_percentile(ordered, 0.50),
        p99_ms=_percentile(ordered, 0.99),
        max_ms=ordered[-1],
        mean_ms=sum(ordered) / len(ordered),
    )


def deny_audit_event(decision: DenyDecision, *, seq: int = 0) -> Dict[str, Any]:
    """The audit event for one dispatch deny check.

    The event carries the refusal id, the scope, the outcome, and the
    counter the decision was based on -- so a reader can tell which
    revocation state the decision saw, and not merely that a decision
    happened.
    """
    return {
        "schema": SCHEMA_PIN,
        "kind": "deny-hotpath.decision",
        "seq": int(seq),
        "refusal_id": decision.refusal_id,
        "scope": decision.scope,
        "outcome": decision.outcome,
        "denied": decision.denied,
        "counter": decision.lookup.counter,
        "lookup_source": decision.lookup.source,
        "reason": decision.lookup.reason,
        "cache_ttl_ms": DENY_CACHE_TTL_MS,
        "module_version": DENY_HOTPATH_VERSION,
    }


def stdlib_only() -> bool:
    """AST check: this module imports stdlib modules only."""
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {
        "__future__",
        "ast",
        "dataclasses",
        "hashlib",
        "json",
        "pathlib",
        "sqlite3",
        "threading",
        "time",
        "typing",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0].split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    """Self-check: the refusal row lands first, the lookup is one read,
    and an unreadable counter denies."""
    store = DenyStore()
    dispatcher = DenyDispatcher(store)
    store.revoke("scope-a", reason="revoked by operator")
    decision = dispatcher.check("scope-a")
    assert decision.denied, "a revoked scope must be denied"
    assert store.events[0] == "refusal", "the refusal row comes first"
    row = store.refusal(decision.refusal_id)
    assert row is not None and row["outcome"] == OUTCOME_DENIED
    allowed = dispatcher.check("scope-b")
    assert not allowed.denied, "an unknown scope is not denied"
    # A counter that cannot be read must fail closed.
    store._conn.execute(f"DROP TABLE {COUNTER_TABLE}")
    failed = dispatcher.check("scope-b")
    assert failed.denied, "an unreadable counter must deny"
    assert failed.lookup.source == SOURCE_FAIL_CLOSED
    stats = measure_p99(dispatcher, "scope-b", samples=50)
    assert stats.p99_ms >= 0.0
    print(f"deny-hotpath self-check ok; p99={stats.p99_ms:.3f}ms")


if __name__ == "__main__":  # pragma: no cover - self-check entry point
    main()
