"""Materialized view: deferred-refresh view maintenance bookkeeping.

Research note: a *materialized view* is a precomputed query result stored
like a table. The defining maintenance question is *when* to recompute.
*Refresh-on-commit* recomputes eagerly inside every base-table write
transaction (always fresh, write amplification); *refresh-on-demand*
(``REFRESH MATERIALIZED VIEW`` in PostgreSQL) recomputes lazily when asked,
marking the view stale on every base change in between. This module is
refresh-on-demand only: base changes book deltas and flip a ``stale``
flag; :meth:`refresh` recomputes; :meth:`query` reads the last materialized
snapshot and reports ``fresh`` as data, never raising on staleness.

* **base_upsert(key, value, seq)** — host-reported base-row insert/overwrite;
  values are pinned by digest; the view is marked stale and a pending delta
  is booked.
* **base_delete(key, seq)** — host-reported base-row delete; unknown keys
  are refused fail-closed.
* **refresh(seq)** — recompute the view from the base rows; books whether
  the result changed (digest compare), clears staleness and the delta
  backlog.
* **query(key, seq)** — read the materialized snapshot (pure read: seq
  shape validated, never consumed). For ``select`` pass a key; for
  ``count``/``sum``/``avg`` omit it.
* **invalidate(seq)** — operator-forced staleness (base changed out of
  band); queries report ``fresh=False`` until the next refresh.

Query kinds: ``select`` (identity projection over pinned rows),
``count`` (row count), ``sum`` (integer total), ``avg`` (exact
``"sum/count"`` text — no floats anywhere, no wall-clock anywhere).

Fail-closed: bad ids/keys/values/query kinds and seq regressions are
programming errors and raise :class:`MaterializedViewError`. A stale view
is not an error — ``fresh`` is data. Base contents are host-reported
(GIGO): this ledger cannot prove the base table holds what the host
claimed.

Honest scope: this is *bookkeeping* for a refresh-on-demand view, not a
query engine. No SQL is parsed; predicates are not supported; there is no
incremental per-row delta application (each refresh recomputes from the
full base) — the "pending delta" counter is a staleness metric, not a
materialized delta log. A fresh view means "matches the host-reported
base at the last refresh seq", never "matches a real database".

Version pin: materialized-view.v1
Schema pin: northstar.materialized-view.v1
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    _cj = None  # type: ignore

#: Module version.
MATERIALIZED_VIEW_VERSION = "materialized-view.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.materialized-view.v1"

#: Schema pin for audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Pinned query-kind vocabulary.
QUERY_KINDS = ("select", "count", "sum", "avg")

_MAX_ID_LEN = 256
_MAX_KEY_LEN = 4096
_MAX_SAFE_INT = 2**53


class MaterializedViewError(Exception):
    """Malformed use of the materialized-view contract (programming error)."""


class BadViewError(MaterializedViewError):
    """view_id failed validation (non-str, empty, or too long)."""


class BadQueryError(MaterializedViewError):
    """query_kind is not one of the pinned vocabulary."""


class BadKeyError(MaterializedViewError):
    """Key failed validation (non-str, empty, or too long)."""


class BadValueError(MaterializedViewError):
    """Value failed validation (unsafe type or out of range)."""


class UnknownKeyError(MaterializedViewError):
    """A mutation referenced a key with no base row."""


class SeqOrderError(MaterializedViewError):
    """seq failed validation or regressed (not strictly increasing)."""


class AuditKindError(MaterializedViewError):
    """Unknown audit kind or banned field in the audit builder."""


def _check_str(value: Any, exc: type, what: str, max_len: int) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise exc(f"{what} must be a str, got {type(value).__name__}")
    if not value:
        raise exc(f"{what} must not be empty")
    if len(value) > max_len:
        raise exc(f"{what} too long (>{max_len} chars)")
    return value


def _check_seq_shape(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"seq must be an int, got {type(seq).__name__}")
    if seq < 0:
        raise SeqOrderError(f"seq must be >= 0, got {seq}")
    return seq


def _check_query_kind(kind: Any) -> str:
    if isinstance(kind, bool) or not isinstance(kind, str):
        raise BadQueryError(
            f"query_kind must be a str, got {type(kind).__name__}"
        )
    if kind not in QUERY_KINDS:
        raise BadQueryError(
            f"query_kind must be one of {sorted(QUERY_KINDS)}, got {kind!r}"
        )
    return kind


def _check_value(value: Any, query_kind: str) -> Any:
    """Validate a base-row value; values are digest-pinned, never logged."""
    if value is None:
        raise BadValueError("value must not be None")
    if isinstance(value, bool):
        if query_kind in ("sum", "avg"):
            raise BadValueError("bool values refused for sum/avg")
        return value
    if isinstance(value, int):
        if abs(value) >= _MAX_SAFE_INT:
            raise BadValueError(f"int outside safe range (|n| >= 2^53)")
        return value
    if isinstance(value, float):
        if query_kind in ("sum", "avg"):
            raise BadValueError("float values refused for sum/avg")
        if value != value or value in (float("inf"), float("-inf")):
            raise BadValueError("non-finite float refused")
        return value
    if isinstance(value, str):
        return value
    raise BadValueError(f"value type not supported: {type(value).__name__}")


def _canonical(payload: Any) -> bytes:
    if _cj is not None:
        return _cj.jcs_dumps(payload).encode("utf-8")  # type: ignore
    import json

    def _tag(v: Any) -> Any:
        if isinstance(v, bool):
            return {"t": "bool", "v": v}
        if isinstance(v, int):
            if abs(v) >= 2**53:
                raise MaterializedViewError("integer outside safe range")
            return {"t": "int", "v": v}
        if isinstance(v, float):
            if v != v or v in (float("inf"), float("-inf")):
                raise MaterializedViewError("non-finite float refused")
            return {"t": "float", "v": v}
        if isinstance(v, str):
            return {"t": "str", "v": v}
        if isinstance(v, (list, tuple)):
            return {"t": "list", "v": [_tag(x) for x in v]}
        if isinstance(v, dict):
            return {"t": "dict", "v": [[_tag(k), _tag(x)] for k, x in sorted(v.items())]}
        if v is None:
            return {"t": "null"}
        raise MaterializedViewError(f"cannot canonicalize {type(v).__name__}")

    return json.dumps(_tag(payload), sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def _digest(payload: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(payload)).hexdigest()


def _digest_key(key: str) -> str:
    return "sha256:" + hashlib.sha256(key.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class BaseRowRecord:
    """One booked base-row change (frozen record)."""

    version: str
    view_id: str
    key_digest: str
    value_digest: Optional[str]
    present: bool  # False for deletes

    def verify(self) -> bool:
        return self.version == MATERIALIZED_VIEW_VERSION and bool(self.key_digest)

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "version": self.version,
            "view_id": self.view_id,
            "key_digest": self.key_digest,
            "value_digest": self.value_digest,
            "present": self.present,
        }


@dataclass(frozen=True)
class RefreshRecord:
    """One refresh (frozen record)."""

    version: str
    view_id: str
    refresh_no: int
    changed: bool
    rows: int
    result_digest: str
    stale_before: bool
    deltas_applied: int

    def verify(self) -> bool:
        return (
            self.version == MATERIALIZED_VIEW_VERSION
            and self.refresh_no >= 1
            and self.result_digest.startswith("sha256:")
        )

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "version": self.version,
            "view_id": self.view_id,
            "refresh_no": self.refresh_no,
            "changed": self.changed,
            "rows": self.rows,
            "result_digest": self.result_digest,
            "stale_before": self.stale_before,
            "deltas_applied": self.deltas_applied,
        }


@dataclass(frozen=True)
class QueryResult:
    """One query over the materialized snapshot (frozen record).

    ``fresh`` is False when the view is stale; staleness is data, never
    raised. ``found`` is False for unknown select keys (data, not error).
    """

    version: str
    view_id: str
    fresh: bool
    query_kind: str
    key_digest: Optional[str]
    found: bool
    value: Any = None
    result_digest: Optional[str] = None

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "version": self.version,
            "view_id": self.view_id,
            "fresh": self.fresh,
            "query_kind": self.query_kind,
            "key_digest": self.key_digest,
            "found": self.found,
            "value": self.value if self.found else None,
            "result_digest": self.result_digest,
        }


@dataclass(frozen=True)
class InvalidateRecord:
    """One operator-forced invalidation (frozen record)."""

    version: str
    view_id: str
    reason: str

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "version": self.version,
            "view_id": self.view_id,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class ViewStats:
    """Counter snapshot (frozen record)."""

    version: str
    view_id: str
    query_kind: str
    base_rows: int
    refreshes: int
    stale: bool
    pending_deltas: int
    queries: int
    upserts: int
    deletes: int
    invalidations: int

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "version": self.version,
            "view_id": self.view_id,
            "query_kind": self.query_kind,
            "base_rows": self.base_rows,
            "refreshes": self.refreshes,
            "stale": self.stale,
            "pending_deltas": self.pending_deltas,
            "queries": self.queries,
            "upserts": self.upserts,
            "deletes": self.deletes,
            "invalidations": self.invalidations,
        }


class MaterializedView:
    """Refresh-on-demand materialized view bookkeeping.

    Base rows are host-reported (GIGO). Every base change marks the view
    stale and books a pending delta; :meth:`refresh` recomputes and clears.
    Queries read the last materialized snapshot. Deterministic: no
    wall-clock, caller seqs strictly increasing, RLock-guarded.
    """

    def __init__(self, view_id: str, query_kind: str) -> None:
        self._view_id = _check_str(view_id, BadViewError, "view_id", _MAX_ID_LEN)
        self._query_kind = _check_query_kind(query_kind)
        self._lock = threading.RLock()
        self._base: Dict[str, Any] = {}  # key -> value (host-reported)
        self._materialized: Dict[str, Any] = {}  # key -> value at last refresh
        self._aggregate: Any = None  # materialized aggregate for count/sum/avg
        self._last_seq = 0
        self._stale = False
        self._pending_deltas = 0
        self._refresh_no = 0
        self._queries = 0
        self._upserts = 0
        self._deletes = 0
        self._invalidations = 0
        self._audit: List[dict] = []

    @property
    def view_id(self) -> str:
        return self._view_id

    @property
    def query_kind(self) -> str:
        return self._query_kind

    def _claim(self, seq: int) -> int:
        """Claim a fresh strictly-increasing seq (batch-21 discipline)."""
        _check_seq_shape(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must strictly increase (last={self._last_seq}, got={seq})"
            )
        self._last_seq = seq
        return seq

    def _emit(self, kind: str, seq: int, **fields: Any) -> None:
        self._audit.append(
            materialized_view_audit_event(
                kind, seq, view_id=self._view_id, **fields
            )
        )

    def _result_digest(self, rows: Dict[str, Any], aggregate: Any) -> str:
        pairs = sorted(
            (k, _digest(v)) for k, v in rows.items()
        )
        return _digest(
            {
                "kind": self._query_kind,
                "rows": pairs,
                "aggregate": aggregate,
            }
        )

    def _recompute(self) -> Tuple[Dict[str, Any], Any]:
        """Recompute the materialized snapshot from the base rows."""
        snapshot = dict(self._base)
        if self._query_kind == "select":
            aggregate = None
        elif self._query_kind == "count":
            aggregate = len(snapshot)
        else:  # sum / avg over validated ints
            total = sum(v for v in snapshot.values())
            if self._query_kind == "sum":
                aggregate = total
            else:
                n = len(snapshot)
                aggregate = f"{total}/{n}" if n else "0/0"
        return snapshot, aggregate

    def base_upsert(self, key: str, value: Any, seq: int) -> BaseRowRecord:
        """Book a base-row insert/overwrite; marks the view stale."""
        with self._lock:
            _check_str(key, BadKeyError, "key", _MAX_KEY_LEN)
            _check_value(value, self._query_kind)
            self._claim(seq)
            self._base[key] = value
            self._stale = True
            self._pending_deltas += 1
            self._upserts += 1
            rec = BaseRowRecord(
                version=MATERIALIZED_VIEW_VERSION,
                view_id=self._view_id,
                key_digest=_digest_key(key),
                value_digest=_digest(value),
                present=True,
            )
            self._emit(
                "base-upserted", seq, key_digest=rec.key_digest
            )
            return rec

    def base_delete(self, key: str, seq: int) -> BaseRowRecord:
        """Book a base-row delete; unknown keys refused fail-closed."""
        with self._lock:
            _check_str(key, BadKeyError, "key", _MAX_KEY_LEN)
            self._claim(seq)
            if key not in self._base:
                self._emit("rejected", seq, reason="unknown-key")
                raise UnknownKeyError(f"no base row for key digest {_digest_key(key)}")
            del self._base[key]
            self._stale = True
            self._pending_deltas += 1
            self._deletes += 1
            rec = BaseRowRecord(
                version=MATERIALIZED_VIEW_VERSION,
                view_id=self._view_id,
                key_digest=_digest_key(key),
                value_digest=None,
                present=False,
            )
            self._emit("base-deleted", seq, key_digest=rec.key_digest)
            return rec

    def refresh(self, seq: int) -> RefreshRecord:
        """Recompute the view from base rows; clears staleness and deltas."""
        with self._lock:
            self._claim(seq)
            stale_before = self._stale
            deltas = self._pending_deltas
            old_digest = self._result_digest(self._materialized, self._aggregate)
            self._materialized, self._aggregate = self._recompute()
            new_digest = self._result_digest(self._materialized, self._aggregate)
            self._refresh_no += 1
            self._stale = False
            self._pending_deltas = 0
            rec = RefreshRecord(
                version=MATERIALIZED_VIEW_VERSION,
                view_id=self._view_id,
                refresh_no=self._refresh_no,
                changed=new_digest != old_digest,
                rows=len(self._materialized),
                result_digest=new_digest,
                stale_before=stale_before,
                deltas_applied=deltas,
            )
            self._emit(
                "refreshed",
                seq,
                refresh_no=rec.refresh_no,
                changed=rec.changed,
                rows=rec.rows,
            )
            return rec

    def query(self, seq: int, key: Optional[str] = None) -> QueryResult:
        """Read the materialized snapshot (pure read; seq validated, not consumed)."""
        with self._lock:
            _check_seq_shape(seq)
            self._queries += 1
            if self._query_kind == "select":
                if key is None:
                    raise BadKeyError("select queries require a key")
                _check_str(key, BadKeyError, "key", _MAX_KEY_LEN)
                if key in self._materialized:
                    return QueryResult(
                        version=MATERIALIZED_VIEW_VERSION,
                        view_id=self._view_id,
                        fresh=not self._stale,
                        query_kind=self._query_kind,
                        key_digest=_digest_key(key),
                        found=True,
                        value=self._materialized[key],
                        result_digest=self._result_digest(
                            self._materialized, self._aggregate
                        ),
                    )
                return QueryResult(
                    version=MATERIALIZED_VIEW_VERSION,
                    view_id=self._view_id,
                    fresh=not self._stale,
                    query_kind=self._query_kind,
                    key_digest=_digest_key(key),
                    found=False,
                )
            if key is not None:
                raise BadKeyError(
                    f"{self._query_kind} queries take no key"
                )
            return QueryResult(
                version=MATERIALIZED_VIEW_VERSION,
                view_id=self._view_id,
                fresh=not self._stale,
                query_kind=self._query_kind,
                key_digest=None,
                found=True,
                value=self._aggregate,
                result_digest=self._result_digest(
                    self._materialized, self._aggregate
                ),
            )

    def invalidate(self, seq: int, reason: str = "operator") -> InvalidateRecord:
        """Mark the view stale without recomputing (base changed out of band)."""
        with self._lock:
            _check_str(reason, BadValueError, "reason", _MAX_ID_LEN)
            self._claim(seq)
            self._stale = True
            self._invalidations += 1
            rec = InvalidateRecord(
                version=MATERIALIZED_VIEW_VERSION,
                view_id=self._view_id,
                reason=reason,
            )
            self._emit("invalidated", seq, reason=reason)
            return rec

    def is_stale(self) -> bool:
        """Whether the view is stale (pure view, no seq)."""
        with self._lock:
            return self._stale

    def stats(self) -> ViewStats:
        """Counter snapshot (pure view, no seq consumed)."""
        with self._lock:
            return ViewStats(
                version=MATERIALIZED_VIEW_VERSION,
                view_id=self._view_id,
                query_kind=self._query_kind,
                base_rows=len(self._base),
                refreshes=self._refresh_no,
                stale=self._stale,
                pending_deltas=self._pending_deltas,
                queries=self._queries,
                upserts=self._upserts,
                deletes=self._deletes,
                invalidations=self._invalidations,
            )

    def audit_log(self) -> Tuple[dict, ...]:
        return tuple(self._audit)


def materialized_view_audit_event(kind: str, seq: int, **fields: Any) -> dict:
    """Shape an ``audit.ndjson/1`` record for a materialized-view event."""
    allowed = {
        "base-upserted",
        "base-deleted",
        "refreshed",
        "invalidated",
        "rejected",
    }
    if kind not in allowed:
        raise AuditKindError(
            f"unknown audit kind {kind!r}; allowed: {sorted(allowed)}"
        )
    _check_seq_shape(seq)
    record = {
        "schema": AUDIT_SCHEMA,
        "kind": f"materialized-view.{kind}",
        "module": MATERIALIZED_VIEW_VERSION,
        "seq": seq,
    }
    for k, v in fields.items():
        if k in ("value", "payload", "row", "rows_data"):
            raise AuditKindError(
                "raw values are never logged; pass digests"
            )
        record[k] = v
    return record


def main() -> None:
    v = MaterializedView("orders_total", "sum")
    v.base_upsert("a", 10, seq=1)
    v.base_upsert("b", 20, seq=2)
    assert v.is_stale()
    rec = v.refresh(seq=3)
    assert rec.changed and rec.rows == 2 and rec.refresh_no == 1, rec
    assert rec.deltas_applied == 2
    q = v.query(seq=4)
    assert q.found and q.value == 30 and q.fresh, q

    # No base change -> refresh reports no change.
    rec2 = v.refresh(seq=5)
    assert not rec2.changed and rec2.deltas_applied == 0, rec2

    # Base change marks stale; query reports fresh=False as data.
    v.base_upsert("c", 5, seq=6)
    stale_q = v.query(seq=7)
    assert not stale_q.fresh and stale_q.value == 30, stale_q
    rec3 = v.refresh(seq=8)
    assert rec3.changed and v.query(seq=9).value == 35, rec3

    # Select kind: per-key lookup, unknown key is data.
    s = MaterializedView("names", "select")
    s.base_upsert("u1", "ann", seq=1)
    s.refresh(seq=2)
    hit = s.query(seq=3, key="u1")
    assert hit.found and hit.value == "ann" and hit.fresh, hit
    miss = s.query(seq=3, key="nope")
    assert not miss.found and miss.value is None, miss

    # Delete of unknown key refused fail-closed.
    try:
        s.base_delete("nope", seq=4)
    except UnknownKeyError:
        pass
    else:
        raise AssertionError("expected UnknownKeyError")
    s.base_delete("u1", seq=5)
    assert s.refresh(seq=6).rows == 0

    # Invalidate forces staleness without recompute.
    s.invalidate(seq=7, reason="base-migrated")
    assert s.is_stale() and not s.query(seq=8, key="u1").fresh

    # avg is exact "sum/count" text, no floats.
    a = MaterializedView("avg_lat", "avg")
    a.base_upsert("x", 3, seq=1)
    a.base_upsert("y", 5, seq=2)
    a.refresh(seq=3)
    assert a.query(seq=4).value == "8/2", a.query(seq=4)

    print(
        "materialized-view OK: upsert, refresh, stale-as-data, "
        "select, delete, invalidate, aggregates"
    )


if __name__ == "__main__":
    main()
