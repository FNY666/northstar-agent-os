"""Column store: Cassandra-shaped wide-column bookkeeping ledger.

Wide-column data model (Cassandra/CQL shaped):

* **Table** -- a named column family with an opaque row key space.
* **Row** -- one partition key maps to a set of named cells.
* **Cell** -- ``(column, value)`` with a logical write timestamp; cell-level
  **last-write-wins**: a newer timestamp always replaces an older one for the
  same ``(table, key, column)``.
* **Upsert** -- ``insert`` never raises "already exists"; it merges cells
  into the row, exactly like Cassandra's write path.
* **Tombstones** -- ``delete`` never removes data outright; it books a
  tombstone at the current timestamp. A row delete books a *row* tombstone;
  a column delete books *column* tombstones. A cell is visible only when its
  timestamp is newer than every tombstone covering it.

House style: frozen dataclasses, caller-supplied strictly increasing int
seqs (which double as the logical write timestamps -- no wall-clock),
RLock-guarded, fail-closed, stdlib-only, ``sha256:`` digest pins,
``audit.ndjson/1`` events.

Honest scope: this books *declared* writes and read decisions; it is not a
storage engine -- there is no persistence, no replication, no compaction,
no CQL parsing, and no repair. Values are pinned by ``sha256:`` digests of
canonical JSON; values that are not JSON-canonicalizable (NaN/inf,
non-str dict keys, ``|int| >= 2**53``, arbitrary objects) are rejected
fail-closed rather than hashed ambiguously. Raw values never cross the
audit boundary.

Version pin: column-store.v1
Schema pin: northstar.column-store.v1
"""

from __future__ import annotations

import ast
import hashlib
import json
import math
import threading
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Tuple

#: Module version.
COLUMN_STORE_VERSION = "column-store.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.column-store.v1"

#: Schema pin for audit events.
AUDIT_SCHEMA = "northstar.audit.ndjson/1"

#: Audit event kinds emitted by this module.
_AUDIT_KINDS = (
    "table-created",
    "inserted",
    "deleted",
    "rejected",
)


class ColumnStoreError(Exception):
    """Base class for column-store errors."""


class BadTableError(ColumnStoreError):
    """Raised when a table id is malformed."""


class DuplicateTableError(ColumnStoreError):
    """Raised when creating a table id that already exists."""


class UnknownTableError(ColumnStoreError):
    """Raised when referencing a table id that does not exist."""


class BadKeyError(ColumnStoreError):
    """Raised when a row key is malformed."""


class BadColumnError(ColumnStoreError):
    """Raised when a column name is malformed."""


class BadValueError(ColumnStoreError):
    """Raised when a cell value is not JSON-canonicalizable."""


class SeqOrderError(ColumnStoreError):
    """Raised when a caller seq is not strictly increasing."""


class AuditKindError(ColumnStoreError):
    """Raised when building an audit event with an unknown kind."""


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"seq must be int, got {type(seq).__name__}")
    if seq < 0:
        raise SeqOrderError(f"seq must be non-negative, got {seq}")
    return seq


def _check_table_id(table_id: Any) -> str:
    if not isinstance(table_id, str):
        raise BadTableError("table_id must be str")
    if not table_id or len(table_id) > 256:
        raise BadTableError("table_id must be non-empty and <= 256 chars")
    if any(ch.isspace() for ch in table_id):
        raise BadTableError("table_id must not contain whitespace")
    return table_id


def _check_key(key: Any) -> str:
    if not isinstance(key, str):
        raise BadKeyError("key must be str")
    if not key or len(key) > 1024:
        raise BadKeyError("key must be non-empty and <= 1024 chars")
    return key


def _check_column(column: Any) -> str:
    if not isinstance(column, str):
        raise BadColumnError("column must be str")
    if not column or len(column) > 256:
        raise BadColumnError("column must be non-empty and <= 256 chars")
    if any(ch.isspace() for ch in column):
        raise BadColumnError("column must not contain whitespace")
    return column


def _check_value(value: Any) -> None:
    """Reject values that are not JSON-canonicalizable, fail-closed."""
    if value is None:
        return
    if isinstance(value, bool):
        return
    if isinstance(value, int):
        if abs(value) >= 2**53:
            raise BadValueError("|int| >= 2**53 is not canonicalizable")
        return
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise BadValueError("NaN/inf floats are not canonicalizable")
        return
    if isinstance(value, str):
        if len(value) > 65536:
            raise BadValueError("str value longer than 64 KiB is refused")
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _check_value(item)
        return
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise BadValueError("dict keys must be str for canonical digest")
            _check_value(v)
        return
    raise BadValueError(f"value of type {type(value).__name__} is not canonicalizable")


def _canonical(value: Any) -> str:
    """Canonical JSON for digest pinning (sorted keys, compact separators)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def column_store_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
    """Wrap a column-store event as an audit event dict (audit.ndjson/1).

    Raw cell values are banned from the audit boundary: only digests, ids,
    counts and timestamps cross it.
    """
    if kind not in _AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    seq = _check_seq(seq)
    for banned in ("value", "values", "cells", "payload", "raw", "body", "data"):
        if banned in detail:
            raise AuditKindError(f"audit detail key {banned!r} is banned")
    event: Dict[str, Any] = {
        "schema": AUDIT_SCHEMA,
        "module": COLUMN_STORE_VERSION,
        "event": "column-store." + kind,
        "audit_seq": seq,
    }
    event.update(detail)
    return event


@dataclass(frozen=True)
class TableRecord:
    """Frozen record of a table creation."""

    table_id: str
    seq: int
    record_digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "table_id": self.table_id,
            "seq": self.seq,
            "record_digest": self.record_digest,
            "schema": SCHEMA_PIN,
        }


@dataclass(frozen=True)
class Cell:
    """One versioned cell: (column, value) pinned at a logical timestamp."""

    column: str
    value: Any
    value_digest: str
    ts: int

    def as_dict(self) -> Dict[str, Any]:
        return {
            "column": self.column,
            "value": self.value,
            "value_digest": self.value_digest,
            "ts": self.ts,
            "schema": SCHEMA_PIN,
        }


@dataclass(frozen=True)
class InsertRecord:
    """Frozen record of an upsert: cells merged into a row."""

    table_id: str
    key: str
    columns: Tuple[str, ...]
    ts: int
    record_digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "table_id": self.table_id,
            "key": self.key,
            "columns": list(self.columns),
            "ts": self.ts,
            "record_digest": self.record_digest,
            "schema": SCHEMA_PIN,
        }


@dataclass(frozen=True)
class DeleteRecord:
    """Frozen record of a tombstone write (row or column scope)."""

    table_id: str
    key: str
    scope: str  # "row" or "columns"
    columns: Tuple[str, ...]
    ts: int
    record_digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "table_id": self.table_id,
            "key": self.key,
            "scope": self.scope,
            "columns": list(self.columns),
            "ts": self.ts,
            "record_digest": self.record_digest,
            "schema": SCHEMA_PIN,
        }


@dataclass(frozen=True)
class SelectResult:
    """Frozen result of a point read: visible cells after tombstone merge."""

    table_id: str
    key: str
    found: bool
    cells: Tuple[Cell, ...]
    result_digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "table_id": self.table_id,
            "key": self.key,
            "found": self.found,
            "cells": [c.as_dict() for c in self.cells],
            "result_digest": self.result_digest,
            "schema": SCHEMA_PIN,
        }


@dataclass(frozen=True)
class _Tombstone:
    """Internal tombstone marker: scope + covered columns + timestamp."""

    scope: str  # "row" or "columns"
    columns: Tuple[str, ...]
    ts: int


class ColumnStore:
    """Deterministic wide-column store ledger (single host).

    Frozen dataclass records, caller-supplied strictly increasing int seqs
    (which double as the logical write timestamps for cell LWW and
    tombstones), no wall-clock, RLock-guarded, fail-closed. Failed mutations
    consume their seq and book a ``column-store.rejected`` audit row.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = -1
        # table_id -> TableRecord
        self._tables: Dict[str, TableRecord] = {}
        # table_id -> key -> column -> Cell (latest version per cell)
        self._cells: Dict[str, Dict[str, Dict[str, Cell]]] = {}
        # table_id -> key -> tuple of _Tombstone (append-only)
        self._tombstones: Dict[str, Dict[str, Tuple[_Tombstone, ...]]] = {}
        self._audit: list = []

    # ------------------------------------------------------------------ seq

    def _claim(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError(
                f"seq must be strictly increasing, got {seq} after {self._seq}"
            )
        self._seq = seq
        return seq

    def _emit(self, kind: str, seq: int, **detail: Any) -> None:
        self._audit.append(column_store_audit_event(kind, seq, **detail))

    def _reject(self, seq: int, exc: ColumnStoreError) -> ColumnStoreError:
        self._emit("rejected", seq, error=type(exc).__name__)
        return exc

    def _guarded(self, seq: Any, fn, name: str) -> Any:
        seq = self._claim(seq)
        try:
            return fn(seq)
        except ColumnStoreError as exc:
            raise self._reject(seq, exc) from exc

    # ---------------------------------------------------------------- tables

    def create_table(self, table_id: str, seq: int) -> TableRecord:
        """Register a column family (idempotent refusal on duplicates)."""

        def _run(s: int) -> TableRecord:
            tid = _check_table_id(table_id)
            if tid in self._tables:
                raise DuplicateTableError(f"table {tid!r} already exists")
            digest = _digest({"table_id": tid, "seq": s})
            rec = TableRecord(table_id=tid, seq=s, record_digest=digest)
            self._tables[tid] = rec
            self._cells[tid] = {}
            self._tombstones[tid] = {}
            self._emit("table-created", s, table_id=tid, record_digest=digest)
            return rec

        with self._lock:
            return self._guarded(seq, _run, "create_table")

    # ----------------------------------------------------------------- write

    def insert(
        self, table_id: str, key: str, values: Mapping[str, Any], seq: int
    ) -> InsertRecord:
        """Upsert cells into a row (Cassandra write path: never "exists").

        Each cell is timestamped with the caller's seq; cell-level
        last-write-wins decides the visible version.
        """

        def _run(s: int) -> InsertRecord:
            tid = _check_table_id(table_id)
            if tid not in self._tables:
                raise UnknownTableError(f"unknown table {tid!r}")
            k = _check_key(key)
            if not isinstance(values, Mapping):
                raise BadValueError("values must be a mapping of column -> value")
            if not values:
                raise BadValueError("values must be non-empty")
            cols: Tuple[str, ...] = ()
            row = self._cells[tid].setdefault(k, {})
            for column, value in values.items():
                col = _check_column(column)
                _check_value(value)
                cols = cols + (col,)
                cell = Cell(
                    column=col,
                    value=value,
                    value_digest=_digest(value),
                    ts=s,
                )
                # LWW: the caller seq is strictly increasing, so the new
                # cell always wins; the comparison documents the rule.
                prev = row.get(col)
                if prev is None or s >= prev.ts:
                    row[col] = cell
            cols = tuple(sorted(cols))
            digest = _digest(
                {"table_id": tid, "key": k, "columns": list(cols), "ts": s}
            )
            rec = InsertRecord(
                table_id=tid, key=k, columns=cols, ts=s, record_digest=digest
            )
            self._emit(
                "inserted",
                s,
                table_id=tid,
                key=k,
                columns=list(cols),
                ts=s,
                cell_digests=[row[c].value_digest for c in cols],
                record_digest=digest,
            )
            return rec

        with self._lock:
            return self._guarded(seq, _run, "insert")

    def delete(
        self,
        table_id: str,
        key: str,
        seq: int,
        columns: Optional[Tuple[str, ...]] = None,
    ) -> DeleteRecord:
        """Write a tombstone: row scope (columns=None) or column scope.

        Data is never removed outright; the tombstone hides covered cells
        whose timestamp is not newer than it.
        """

        def _run(s: int) -> DeleteRecord:
            tid = _check_table_id(table_id)
            if tid not in self._tables:
                raise UnknownTableError(f"unknown table {tid!r}")
            k = _check_key(key)
            if columns is None:
                scope = "row"
                cols: Tuple[str, ...] = ()
            else:
                scope = "columns"
                if not isinstance(columns, (tuple, list)):
                    raise BadColumnError("columns must be a tuple/list of str")
                cols = tuple(sorted(_check_column(c) for c in columns))
                if not cols:
                    raise BadColumnError("columns must be non-empty when given")
            tomb = _Tombstone(scope=scope, columns=cols, ts=s)
            key_tombs = self._tombstones[tid].setdefault(k, ())
            self._tombstones[tid][k] = key_tombs + (tomb,)
            digest = _digest(
                {
                    "table_id": tid,
                    "key": k,
                    "scope": scope,
                    "columns": list(cols),
                    "ts": s,
                }
            )
            rec = DeleteRecord(
                table_id=tid,
                key=k,
                scope=scope,
                columns=cols,
                ts=s,
                record_digest=digest,
            )
            self._emit(
                "deleted",
                s,
                table_id=tid,
                key=k,
                scope=scope,
                columns=list(cols),
                ts=s,
                record_digest=digest,
            )
            return rec

        with self._lock:
            return self._guarded(seq, _run, "delete")

    # ------------------------------------------------------------------ read

    def _visible_cells(
        self, table_id: str, key: str, columns: Tuple[str, ...]
    ) -> Tuple[Cell, ...]:
        """Merge cells and tombstones: a cell is visible only when its ts is
        newer than every tombstone covering it."""
        row = self._cells[table_id].get(key, {})
        tombs = self._tombstones[table_id].get(key, ())
        out: list = []
        for col in sorted(row):
            if columns and col not in columns:
                continue
            cell = row[col]
            hidden = False
            for tomb in tombs:
                covers = tomb.scope == "row" or col in tomb.columns
                if covers and tomb.ts >= cell.ts:
                    hidden = True
                    break
            if not hidden:
                out.append(cell)
        return tuple(out)

    def select(
        self,
        table_id: str,
        key: str,
        seq: int,
        columns: Tuple[str, ...] = (),
    ) -> SelectResult:
        """Point read: pure read view (seq shape validated, not consumed).

        Missing rows are ``found=False`` data, never raised. Tombstones
        merge before the result is built.
        """

        def _run(s: int) -> SelectResult:
            tid = _check_table_id(table_id)
            if tid not in self._tables:
                raise UnknownTableError(f"unknown table {tid!r}")
            k = _check_key(key)
            if not isinstance(columns, (tuple, list)):
                raise BadColumnError("columns must be a tuple/list of str")
            cols = tuple(_check_column(c) for c in columns)
            cells = self._visible_cells(tid, k, cols)
            found = len(cells) > 0
            digest = _digest(
                {
                    "table_id": tid,
                    "key": k,
                    "columns": [c.column for c in cells],
                    "digests": [c.value_digest for c in cells],
                }
            )
            return SelectResult(
                table_id=tid,
                key=k,
                found=found,
                cells=cells,
                result_digest=digest,
            )

        with self._lock:
            _check_seq(seq)  # shape only; reads do not consume seq
            try:
                return _run(seq)
            except ColumnStoreError as exc:
                raise exc

    # ------------------------------------------------------------------ views

    def table(self, table_id: str) -> Optional[TableRecord]:
        """Pure view: the table record, or None."""
        with self._lock:
            return self._tables.get(_check_table_id(table_id))

    def table_ids(self) -> Tuple[str, ...]:
        """Pure view: sorted table ids."""
        with self._lock:
            return tuple(sorted(self._tables))

    def keys(self, table_id: str) -> Tuple[str, ...]:
        """Pure view: sorted row keys that have any cells."""
        with self._lock:
            tid = _check_table_id(table_id)
            if tid not in self._tables:
                raise UnknownTableError(f"unknown table {tid!r}")
            return tuple(sorted(self._cells[tid]))

    def stats(self, seq: int) -> Dict[str, Any]:
        """Pure view: counts (seq shape validated, not consumed)."""
        _check_seq(seq)
        with self._lock:
            cell_count = sum(
                len(row) for table in self._cells.values() for row in table.values()
            )
            tomb_count = sum(
                len(tombs)
                for table in self._tombstones.values()
                for tombs in table.values()
            )
            return {
                "tables": len(self._tables),
                "cells": cell_count,
                "tombstones": tomb_count,
                "audit_rows": len(self._audit),
                "schema": SCHEMA_PIN,
            }

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        """Pure view: booked audit events."""
        with self._lock:
            return tuple(self._audit)


def _stdlib_only(path: str) -> None:
    """AST check that the module imports stdlib only."""
    tree = ast.parse(open(path, encoding="utf-8").read())
    allowed = {
        "__future__",
        "ast",
        "dataclasses",
        "hashlib",
        "json",
        "math",
        "threading",
        "typing",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                assert top in allowed, f"non-stdlib import: {alias.name}"
        elif isinstance(node, ast.ImportFrom):
            assert node.module is not None
            top = node.module.split(".")[0]
            assert top in allowed, f"non-stdlib import: {node.module}"


def main() -> None:
    """Self-check: create, insert, select, delete, tombstone visibility."""
    _stdlib_only(__file__)
    store = ColumnStore()
    store.create_table("users", 1)
    store.insert("users", "u1", {"name": "ada", "age": 36}, 2)
    got = store.select("users", "u1", 3)
    assert got.found and len(got.cells) == 2
    store.delete("users", "u1", 4, columns=("age",))
    got = store.select("users", "u1", 5)
    assert got.found and [c.column for c in got.cells] == ["name"]
    store.delete("users", "u1", 6)
    got = store.select("users", "u1", 7)
    assert not got.found
    # Tombstone does not block a newer write: LWW wins.
    store.insert("users", "u1", {"name": "ada"}, 8)
    got = store.select("users", "u1", 9)
    assert got.found
    stats = store.stats(10)
    assert stats["tables"] == 1
    assert len(store.audit_log()) == 5  # create + 2 insert + 2 delete
    print("column-store OK: create, insert, select, tombstone, row-delete, audit")


if __name__ == "__main__":
    main()
