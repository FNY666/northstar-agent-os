"""PostgreSQL-shaped relational database interface bookkeeping.

Research motivation: a *relational database* (System R, 1970s; PostgreSQL,
1996) stores rows in named tables with a fixed column schema, enforces
primary-key uniqueness, and answers declarative queries: ``SELECT`` with
``WHERE`` predicates and equi-``JOIN``s across tables. The production
concerns are textbook (Date; the PostgreSQL manual):

* **Schema on write** -- every row must present exactly the declared
  columns, each value type-checked against its column type. ``NULL`` is
  not modelled here: every column is ``NOT NULL`` by construction, so a
  missing or extra field is refused fail-closed, never silently coerced.
* **Primary keys** -- a declared key column carries a uniqueness
  invariant; a second insert reusing the key is refused (here
  :class:`DuplicateKeyError`), the in-memory analogue of PostgreSQL's
  ``unique_violation``.
* **Predicate queries** -- ``WHERE`` is a conjunction of
  ``(column, operator, value)`` triples over the pinned operator
  vocabulary ``=``/``!=``/``<``/``<=``/``>``/``>=``/``IN``. Type
  mismatches are *data* (no match), never an error: the ledger books
  what matched, it does not raise on the data it was asked about.
* **Equi-joins** -- a hash join over two tables' columns, booked as
  ``(left_row_id, right_row_id)`` pairs. ``INNER`` drops unmatched left
  rows; ``LEFT`` keeps them with an empty right id as data.

Rows and result sets are pinned by ``sha256:`` digests of the shared
JCS canonical form, so stored payloads and their pins are
tamper-evident; raw values never cross the audit boundary.

Public API:

- ``RelationalDB()`` -- mutable, RLock-guarded ledger.
  - ``table(table_id, columns, seq, primary_key="")`` -> frozen
    ``TableRecord``: declare a table. ``columns`` is a tuple of
    ``ColumnDef(name, col_type)``; column types are pinned to
    ``int``/``float``/``text``/``bool``. Duplicate ids refused; dropped
    ids are retired forever.
  - ``insert(table_id, row, seq)`` -> frozen ``InsertRecord``: store one
    row (``row-N`` ids), type-checking every field and enforcing the
    primary-key uniqueness invariant.
  - ``query(table_id, where, seq, select=())`` -> frozen
    ``QueryReport``: books one conjunctive predicate query; reports
    matched row ids and a result-set digest.
  - ``join(left_table, right_table, left_col, right_col, seq,
    join_type="inner")`` -> frozen ``JoinReport``: books one equi-join
    over pinned ``inner``/``left`` semantics.
  - ``drop(table_id, seq)`` -> frozen ``DropRecord``: terminally
    removes a table; the id is retired and can never be re-declared.
- ``relational_db_audit_event(kind, detail, seq)`` --
  ``audit.ndjson/1`` records: ``"relational-db.table-defined"``,
  ``"relational-db.row-inserted"``, ``"relational-db.queried"``,
  ``"relational-db.joined"``, ``"relational-db.table-dropped"``,
  ``"relational-db.rejected"``.

House discipline: caller int seqs strictly increasing on mutations
(failed mutations consume their seq; bool/negative/rewind refused),
RLock-guarded, fail-closed taxonomy, stdlib-only (``canonical_json``
sibling helper behind the standard try/except fallback).

Honest scope:

- This is in-memory *interface bookkeeping*, not PostgreSQL. It has no
  persistence (a crash loses the database), no query planner, no
  transactions, no indexes -- every query is a scan, and pins only
  host-reported bytes; it cannot prove a row was true.
- A booked ``QueryReport``/``JoinReport`` is a record of a computation
  over host-declared rows, not proof the host needed it.
- Join keys are matched with numeric normalization (``1 == 1.0``);
  booleans never match numbers, mirroring the bool-is-not-int
  discipline used at the write boundary.

Version pin: ``relational-db.v1`` / schema pin
``northstar.relational-db.v1``.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Tuple

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    _cj = None  # type: ignore

#: Version pin for this module's record shape.
RELATIONAL_DB_VERSION = "relational-db.v1"

#: Schema pin carried by records and audit events.
RELATIONAL_DB_SCHEMA = "northstar.relational-db.v1"

#: Wire format of audit records.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Fixed vocabulary for audit event kinds.
KIND_TABLE_DEFINED = "relational-db.table-defined"
KIND_ROW_INSERTED = "relational-db.row-inserted"
KIND_QUERIED = "relational-db.queried"
KIND_JOINED = "relational-db.joined"
KIND_TABLE_DROPPED = "relational-db.table-dropped"
KIND_REJECTED = "relational-db.rejected"
_KINDS = frozenset(
    {
        KIND_TABLE_DEFINED,
        KIND_ROW_INSERTED,
        KIND_QUERIED,
        KIND_JOINED,
        KIND_TABLE_DROPPED,
        KIND_REJECTED,
    }
)

#: Pinned column-type vocabulary.
_COL_TYPES = frozenset({"int", "float", "text", "bool"})

#: Pinned predicate-operator vocabulary.
_OPS = frozenset({"=", "!=", "<", "<=", ">", ">=", "IN"})

#: Pinned join-type vocabulary.
_JOIN_TYPES = frozenset({"inner", "left"})

_MAX_INT = 2**53 - 1
_MAX_STR = 65536
_DIGEST_PREFIX = "sha256:"
_DIGEST_LEN = len(_DIGEST_PREFIX) + 64


# ---------------------------------------------------------------------------
# Error taxonomy (fail-closed)
# ---------------------------------------------------------------------------


class RelationalDBError(Exception):
    """Base class for all relational-db errors."""


class BadTableError(RelationalDBError):
    """Table id or table definition is malformed."""


class DuplicateTableError(RelationalDBError):
    """A table id was declared twice (retired ids included)."""


class UnknownTableError(RelationalDBError):
    """An operation named a table that was never declared."""


class DroppedTableError(RelationalDBError):
    """An operation named a table that was dropped."""


class BadColumnError(RelationalDBError):
    """A column definition or column reference is malformed."""


class BadTypeError(RelationalDBError):
    """A column type is outside the pinned vocabulary."""


class BadRowError(RelationalDBError):
    """A row's shape does not match its table's columns."""


class BadValueError(RelationalDBError):
    """A row value does not fit its column type."""


class DuplicateKeyError(RelationalDBError):
    """An insert would violate the primary-key uniqueness invariant."""


class BadPredicateError(RelationalDBError):
    """A query predicate is malformed."""


class BadJoinError(RelationalDBError):
    """A join's tables or columns are malformed or unknown."""


class BadJoinTypeError(RelationalDBError):
    """A join type is outside the pinned vocabulary."""


class SeqOrderError(RelationalDBError):
    """Caller seq did not strictly increase."""


class AuditKindError(RelationalDBError):
    """Unknown audit kind for relational_db_audit_event."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_table_id(table_id: Any) -> str:
    if isinstance(table_id, bool) or not isinstance(table_id, str):
        raise BadTableError(
            f"table_id must be str, got {type(table_id).__name__}"
        )
    if not table_id.strip():
        raise BadTableError("table_id must be non-empty")
    if len(table_id) > 256:
        raise BadTableError("table_id exceeds 256 chars")
    return table_id


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"seq must be int, got {type(seq).__name__}")
    if seq < 0:
        raise SeqOrderError("seq must be non-negative")
    return seq


def _check_col_name(name: Any) -> str:
    if isinstance(name, bool) or not isinstance(name, str):
        raise BadColumnError(
            f"column name must be str, got {type(name).__name__}"
        )
    if not name.strip():
        raise BadColumnError("column name must be non-empty")
    if len(name) > 256:
        raise BadColumnError("column name exceeds 256 chars")
    return name


def _check_col_type(col_type: Any) -> str:
    if isinstance(col_type, bool) or not isinstance(col_type, str):
        raise BadTypeError(
            f"column type must be str, got {type(col_type).__name__}"
        )
    if col_type not in _COL_TYPES:
        raise BadTypeError(
            f"column type must be one of {sorted(_COL_TYPES)}, "
            f"got {col_type!r}"
        )
    return col_type


def _check_value(value: Any, col_type: str) -> Any:
    """Type-check one row value against its column type (fail-closed)."""
    if col_type == "bool":
        if isinstance(value, bool):
            return value
        raise BadValueError(
            f"bool column got {type(value).__name__} (bool is not int)"
        )
    if col_type == "int":
        if isinstance(value, bool) or not isinstance(value, int):
            raise BadValueError(
                f"int column got {type(value).__name__}"
            )
        if abs(value) > _MAX_INT:
            raise BadValueError("int value exceeds safe range")
        return value
    if col_type == "float":
        if isinstance(value, bool) or not isinstance(
            value, (int, float)
        ):
            raise BadValueError(
                f"float column got {type(value).__name__}"
            )
        f = float(value)
        if f != f or f in (float("inf"), float("-inf")):
            raise BadValueError("non-finite float refused")
        return value
    if col_type == "text":
        if not isinstance(value, str):
            raise BadValueError(
                f"text column got {type(value).__name__}"
            )
        if len(value) > _MAX_STR:
            raise BadValueError("text value exceeds 64 KiB")
        return value
    raise BadTypeError(f"unknown column type: {col_type!r}")  # pragma: no cover


def _check_digest(digest: Any) -> str:
    if isinstance(digest, bool) or not isinstance(digest, str):
        raise BadValueError(
            f"digest must be str, got {type(digest).__name__}"
        )
    if len(digest) != _DIGEST_LEN or not digest.startswith(_DIGEST_PREFIX):
        raise BadValueError("digest must be 'sha256:' + 64 hex chars")
    hexpart = digest[len(_DIGEST_PREFIX):]
    if any(c not in "0123456789abcdef" for c in hexpart):
        raise BadValueError("digest hex part is not lowercase hex")
    return digest


# ---------------------------------------------------------------------------
# Canonical encoding and digest pins
# ---------------------------------------------------------------------------


def _canonical(payload: Any) -> bytes:
    if _cj is not None:
        return _cj.jcs_dumps(payload).encode("utf-8")  # type: ignore

    def _tag(v: Any) -> Any:
        if isinstance(v, bool):
            return {"t": "bool", "v": v}
        if isinstance(v, int):
            if abs(v) > _MAX_INT:
                raise RelationalDBError("integer outside safe range")
            return {"t": "int", "v": v}
        if isinstance(v, float):
            if v != v or v in (float("inf"), float("-inf")):
                raise RelationalDBError("non-finite float refused")
            return {"t": "float", "v": repr(v)}
        if isinstance(v, str):
            return {"t": "str", "v": v}
        if isinstance(v, (list, tuple)):
            return {"t": "list", "v": [_tag(i) for i in v]}
        if isinstance(v, dict):
            return {"t": "dict", "v": [[k, _tag(v[k])] for k in sorted(v)]}
        if v is None:
            return {"t": "null"}
        raise RelationalDBError(f"unencodable type: {type(v).__name__}")

    import json

    return json.dumps(
        _tag(payload), sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _pin(*parts: Any) -> str:
    digest = hashlib.sha256(
        _canonical([RELATIONAL_DB_VERSION, *parts])
    ).hexdigest()
    return f"sha256:{digest}"


def _norm_key(value: Any) -> Tuple[str, Any]:
    """Normalize a join-key value for hash probing.

    Numeric normalization: ``1`` and ``1.0`` are the same key.
    Booleans never match numbers (bool-is-not-int discipline).
    """
    if isinstance(value, bool):
        return ("bool", value)
    if isinstance(value, (int, float)):
        return ("num", float(value))
    return ("str", value)


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ColumnDef:
    """One declared column: ``(name, col_type)``."""

    name: str
    col_type: str

    def verify(self) -> bool:
        """Re-check well-formedness (never raises)."""
        try:
            _check_col_name(self.name)
            _check_col_type(self.col_type)
        except RelationalDBError:
            return False
        return self.schema == RELATIONAL_DB_SCHEMA

    schema: str = RELATIONAL_DB_SCHEMA


@dataclass(frozen=True)
class TableRecord:
    """A declared table: id, ordered columns, optional primary key."""

    table_id: str
    columns: Tuple[ColumnDef, ...]
    primary_key: str
    digest: str
    seq: int
    schema: str = RELATIONAL_DB_SCHEMA

    def verify(self) -> bool:
        try:
            recomputed = _pin(
                "table",
                self.table_id,
                [(c.name, c.col_type) for c in self.columns],
                self.primary_key,
                self.seq,
            )
        except RelationalDBError:
            return False
        return recomputed == self.digest and self.schema == RELATIONAL_DB_SCHEMA


@dataclass(frozen=True)
class InsertRecord:
    """One booked row insert: ``row-N`` id plus the row's digest pin."""

    table_id: str
    row_id: str
    row_digest: str
    digest: str
    seq: int
    schema: str = RELATIONAL_DB_SCHEMA

    def verify(self) -> bool:
        try:
            recomputed = _pin(
                "insert", self.table_id, self.row_id, self.row_digest, self.seq
            )
        except RelationalDBError:
            return False
        return recomputed == self.digest and self.schema == RELATIONAL_DB_SCHEMA


@dataclass(frozen=True)
class Predicate:
    """One ``(column, operator, value)`` conjunct of a WHERE clause."""

    column: str
    op: str
    value: Any

    def verify(self) -> bool:
        try:
            _check_col_name(self.column)
            if self.op not in _OPS:
                return False
            _canonical(self.value)
        except RelationalDBError:
            return False
        return True


@dataclass(frozen=True)
class QueryReport:
    """Booked predicate query: matched row ids and a result-set digest."""

    table_id: str
    query_id: str
    matched_row_ids: Tuple[str, ...]
    result_digest: str
    digest: str
    seq: int
    schema: str = RELATIONAL_DB_SCHEMA

    def verify(self) -> bool:
        try:
            recomputed = _pin(
                "query",
                self.table_id,
                self.query_id,
                list(self.matched_row_ids),
                self.result_digest,
                self.seq,
            )
        except RelationalDBError:
            return False
        return recomputed == self.digest and self.schema == RELATIONAL_DB_SCHEMA


@dataclass(frozen=True)
class JoinReport:
    """Booked equi-join: ``(left_row_id, right_row_id)`` pairs.

    For ``left`` joins, unmatched left rows pair with ``""`` as data.
    """

    join_id: str
    left_table: str
    right_table: str
    left_col: str
    right_col: str
    join_type: str
    pairs: Tuple[Tuple[str, str], ...]
    result_digest: str
    digest: str
    seq: int
    schema: str = RELATIONAL_DB_SCHEMA

    def verify(self) -> bool:
        try:
            recomputed = _pin(
                "join",
                self.join_id,
                self.left_table,
                self.right_table,
                self.left_col,
                self.right_col,
                self.join_type,
                [list(p) for p in self.pairs],
                self.result_digest,
                self.seq,
            )
        except RelationalDBError:
            return False
        return recomputed == self.digest and self.schema == RELATIONAL_DB_SCHEMA


@dataclass(frozen=True)
class DropRecord:
    """Terminal table drop; the id is retired forever."""

    table_id: str
    digest: str
    seq: int
    schema: str = RELATIONAL_DB_SCHEMA

    def verify(self) -> bool:
        try:
            recomputed = _pin("drop", self.table_id, self.seq)
        except RelationalDBError:
            return False
        return recomputed == self.digest and self.schema == RELATIONAL_DB_SCHEMA


@dataclass(frozen=True)
class StatsReport:
    """Pure read view of ledger counters."""

    tables: int
    rows_total: int
    inserts: int
    queries: int
    joins: int
    last_seq: int
    schema: str = RELATIONAL_DB_SCHEMA


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def relational_db_audit_event(
    kind: str, detail: Mapping[str, Any], seq: int
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for relational-db.

    Raw values never cross the audit boundary: ``detail`` may carry
    digests, ids, column names and counts -- never ``value``/``row``.
    """
    if not isinstance(kind, str) or kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    if not isinstance(detail, Mapping):
        raise AuditKindError("detail must be a mapping")
    banned = {"value", "values", "payload", "raw", "row"}
    if any(k in detail for k in banned):
        raise AuditKindError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": RELATIONAL_DB_VERSION,
        "detail": dict(detail),
        "seq": seq,
    }


# ---------------------------------------------------------------------------
# The ledger
# ---------------------------------------------------------------------------


class RelationalDB:
    """PostgreSQL-shaped table/query/join bookkeeping, in memory."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        self._tables: Dict[str, Dict[str, Any]] = {}
        self._retired: set = set()
        self._queries: list = []
        self._joins: list = []
        self._audit: list = []

    # -- seq discipline ----------------------------------------------------

    def _claim(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq {seq} did not exceed last seq {self._last_seq}"
            )
        self._last_seq = seq
        return seq

    def _reject(self, seq: int, reason: str, table_id: str = "") -> Dict[str, Any]:
        row = relational_db_audit_event(
            KIND_REJECTED, {"reason": reason, "table_id": table_id}, seq
        )
        self._audit.append(row)
        return row

    def _live_table(self, table_id: str) -> Dict[str, Any]:
        """Return the table entry; fail closed on unknown/dropped."""
        entry = self._tables.get(table_id)
        if entry is None:
            if table_id in self._retired:
                raise DroppedTableError(f"table was dropped: {table_id}")
            raise UnknownTableError(f"unknown table: {table_id}")
        if entry["dropped"]:
            raise DroppedTableError(f"table was dropped: {table_id}")
        return entry

    # -- pure views --------------------------------------------------------

    def table_ids(self) -> Tuple[str, ...]:
        """Ids of live (non-dropped) tables, sorted."""
        with self._lock:
            return tuple(
                sorted(
                    tid for tid, e in self._tables.items() if not e["dropped"]
                )
            )

    def table_record(self, table_id: str) -> TableRecord:
        """The declared ``TableRecord`` for a live table."""
        with self._lock:
            return self._live_table(table_id)["record"]

    def row_ids(self, table_id: str) -> Tuple[str, ...]:
        """Row ids of a live table, in insert order."""
        with self._lock:
            return tuple(self._live_table(table_id)["row_order"])

    def row_digest(self, table_id: str, row_id: str) -> str:
        """The pinned digest of one stored row."""
        with self._lock:
            entry = self._live_table(table_id)
            digest = entry["row_digests"].get(row_id)
            if digest is None:
                raise BadRowError(f"unknown row: {row_id}")
            return digest

    def stats(self) -> StatsReport:
        """Ledger counters. Pure read; consumes no seq."""
        with self._lock:
            rows_total = sum(
                len(e["row_order"])
                for e in self._tables.values()
                if not e["dropped"]
            )
            return StatsReport(
                tables=len(self.table_ids()),
                rows_total=rows_total,
                inserts=sum(
                    len(e["row_order"]) for e in self._tables.values()
                ),
                queries=len(self._queries),
                joins=len(self._joins),
                last_seq=self._last_seq,
            )

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return tuple(self._audit)

    # -- mutations ---------------------------------------------------------

    def table(
        self,
        table_id: str,
        columns: Tuple[ColumnDef, ...],
        seq: int,
        primary_key: str = "",
    ) -> TableRecord:
        """Declare a table. Duplicate/retired ids refused fail-closed."""
        with self._lock:
            self._claim(seq)
            try:
                table_id = _check_table_id(table_id)
                if table_id in self._tables or table_id in self._retired:
                    raise DuplicateTableError(
                        f"table already declared: {table_id}"
                    )
                if not isinstance(columns, tuple) or not columns:
                    raise BadColumnError("columns must be a non-empty tuple")
                seen = set()
                for col in columns:
                    if not isinstance(col, ColumnDef):
                        raise BadColumnError(
                            "columns must hold ColumnDef records"
                        )
                    _check_col_name(col.name)
                    _check_col_type(col.col_type)
                    if col.name in seen:
                        raise BadColumnError(
                            f"duplicate column: {col.name}"
                        )
                    seen.add(col.name)
                if primary_key:
                    primary_key = _check_col_name(primary_key)
                    if primary_key not in seen:
                        raise BadColumnError(
                            f"primary_key names unknown column: {primary_key}"
                        )
            except RelationalDBError as exc:
                self._reject(seq, type(exc).__name__, table_id)
                raise

            digest = _pin(
                "table",
                table_id,
                [(c.name, c.col_type) for c in columns],
                primary_key,
                seq,
            )
            record = TableRecord(
                table_id=table_id,
                columns=columns,
                primary_key=primary_key,
                digest=digest,
                seq=seq,
            )
            pk_index = self._col_index(columns, primary_key)
            self._tables[table_id] = {
                "record": record,
                "columns": columns,
                "pk_index": pk_index,
                "row_order": [],
                "row_values": {},
                "row_digests": {},
                "pk_values": set(),
                "dropped": False,
            }
            self._audit.append(
                relational_db_audit_event(
                    KIND_TABLE_DEFINED,
                    {
                        "table_id": table_id,
                        "columns": [c.name for c in columns],
                        "primary_key": primary_key,
                        "digest": digest,
                    },
                    seq,
                )
            )
            return record

    @staticmethod
    def _col_index(
        columns: Tuple[ColumnDef, ...], name: str
    ) -> Optional[int]:
        for i, col in enumerate(columns):
            if col.name == name:
                return i
        return None

    def insert(self, table_id: str, row: Mapping[str, Any], seq: int) -> InsertRecord:
        """Store one row; exact column shape, typed values, PK unique."""
        with self._lock:
            self._claim(seq)
            try:
                table_id = _check_table_id(table_id)
                entry = self._live_table(table_id)
                columns = entry["columns"]
                if not isinstance(row, Mapping):
                    raise BadRowError(
                        f"row must be a mapping, got {type(row).__name__}"
                    )
                for k in row.keys():
                    if isinstance(k, bool) or not isinstance(k, str):
                        raise BadRowError("row keys must be strings")
                expected = {c.name for c in columns}
                given = set(row.keys())
                if given != expected:
                    raise BadRowError(
                        f"row keys {sorted(given)} do not match "
                        f"columns {sorted(expected)}"
                    )
                values = []
                for col in columns:
                    values.append(_check_value(row[col.name], col.col_type))
                pk = entry["record"].primary_key
                if pk:
                    pk_val = row[pk]
                    if pk_val in entry["pk_values"]:
                        raise DuplicateKeyError(
                            f"duplicate primary key: {pk_val!r}"
                        )
            except RelationalDBError as exc:
                self._reject(seq, type(exc).__name__, table_id)
                raise

            row_id = f"row-{len(entry['row_order'])}"
            row_digest = _pin(
                "row",
                table_id,
                row_id,
                [[c.name, v] for c, v in zip(columns, values)],
            )
            digest = _pin("insert", table_id, row_id, row_digest, seq)
            record = InsertRecord(
                table_id=table_id,
                row_id=row_id,
                row_digest=row_digest,
                digest=digest,
                seq=seq,
            )
            entry["row_order"].append(row_id)
            entry["row_values"][row_id] = tuple(values)
            entry["row_digests"][row_id] = row_digest
            pk = entry["record"].primary_key
            if pk:
                entry["pk_values"].add(row[pk])
            self._audit.append(
                relational_db_audit_event(
                    KIND_ROW_INSERTED,
                    {
                        "table_id": table_id,
                        "row_id": row_id,
                        "row_digest": row_digest,
                        "digest": digest,
                    },
                    seq,
                )
            )
            return record

    def query(
        self,
        table_id: str,
        where: Tuple[Predicate, ...],
        seq: int,
        select: Tuple[str, ...] = (),
    ) -> QueryReport:
        """Book one conjunctive predicate query over a table.

        Type mismatches between row values and predicate values are
        no-match *data*, never an error. ``select=()`` projects all
        columns; the report carries row ids and a result-set digest.
        """
        with self._lock:
            self._claim(seq)
            try:
                table_id = _check_table_id(table_id)
                entry = self._live_table(table_id)
                columns = entry["columns"]
                col_names = [c.name for c in columns]
                if not isinstance(where, tuple):
                    raise BadPredicateError("where must be a tuple")
                for pred in where:
                    if not isinstance(pred, Predicate):
                        raise BadPredicateError(
                            "where must hold Predicate records"
                        )
                    _check_col_name(pred.column)
                    if pred.column not in col_names:
                        raise BadColumnError(
                            f"unknown column: {pred.column}"
                        )
                    if pred.op not in _OPS:
                        raise BadPredicateError(
                            f"unknown operator: {pred.op}"
                        )
                    try:
                        _canonical(pred.value)
                    except RelationalDBError as exc:
                        raise BadPredicateError(
                            f"predicate value not encodable: {exc}"
                        ) from exc
                    if pred.op == "IN":
                        if not isinstance(pred.value, (list, tuple)):
                            raise BadPredicateError(
                                "IN needs a list/tuple value"
                            )
                if not isinstance(select, tuple):
                    raise BadPredicateError("select must be a tuple")
                for name in select:
                    _check_col_name(name)
                    if name not in col_names:
                        raise BadColumnError(
                            f"unknown select column: {name}"
                        )
            except RelationalDBError as exc:
                self._reject(seq, type(exc).__name__, table_id)
                raise

            matched = []
            for row_id in entry["row_order"]:
                values = dict(
                    zip(col_names, entry["row_values"][row_id])
                )
                if all(
                    self._match(values[p.column], p.op, p.value)
                    for p in where
                ):
                    matched.append(row_id)
            query_id = f"q-{len(self._queries)}"
            result_digest = _pin("query-result", table_id, matched)
            digest = _pin(
                "query", table_id, query_id, matched, result_digest, seq
            )
            report = QueryReport(
                table_id=table_id,
                query_id=query_id,
                matched_row_ids=tuple(matched),
                result_digest=result_digest,
                digest=digest,
                seq=seq,
            )
            self._queries.append(report)
            self._audit.append(
                relational_db_audit_event(
                    KIND_QUERIED,
                    {
                        "table_id": table_id,
                        "query_id": query_id,
                        "matched": len(matched),
                        "result_digest": result_digest,
                    },
                    seq,
                )
            )
            return report

    @staticmethod
    def _match(value: Any, op: str, target: Any) -> bool:
        """One predicate comparison; type mismatch is no-match (data)."""
        if op == "IN":
            return any(RelationalDB._eq(value, t) for t in target)
        if op == "=":
            return RelationalDB._eq(value, target)
        if op == "!=":
            return not RelationalDB._eq(value, target)
        if isinstance(value, bool) or isinstance(target, bool):
            return False
        if not isinstance(value, (int, float)) or not isinstance(
            target, (int, float)
        ):
            return False
        if op == "<":
            return value < target
        if op == "<=":
            return value <= target
        if op == ">":
            return value > target
        if op == ">=":
            return value >= target
        return False  # pragma: no cover

    @staticmethod
    def _eq(value: Any, target: Any) -> bool:
        if isinstance(value, bool) or isinstance(target, bool):
            return value is target
        if isinstance(value, (int, float)) and isinstance(
            target, (int, float)
        ):
            return float(value) == float(target)
        return type(value) is type(target) and value == target

    def join(
        self,
        left_table: str,
        right_table: str,
        left_col: str,
        right_col: str,
        seq: int,
        join_type: str = "inner",
    ) -> JoinReport:
        """Book one equi-join: hash probe of right on left, in order.

        ``inner`` drops unmatched left rows; ``left`` keeps them with
        ``""`` as the right id (as data).
        """
        with self._lock:
            self._claim(seq)
            try:
                left_table = _check_table_id(left_table)
                right_table = _check_table_id(right_table)
                left_entry = self._live_table(left_table)
                right_entry = self._live_table(right_table)
                left_cols = [c.name for c in left_entry["columns"]]
                right_cols = [c.name for c in right_entry["columns"]]
                _check_col_name(left_col)
                _check_col_name(right_col)
                if left_col not in left_cols:
                    raise BadJoinError(
                        f"unknown left column: {left_col}"
                    )
                if right_col not in right_cols:
                    raise BadJoinError(
                        f"unknown right column: {right_col}"
                    )
                if (
                    not isinstance(join_type, str)
                    or join_type not in _JOIN_TYPES
                ):
                    raise BadJoinTypeError(
                        f"join_type must be one of {sorted(_JOIN_TYPES)}"
                    )
            except RelationalDBError as exc:
                self._reject(seq, type(exc).__name__, left_table)
                raise

            li = left_cols.index(left_col)
            ri = right_cols.index(right_col)
            probe: Dict[Tuple[str, Any], list] = {}
            for rrow_id in right_entry["row_order"]:
                key = _norm_key(right_entry["row_values"][rrow_id][ri])
                probe.setdefault(key, []).append(rrow_id)
            pairs = []
            for lrow_id in left_entry["row_order"]:
                key = _norm_key(left_entry["row_values"][lrow_id][li])
                hits = probe.get(key, [])
                if hits:
                    for rrow_id in hits:
                        pairs.append((lrow_id, rrow_id))
                elif join_type == "left":
                    pairs.append((lrow_id, ""))
            join_id = f"join-{len(self._joins)}"
            result_digest = _pin(
                "join-result",
                left_table,
                right_table,
                [list(p) for p in pairs],
            )
            digest = _pin(
                "join",
                join_id,
                left_table,
                right_table,
                left_col,
                right_col,
                join_type,
                [list(p) for p in pairs],
                result_digest,
                seq,
            )
            report = JoinReport(
                join_id=join_id,
                left_table=left_table,
                right_table=right_table,
                left_col=left_col,
                right_col=right_col,
                join_type=join_type,
                pairs=tuple(pairs),
                result_digest=result_digest,
                digest=digest,
                seq=seq,
            )
            self._joins.append(report)
            self._audit.append(
                relational_db_audit_event(
                    KIND_JOINED,
                    {
                        "join_id": join_id,
                        "left_table": left_table,
                        "right_table": right_table,
                        "join_type": join_type,
                        "pairs": len(pairs),
                        "result_digest": result_digest,
                    },
                    seq,
                )
            )
            return report

    def drop(self, table_id: str, seq: int) -> DropRecord:
        """Terminally drop a table; the id is retired forever."""
        with self._lock:
            self._claim(seq)
            try:
                table_id = _check_table_id(table_id)
                entry = self._live_table(table_id)
            except RelationalDBError as exc:
                self._reject(seq, type(exc).__name__, table_id)
                raise

            digest = _pin("drop", table_id, seq)
            record = DropRecord(table_id=table_id, digest=digest, seq=seq)
            entry["dropped"] = True
            del self._tables[table_id]
            self._retired.add(table_id)
            self._audit.append(
                relational_db_audit_event(
                    KIND_TABLE_DROPPED,
                    {"table_id": table_id, "digest": digest},
                    seq,
                )
            )
            return record


def main() -> None:
    """Self-check: define, insert, query, join, drop, audit."""
    db = RelationalDB()
    users = db.table(
        "users",
        (ColumnDef("id", "int"), ColumnDef("name", "text")),
        1,
        primary_key="id",
    )
    assert users.verify()
    orders = db.table(
        "orders",
        (ColumnDef("oid", "int"), ColumnDef("uid", "int")),
        2,
    )
    assert orders.verify()

    r0 = db.insert("users", {"id": 1, "name": "amy"}, 3)
    r1 = db.insert("users", {"id": 2, "name": "bo"}, 4)
    assert r0.verify() and r0.row_id == "row-0"
    assert r1.verify() and r1.row_id == "row-1"
    o0 = db.insert("orders", {"oid": 10, "uid": 1}, 5)
    assert o0.verify()

    rep = db.query(
        "users", (Predicate("id", ">", 1),), 6, select=("name",)
    )
    assert rep.verify()
    assert rep.matched_row_ids == ("row-1",)
    assert db.row_digest("users", "row-1")

    jn = db.join("orders", "users", "uid", "id", 7)
    assert jn.verify()
    assert jn.pairs == (("row-0", "row-0"),)
    assert jn.join_type == "inner"

    lj = db.join("users", "orders", "id", "uid", 8, join_type="left")
    assert lj.verify()
    assert lj.pairs == (("row-0", "row-0"), ("row-1", ""))

    dr = db.drop("orders", 9)
    assert dr.verify()
    assert db.table_ids() == ("users",)
    try:
        db.insert("orders", {"oid": 11, "uid": 2}, 10)
    except DroppedTableError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected DroppedTableError")
    assert db.audit_log()[-1]["kind"] == KIND_REJECTED

    kinds = [row["kind"] for row in db.audit_log()]
    assert kinds == [
        KIND_TABLE_DEFINED,
        KIND_TABLE_DEFINED,
        KIND_ROW_INSERTED,
        KIND_ROW_INSERTED,
        KIND_ROW_INSERTED,
        KIND_QUERIED,
        KIND_JOINED,
        KIND_JOINED,
        KIND_TABLE_DROPPED,
        KIND_REJECTED,
    ], kinds
    assert db.stats().tables == 1 and db.stats().rows_total == 2

    print("relational-db OK: table, insert, query, join, drop, audit")


if __name__ == "__main__":
    main()
