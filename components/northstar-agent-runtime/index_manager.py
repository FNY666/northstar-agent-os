"""Index manager: named secondary-index catalog over host-owned tables.

Research note: production engines (PostgreSQL, MySQL/InnoDB, RocksDB)
keep a catalog of *secondary indexes* so equality and range lookups can
be served by key instead of by full-table scan. The catalog answers
"which index exists on which table/field" while the storage layer does
the actual page walk. This module is the catalog + binding ledger layer:

* **create()** declares a named secondary index over ``(table_id, field)``
  with a pinned structural kind (``btree`` / ``hash``).
* **drop()** retires the index; the id is never recycled.
* **bind()/unbind()** book and release individual ``(key, row_id)``
  entries, keeping one entry set per index.
* **lookup()** is a pure read view returning the sorted ``row_id`` set
  for one key.

Deliberately distinct from the sibling ``btree_index.py`` (the actual
B-tree data structure with nodes, splits and rebalancing): this module
owns the *catalog* — name resolution, lifecycle, and entry bookkeeping
— not the tree walk. House style throughout: frozen dataclasses,
caller-supplied strictly-increasing int seqs, no wall-clock, RLock
guarding, fail-closed taxonomy, stdlib-only with the standard
``canonical_json`` try/except fallback, ``sha256:`` digest pins, and
``audit.ndjson/1`` events.

Honest scope: the module books *declared* index topology and
host-reported bindings — it cannot prove a query used the index, that a
binding matches the source table, or that a bound key is the value the
field actually holds. ``kind`` is a declared property of the booking,
not a structural guarantee of the host's storage. Keys and row ids
never cross the audit boundary (digest pins only); a "not found" lookup
means "the index holds no such binding", never "the table holds no such
row".
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    _cj = None  # type: ignore

#: Version pin for this module's record shape.
INDEX_MANAGER_VERSION = "index-manager.v1"

#: Schema pin carried by records and audit events.
INDEX_MANAGER_SCHEMA = "northstar.index-manager.v1"

#: Wire format of audit records.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Fixed vocabulary for audit event kinds.
KIND_CREATED = "index-manager.index-created"
KIND_DROPPED = "index-manager.index-dropped"
KIND_BOUND = "index-manager.bound"
KIND_UNBOUND = "index-manager.unbound"
KIND_REJECTED = "index-manager.rejected"
_KINDS = frozenset({KIND_CREATED, KIND_DROPPED, KIND_BOUND, KIND_UNBOUND, KIND_REJECTED})

#: Pinned structural kinds a declared index may carry.
KIND_BTREE = "btree"
KIND_HASH = "hash"
_INDEX_KINDS = frozenset({KIND_BTREE, KIND_HASH})

_MAX_INT = 2**53 - 1
_DIGEST_PREFIX = "sha256:"
_MAX_ID_LEN = 256

# Index lifecycle states.
_STATE_ACTIVE = "active"
_STATE_DROPPED = "dropped"


# ---------------------------------------------------------------------------
# Error taxonomy (fail-closed)
# ---------------------------------------------------------------------------


class IndexManagerError(Exception):
    """Base class for all index-manager errors."""


class BadIndexError(IndexManagerError):
    """index_id is not a usable non-empty str."""


class DuplicateIndexError(IndexManagerError):
    """index_id is already booked (active or dropped); ids are never recycled."""


class UnknownIndexError(IndexManagerError):
    """index_id names no index this manager ever saw."""


class DroppedIndexError(IndexManagerError):
    """The index was dropped; no further mutations are accepted."""


class BadTableError(IndexManagerError):
    """table_id is not a usable non-empty str."""


class BadFieldError(IndexManagerError):
    """field is not a usable non-empty str."""


class BadKeyError(IndexManagerError):
    """key is not int/str (bool refused, ints must be safe-range)."""


class BadKindError(IndexManagerError):
    """kind is not in the pinned structural vocabulary."""


class DuplicateBindingError(IndexManagerError):
    """(key, row_id) is already bound on this index."""


class UnknownBindingError(IndexManagerError):
    """(key, row_id) names no binding on this index."""


class BadRowError(IndexManagerError):
    """row_id is not a usable non-empty str."""


class SeqOrderError(IndexManagerError):
    """seq is not a fresh strictly-increasing int."""


class AuditKindError(IndexManagerError):
    """audit builder was handed an unknown kind."""


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
                raise IndexManagerError("integer outside safe range")
            return {"t": "int", "v": v}
        if isinstance(v, float):
            if v != v or v in (float("inf"), float("-inf")):
                raise IndexManagerError("non-finite float refused")
            return {"t": "float", "v": repr(v)}
        if isinstance(v, str):
            return {"t": "str", "v": v}
        if isinstance(v, (list, tuple)):
            return {"t": "list", "v": [_tag(i) for i in v]}
        if isinstance(v, dict):
            return {"t": "dict", "v": [[k, _tag(v[k])] for k in sorted(v)]}
        if v is None:
            return {"t": "null"}
        raise IndexManagerError(f"unencodable type: {type(v).__name__}")

    import json

    return json.dumps(_tag(payload), sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest_pin(payload: Any, tag: str) -> str:
    return _DIGEST_PREFIX + hashlib.sha256(
        (tag + ":").encode("utf-8") + _canonical(payload)
    ).hexdigest()


# ---------------------------------------------------------------------------
# Input checks
# ---------------------------------------------------------------------------


def _check_id(value: Any, err: type) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise err(f"id must be a str, got {type(value).__name__}")
    if not value or len(value) > _MAX_ID_LEN or value != value.strip():
        raise err(f"id must be 1..{_MAX_ID_LEN} non-blank chars")
    return value


def _check_key(key: Any) -> Any:
    if isinstance(key, bool) or not isinstance(key, (int, str)):
        raise BadKeyError(f"key must be int or str (bool refused), got {type(key).__name__}")
    if isinstance(key, int) and abs(key) > _MAX_INT:
        raise BadKeyError("key int outside safe range")
    if isinstance(key, str) and (not key or len(key) > 1024):
        raise BadKeyError("key str must be 1..1024 chars")
    return key


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"seq must be an int, got {type(seq).__name__}")
    return seq


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IndexRecord:
    """A declared secondary index."""

    index_id: str
    table_id: str
    field: str
    kind: str
    seq: int
    digest: str = ""
    schema: str = INDEX_MANAGER_SCHEMA

    def verify(self) -> bool:
        expect = _digest_pin(
            (self.index_id, self.table_id, self.field, self.kind, self.seq),
            "index-record",
        )
        return self.digest == expect


@dataclass(frozen=True)
class DropRecord:
    """Terminal retirement of an index."""

    index_id: str
    seq: int
    digest: str = ""
    schema: str = INDEX_MANAGER_SCHEMA

    def verify(self) -> bool:
        expect = _digest_pin((self.index_id, self.seq), "drop-record")
        return self.digest == expect


@dataclass(frozen=True)
class BindRecord:
    """One (key, row_id) entry bound to an index."""

    index_id: str
    key_digest: str
    row_id: str
    seq: int
    digest: str = ""
    schema: str = INDEX_MANAGER_SCHEMA

    def verify(self) -> bool:
        expect = _digest_pin(
            (self.index_id, self.key_digest, self.row_id, self.seq), "bind-record"
        )
        return self.digest == expect


@dataclass(frozen=True)
class UnbindRecord:
    """One (key, row_id) entry released from an index."""

    index_id: str
    key_digest: str
    row_id: str
    seq: int
    digest: str = ""
    schema: str = INDEX_MANAGER_SCHEMA

    def verify(self) -> bool:
        expect = _digest_pin(
            (self.index_id, self.key_digest, self.row_id, self.seq), "unbind-record"
        )
        return self.digest == expect


@dataclass(frozen=True)
class LookupReport:
    """Pure read view: the row ids bound to one key (sorted)."""

    index_id: str
    key_digest: str
    row_ids: Tuple[str, ...]
    digest: str = ""
    schema: str = INDEX_MANAGER_SCHEMA

    def verify(self) -> bool:
        expect = _digest_pin(
            (self.index_id, self.key_digest, tuple(self.row_ids)), "lookup-report"
        )
        return self.digest == expect


@dataclass(frozen=True)
class KeysReport:
    """Pure read view: the sorted key digests held by an index."""

    index_id: str
    key_digests: Tuple[str, ...]
    count: int
    schema: str = INDEX_MANAGER_SCHEMA


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def index_manager_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
    """Build one audit.ndjson/1 event. Raw keys never cross this boundary."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    banned = ("key", "keys", "value", "payload", "raw", "body", "data", "message")
    for bad in banned:
        if bad in detail:
            raise AuditKindError(f"audit detail bans {bad!r}")
    _check_seq(seq)
    event = {
        "schema": AUDIT_SCHEMA,
        "module": "index_manager",
        "kind": kind,
        "seq": seq,
        "detail": detail,
    }
    event["digest"] = _digest_pin((kind, seq, tuple(sorted(detail))), "audit-event")
    return event


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------


class IndexManager:
    """Catalog of named secondary indexes with binding bookkeeping."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        # index_id -> dict(index_id, table_id, field, kind, seq, state, digest)
        self._indexes: Dict[str, Dict[str, Any]] = {}
        # index_id -> list of (key_digest, sort_key, key, row_id) tuples
        self._entries: Dict[str, List[Tuple[str, Any, Any, str]]] = {}
        self._audit: List[Dict[str, Any]] = []

    # -- seq discipline ----------------------------------------------------

    def _claim(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError(f"seq {seq} not strictly greater than {self._seq}")
        self._seq = seq
        return seq

    def _emit(self, kind: str, seq: int, **detail: Any) -> None:
        self._audit.append(index_manager_audit_event(kind, seq, **detail))

    def _fail(self, seq: int, exc: IndexManagerError, **detail: Any) -> None:
        self._emit(KIND_REJECTED, seq, error=type(exc).__name__, **detail)
        raise exc

    def _get_active(self, index_id: str, seq: int) -> Dict[str, Any]:
        entry = self._indexes.get(index_id)
        if entry is None:
            self._fail(seq, UnknownIndexError(f"unknown index: {index_id!r}"), index_id=index_id)
        assert entry is not None
        if entry["state"] == _STATE_DROPPED:
            self._fail(seq, DroppedIndexError(f"index dropped: {index_id!r}"), index_id=index_id)
        return entry

    # -- lifecycle ---------------------------------------------------------

    def create(
        self, index_id: str, table_id: str, field: str, seq: Any, kind: str = KIND_BTREE
    ) -> IndexRecord:
        """Declare a named secondary index over ``(table_id, field)``."""
        with self._lock:
            seq = self._claim(seq)
            try:
                index_id = _check_id(index_id, BadIndexError)
                table_id = _check_id(table_id, BadTableError)
                field = _check_id(field, BadFieldError)
                if isinstance(kind, bool) or not isinstance(kind, str) or kind not in _INDEX_KINDS:
                    raise BadKindError(f"kind must be one of {sorted(_INDEX_KINDS)}")
            except IndexManagerError as exc:
                self._fail(seq, exc)
            if index_id in self._indexes:
                self._fail(
                    seq, DuplicateIndexError(f"duplicate index: {index_id!r}"), index_id=index_id
                )
            digest = _digest_pin((index_id, table_id, field, kind, seq), "index-record")
            self._indexes[index_id] = {
                "index_id": index_id,
                "table_id": table_id,
                "field": field,
                "kind": kind,
                "seq": seq,
                "state": _STATE_ACTIVE,
                "digest": digest,
            }
            self._entries[index_id] = []
            self._emit(
                KIND_CREATED, seq, index_id=index_id, table_id=table_id, field=field, index_kind=kind
            )
            return IndexRecord(
                index_id=index_id,
                table_id=table_id,
                field=field,
                kind=kind,
                seq=seq,
                digest=digest,
            )

    def drop(self, index_id: str, seq: Any) -> DropRecord:
        """Terminally retire an index. The id is never recycled."""
        with self._lock:
            seq = self._claim(seq)
            try:
                index_id = _check_id(index_id, BadIndexError)
            except IndexManagerError as exc:
                self._fail(seq, exc)
            entry = self._indexes.get(index_id)
            if entry is None:
                self._fail(seq, UnknownIndexError(f"unknown index: {index_id!r}"), index_id=index_id)
            assert entry is not None
            if entry["state"] == _STATE_DROPPED:
                self._fail(seq, DroppedIndexError(f"index already dropped: {index_id!r}"), index_id=index_id)
            entry["state"] = _STATE_DROPPED
            digest = _digest_pin((index_id, seq), "drop-record")
            self._emit(KIND_DROPPED, seq, index_id=index_id)
            return DropRecord(index_id=index_id, seq=seq, digest=digest)

    # -- bindings ----------------------------------------------------------

    def bind(self, index_id: str, key: Any, row_id: str, seq: Any) -> BindRecord:
        """Book one ``(key, row_id)`` entry on an active index."""
        with self._lock:
            seq = self._claim(seq)
            try:
                index_id = _check_id(index_id, BadIndexError)
                key = _check_key(key)
                row_id = _check_id(row_id, BadRowError)
            except IndexManagerError as exc:
                self._fail(seq, exc)
            self._get_active(index_id, seq)
            key_digest = _digest_pin(("key", key), "key")
            sort_key = (0, key) if isinstance(key, int) else (1, key)
            rows = self._entries[index_id]
            for existing_digest, _, _, existing_row in rows:
                if existing_digest == key_digest and existing_row == row_id:
                    self._fail(
                        seq,
                        DuplicateBindingError(f"binding already exists: {index_id!r}/{row_id!r}"),
                        index_id=index_id,
                        row_id=row_id,
                    )
            rows.append((key_digest, sort_key, key, row_id))
            digest = _digest_pin((index_id, key_digest, row_id, seq), "bind-record")
            self._emit(KIND_BOUND, seq, index_id=index_id, key_digest=key_digest, row_id=row_id)
            return BindRecord(
                index_id=index_id, key_digest=key_digest, row_id=row_id, seq=seq, digest=digest
            )

    def unbind(self, index_id: str, key: Any, row_id: str, seq: Any) -> UnbindRecord:
        """Release one ``(key, row_id)`` entry from an active index."""
        with self._lock:
            seq = self._claim(seq)
            try:
                index_id = _check_id(index_id, BadIndexError)
                key = _check_key(key)
                row_id = _check_id(row_id, BadRowError)
            except IndexManagerError as exc:
                self._fail(seq, exc)
            self._get_active(index_id, seq)
            key_digest = _digest_pin(("key", key), "key")
            rows = self._entries[index_id]
            for i, (existing_digest, _, _, existing_row) in enumerate(rows):
                if existing_digest == key_digest and existing_row == row_id:
                    del rows[i]
                    digest = _digest_pin((index_id, key_digest, row_id, seq), "unbind-record")
                    self._emit(
                        KIND_UNBOUND, seq, index_id=index_id, key_digest=key_digest, row_id=row_id
                    )
                    return UnbindRecord(
                        index_id=index_id,
                        key_digest=key_digest,
                        row_id=row_id,
                        seq=seq,
                        digest=digest,
                    )
            self._fail(
                seq,
                UnknownBindingError(f"no such binding: {index_id!r}/{row_id!r}"),
                index_id=index_id,
                row_id=row_id,
            )
            raise AssertionError("unreachable")

    # -- reads (pure; seq shape validated, never consumed) -------------------

    def lookup(self, index_id: str, key: Any, seq: Any) -> LookupReport:
        """Pure read view: sorted row ids bound to ``key`` on the index."""
        with self._lock:
            _check_seq(seq)
            index_id = _check_id(index_id, BadIndexError)
            key = _check_key(key)
            rows = self._entries.get(index_id)
            if rows is None:
                raise UnknownIndexError(f"unknown index: {index_id!r}")
            key_digest = _digest_pin(("key", key), "key")
            matched = sorted(r for d, _, _, r in rows if d == key_digest)
            return LookupReport(
                index_id=index_id,
                key_digest=key_digest,
                row_ids=tuple(matched),
                digest=_digest_pin((index_id, key_digest, tuple(matched)), "lookup-report"),
            )

    def keys(self, index_id: str, seq: Any) -> KeysReport:
        """Pure read view: the key digests held by an index, in sorted order."""
        with self._lock:
            _check_seq(seq)
            index_id = _check_id(index_id, BadIndexError)
            rows = self._entries.get(index_id)
            if rows is None:
                raise UnknownIndexError(f"unknown index: {index_id!r}")
            digests = tuple(sorted({d for d, _, _, _ in rows}))
            return KeysReport(index_id=index_id, key_digests=digests, count=len(digests))

    # -- views ---------------------------------------------------------------

    def index_record(self, index_id: str) -> Optional[IndexRecord]:
        with self._lock:
            entry = self._indexes.get(index_id)
            if entry is None:
                return None
            return IndexRecord(
                index_id=entry["index_id"],
                table_id=entry["table_id"],
                field=entry["field"],
                kind=entry["kind"],
                seq=entry["seq"],
                digest=entry["digest"],
            )

    def index_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._indexes))

    def active_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(
                sorted(i for i, e in self._indexes.items() if e["state"] == _STATE_ACTIVE)
            )

    def binding_count(self, index_id: str) -> int:
        with self._lock:
            rows = self._entries.get(index_id)
            if rows is None:
                raise UnknownIndexError(f"unknown index: {index_id!r}")
            return len(rows)

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return tuple(self._audit)


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------


def main() -> None:
    mgr = IndexManager()
    rec = mgr.create("by-email", "users", "email", 1)
    assert rec.verify()
    mgr.bind("by-email", "a@x.com", "row-1", 2)
    mgr.bind("by-email", "a@x.com", "row-2", 3)
    mgr.bind("by-email", "b@x.com", "row-3", 4)
    report = mgr.lookup("by-email", "a@x.com", 5)
    assert report.verify()
    assert report.row_ids == ("row-1", "row-2"), report.row_ids
    assert mgr.binding_count("by-email") == 3
    keys = mgr.keys("by-email", 6)
    assert keys.count == 2
    mgr.unbind("by-email", "a@x.com", "row-1", 7)
    assert mgr.lookup("by-email", "a@x.com", 8).row_ids == ("row-2",)
    mgr.drop("by-email", 9)
    assert mgr.active_ids() == ()
    try:
        mgr.bind("by-email", "c@x.com", "row-9", 10)
        raise AssertionError("bind on dropped index must fail")
    except DroppedIndexError:
        pass
    kinds = [e["kind"] for e in mgr.audit_log()]
    assert kinds[0] == KIND_CREATED and kinds[-2] == KIND_DROPPED
    assert all(e["schema"] == AUDIT_SCHEMA for e in mgr.audit_log())
    print("index-manager OK: create, bind, lookup, unbind, drop, fail-closed, audit")


if __name__ == "__main__":
    main()
