"""MongoDB-style document store: CRUD plus single-field indexes, in-memory.

Research note: a *document store* (MongoDB, 2009; CouchDB; the
"schemaless" family) persists JSON-like documents keyed by ``_id`` and
answers equality/range queries over document fields. The production
concerns are well documented in the MongoDB manual:

* **_id primary key** -- every document carries an ``_id``; duplicate
  ``_id`` on insert is refused (here :class:`DuplicateKeyError`), never
  silently upserted.
* **Single-field indexes** -- an index maps *canonicalized* field values
  to the set of ``_id``s holding them, so equality lookups skip the
  collection scan. :meth:`DocumentStore.explain` reports which strategy a
  query used (``"index-scan"`` vs ``"collection-scan"``), making index
  usage testable rather than a claim.
* **Update operators** -- MongoDB's ``update`` takes operator documents
  (``$set`` / ``$unset`` / ``$inc``). Bare replacement documents are
  refused fail-closed here (they silently drop fields in production --
  the number-one cause of "my update deleted data" incidents).
* **Unique indexes** -- a unique index refuses an insert/update that
  would duplicate a value (here :class:`UniqueViolationError`), the
  in-memory analogue of MongoDB's duplicate-key error on unique indexes.

Documents and indexes are pinned by ``sha256:`` digests of the shared
JCS canonical form, so a stored payload and its pins are tamper-evident.

Honest scope: this is in-memory *interface bookkeeping*, not MongoDB.
It has no persistence (a crash loses the store), no query planner beyond
"first indexed equality field wins", no multi-document transactions, and
pins only host-reported bytes -- it cannot prove a document was true.
JCS canonicalization folds ``1`` and ``1.0`` to the same digest (RFC 8785
§3.2.2.1), so a unique index treats them as equal; NaN/inf are refused
at the API boundary because JCS cannot encode them. Dotted paths
(``"a.b.c"``) reach into nested mappings; a missing intermediate is a
miss, never an implicit document creation on read.

Version pin: document-store.v1
Schema pin: northstar.document-store.v1
"""

from __future__ import annotations

import copy
import hashlib
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Set, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Module version.
DOCUMENT_STORE_VERSION = "document-store.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.document-store.v1"


class DocumentError(Exception):
    """Base error for document-store misuse or constraint violations."""


class DuplicateKeyError(DocumentError):
    """Insert (or unique-index update) would duplicate an ``_id``."""


class UnknownDocumentError(DocumentError):
    """An operation named an ``_id`` that does not exist."""


class QueryError(DocumentError):
    """Malformed filter, update document, or operator use."""


class IndexError(DocumentError):
    """Malformed index definition or index operation."""


class UniqueViolationError(DocumentError):
    """Insert/update would violate a unique index."""


def _check_str(value: Any, name: str, allow_empty: bool = False) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise DocumentError(f"{name} must be a str, got {type(value).__name__}")
    if not allow_empty and not value:
        raise DocumentError(f"{name} must be non-empty")
    return value


def _check_id(value: Any) -> Any:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise DocumentError(f"_id must be a str or int, got {type(value).__name__}")
    if isinstance(value, str) and not value:
        raise DocumentError("_id must be non-empty")
    return value


def _check_mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise DocumentError(f"{name} must be a mapping, got {type(value).__name__}")
    for k in value.keys():
        if not isinstance(k, str) or not k:
            raise DocumentError(f"{name} keys must be non-empty strings")
    return value


def _check_canonical(payload: Any) -> None:
    """Refuse values the shared canonicalizer cannot encode (NaN/inf, bytes, ...)."""
    try:
        jcs_canonical_json(payload)
    except Exception as exc:
        raise DocumentError(f"value is not canonicalizable: {exc}") from exc


def _digest(payload: Any) -> str:
    return "sha256:" + hashlib.sha256(jcs_canonical_json(payload)).hexdigest()


def _split_path(path: str) -> List[str]:
    _check_str(path, "field path")
    if path.startswith(".") or path.endswith(".") or ".." in path:
        raise QueryError(f"malformed field path: {path!r}")
    return path.split(".")


def _get_path(doc: Mapping[str, Any], path: str) -> Tuple[bool, Any]:
    """Return (found, value) for a dotted path; missing => (False, None)."""
    node: Any = doc
    for part in _split_path(path):
        if not isinstance(node, Mapping) or part not in node:
            return False, None
        node = node[part]
    return True, node


def _set_path(doc: Dict[str, Any], path: str, value: Any) -> None:
    """Set a dotted path, creating intermediate mappings."""
    parts = _split_path(path)
    node = doc
    for part in parts[:-1]:
        child = node.get(part)
        if not isinstance(child, dict):
            child = {}
            node[part] = child
        node = child
    node[parts[-1]] = value


def _unset_path(doc: Dict[str, Any], path: str) -> bool:
    """Remove a dotted path leaf; returns True if something was removed."""
    parts = _split_path(path)
    node = doc
    for part in parts[:-1]:
        child = node.get(part)
        if not isinstance(child, dict):
            return False
        node = child
    if parts[-1] in node:
        del node[parts[-1]]
        return True
    return False


_OPERATORS = ("$eq", "$ne", "$gt", "$gte", "$lt", "$lte", "$in")


def _check_number(value: Any, name: str) -> Any:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise QueryError(f"{name} must be a number, got {type(value).__name__}")
    return value


def _values_equal(a: Any, b: Any) -> bool:
    """Canonical-bytes equality: treats 1 and 1.0 as equal (JCS folding)."""
    try:
        return jcs_canonical_json(a) == jcs_canonical_json(b)
    except Exception:
        return a == b


def _filter_matches(doc: Mapping[str, Any], filter: Mapping[str, Any]) -> bool:
    """Mongo-ish filter: {field: value-or-{op: value}} with dotted fields."""
    for path, cond in filter.items():
        found, value = _get_path(doc, path)
        if isinstance(cond, Mapping) and any(
            isinstance(k, str) and k.startswith("$") for k in cond.keys()
        ):
            for op, operand in cond.items():
                if op not in _OPERATORS:
                    raise QueryError(f"unknown filter operator: {op}")
                if op == "$eq":
                    if not (found and _values_equal(value, operand)):
                        return False
                elif op == "$ne":
                    if found and _values_equal(value, operand):
                        return False
                elif op == "$in":
                    if not isinstance(operand, (list, tuple)) or not operand:
                        raise QueryError("$in requires a non-empty list")
                    if not (found and any(_values_equal(value, v) for v in operand)):
                        return False
                else:  # order operators need comparable values
                    if not found:
                        return False
                    _check_number(value, "field value")
                    _check_number(operand, f"operand of {op}")
                    if op == "$gt" and not value > operand:
                        return False
                    if op == "$gte" and not value >= operand:
                        return False
                    if op == "$lt" and not value < operand:
                        return False
                    if op == "$lte" and not value <= operand:
                        return False
        else:
            if not (found and _values_equal(value, cond)):
                return False
    return True


@dataclass(frozen=True)
class Document:
    """One stored document (frozen record)."""

    version: str
    doc_id: Any
    payload: Dict[str, Any]
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "doc_id": self.doc_id,
            "payload": copy.deepcopy(self.payload),
            "digest": self.digest,
        }


@dataclass(frozen=True)
class WriteResult:
    """Outcome of an insert/update/delete (frozen record)."""

    version: str
    op: str
    doc_id: Any = None
    matched: int = 0
    modified: int = 0
    deleted: int = 0

    def as_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "op": self.op,
            "doc_id": self.doc_id,
            "matched": self.matched,
            "modified": self.modified,
            "deleted": self.deleted,
        }


@dataclass(frozen=True)
class IndexDefinition:
    """A single-field index (frozen record)."""

    version: str
    name: str
    field: str
    unique: bool

    def as_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "name": self.name,
            "field": self.field,
            "unique": self.unique,
        }


@dataclass(frozen=True)
class QueryPlan:
    """Explain output for a filter (frozen record)."""

    version: str
    strategy: str  # "index-scan" | "collection-scan"
    index: Optional[str]
    fields: Tuple[str, ...]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "strategy": self.strategy,
            "index": self.index,
            "fields": list(self.fields),
        }


class DocumentStore:
    """In-memory MongoDB-style document store with single-field indexes."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._docs: Dict[Any, Dict[str, Any]] = {}
        self._seq = 0
        # index name -> IndexDefinition; index name -> canonical-bytes -> set(doc_id)
        self._indexes: Dict[str, IndexDefinition] = {}
        self._index_keys: Dict[str, Dict[bytes, Set[Any]]] = {}

    # -- index bookkeeping -------------------------------------------------
    def _index_value_key(self, payload: Mapping[str, Any], path: str) -> Optional[bytes]:
        found, value = _get_path(payload, path)
        if not found:
            return None
        return jcs_canonical_json(value)

    def _index_doc(self, doc_id: Any, payload: Mapping[str, Any]) -> None:
        for name, definition in self._indexes.items():
            key = self._index_value_key(payload, definition.field)
            if key is None:
                continue
            bucket = self._index_keys[name].setdefault(key, set())
            if definition.unique and bucket and doc_id not in bucket:
                raise UniqueViolationError(
                    f"unique index {name!r} violated on field {definition.field!r}"
                )
            bucket.add(doc_id)

    def _deindex_doc(self, doc_id: Any, payload: Mapping[str, Any]) -> None:
        for name, definition in self._indexes.items():
            key = self._index_value_key(payload, definition.field)
            if key is None:
                continue
            bucket = self._index_keys[name].get(key)
            if bucket is not None:
                bucket.discard(doc_id)
                if not bucket:
                    del self._index_keys[name][key]

    # -- CRUD --------------------------------------------------------------
    def insert(self, doc: Mapping[str, Any]) -> WriteResult:
        """Insert a document; assigns ``_id`` as ``doc-N`` when absent."""
        _check_mapping(doc, "doc")
        with self._lock:
            payload = copy.deepcopy(dict(doc))
            _check_canonical(payload)
            doc_id = payload.get("_id")
            if doc_id is None:
                self._seq += 1
                doc_id = f"doc-{self._seq}"
                payload["_id"] = doc_id
            else:
                _check_id(doc_id)
            if doc_id in self._docs:
                raise DuplicateKeyError(f"duplicate _id: {doc_id!r}")
            self._index_doc(doc_id, payload)
            self._docs[doc_id] = payload
            return WriteResult(version=DOCUMENT_STORE_VERSION, op="insert", doc_id=doc_id)

    def find(self, filter: Optional[Mapping[str, Any]] = None) -> List[Document]:
        """Return matching documents in insertion order (deep copies)."""
        filter = {} if filter is None else _check_mapping(filter, "filter")
        with self._lock:
            ids = self._candidate_ids(filter)
            docs: List[Document] = []
            if ids is None:
                for doc_id, payload in self._docs.items():
                    if _filter_matches(payload, filter):
                        docs.append(self._wrap(doc_id, payload))
            else:
                for doc_id in self._docs:  # preserve insertion order
                    if doc_id in ids and _filter_matches(self._docs[doc_id], filter):
                        docs.append(self._wrap(doc_id, self._docs[doc_id]))
            return docs

    def find_one(self, filter: Optional[Mapping[str, Any]] = None) -> Optional[Document]:
        """Return the first matching document, or None."""
        found = self.find(filter)
        return found[0] if found else None

    def count(self, filter: Optional[Mapping[str, Any]] = None) -> int:
        """Count matching documents."""
        return len(self.find(filter))

    def _candidate_ids(self, filter: Mapping[str, Any]) -> Optional[Set[Any]]:
        """Index-narrowed candidate ids, or None for a full collection scan."""
        for path, cond in filter.items():
            if isinstance(cond, Mapping):
                continue  # operator filters do not use indexes here
            for name, definition in self._indexes.items():
                if definition.field == path:
                    key = jcs_canonical_json(cond)
                    return set(self._index_keys[name].get(key, set()))
        return None

    def _wrap(self, doc_id: Any, payload: Dict[str, Any]) -> Document:
        return Document(
            version=DOCUMENT_STORE_VERSION,
            doc_id=doc_id,
            payload=copy.deepcopy(payload),
            digest=_digest(payload),
        )

    def _apply_update(self, payload: Dict[str, Any], update: Mapping[str, Any]) -> int:
        """Apply $set/$unset/$inc; returns number of fields touched."""
        if not update:
            raise QueryError("update document must not be empty")
        touched = 0
        for op, operand in update.items():
            if op == "$set":
                for path, value in _check_mapping(operand, "$set").items():
                    _split_path(path)
                    _set_path(payload, path, copy.deepcopy(value))
                    touched += 1
            elif op == "$unset":
                if isinstance(operand, Mapping):
                    fields = list(operand.keys())
                elif isinstance(operand, (list, tuple)):
                    fields = list(operand)
                else:
                    raise QueryError("$unset requires a mapping or list of fields")
                for path in fields:
                    if _unset_path(payload, _check_str(path, "$unset field")):
                        touched += 1
            elif op == "$inc":
                for path, delta in _check_mapping(operand, "$inc").items():
                    _check_number(delta, "$inc delta")
                    found, current = _get_path(payload, path)
                    if found:
                        _check_number(current, "field value")
                        _set_path(payload, path, current + delta)
                    else:
                        _set_path(payload, path, delta)
                    touched += 1
            else:
                raise QueryError(f"unknown update operator: {op}")
        _check_canonical(payload)
        return touched

    def update(
        self, filter: Mapping[str, Any], update: Mapping[str, Any]
    ) -> WriteResult:
        """Apply operator update to all matching documents (multi=true)."""
        _check_mapping(filter, "filter")
        _check_mapping(update, "update")
        if not any(isinstance(k, str) and k.startswith("$") for k in update.keys()):
            raise QueryError("update must use operators ($set/$unset/$inc)")
        with self._lock:
            matched = 0
            modified = 0
            for doc_id, payload in list(self._docs.items()):
                if not _filter_matches(payload, filter):
                    continue
                matched += 1
                new_payload = copy.deepcopy(payload)
                self._apply_update(new_payload, update)
                if new_payload.get("_id") != doc_id:
                    raise QueryError("_id is immutable")
                if not _values_equal(new_payload, payload):
                    self._deindex_doc(doc_id, payload)
                    try:
                        self._index_doc(doc_id, new_payload)
                    except UniqueViolationError:
                        self._index_doc(doc_id, payload)  # restore old entries
                        raise
                    self._docs[doc_id] = new_payload
                    modified += 1
            return WriteResult(
                version=DOCUMENT_STORE_VERSION,
                op="update",
                matched=matched,
                modified=modified,
            )

    def delete(self, filter: Mapping[str, Any]) -> WriteResult:
        """Delete all matching documents; returns the deleted count."""
        _check_mapping(filter, "filter")
        with self._lock:
            deleted = 0
            for doc_id, payload in list(self._docs.items()):
                if _filter_matches(payload, filter):
                    self._deindex_doc(doc_id, payload)
                    del self._docs[doc_id]
                    deleted += 1
            return WriteResult(
                version=DOCUMENT_STORE_VERSION, op="delete", deleted=deleted
            )

    def get(self, doc_id: Any) -> Document:
        """Fetch one document by ``_id`` (deep copy)."""
        _check_id(doc_id)
        with self._lock:
            payload = self._docs.get(doc_id)
            if payload is None:
                raise UnknownDocumentError(f"no document with _id {doc_id!r}")
            return self._wrap(doc_id, payload)

    # -- indexes ------------------------------------------------------------
    def create_index(
        self, field: str, unique: bool = False, name: Optional[str] = None
    ) -> IndexDefinition:
        """Create a single-field index; backfills over existing documents."""
        _split_path(field)
        if not isinstance(unique, bool):
            raise IndexError("unique must be a bool")
        with self._lock:
            index_name = name or f"idx_{field.replace('.', '_')}"
            _check_str(index_name, "index name")
            if index_name in self._indexes:
                raise IndexError(f"index {index_name!r} already exists")
            definition = IndexDefinition(
                version=DOCUMENT_STORE_VERSION,
                name=index_name,
                field=field,
                unique=unique,
            )
            self._indexes[index_name] = definition
            self._index_keys[index_name] = {}
            try:
                for doc_id, payload in self._docs.items():
                    self._index_doc(doc_id, payload)
            except UniqueViolationError:
                del self._indexes[index_name]
                del self._index_keys[index_name]
                raise
            return definition

    def drop_index(self, name: str) -> None:
        """Drop an index by name."""
        _check_str(name, "index name")
        with self._lock:
            if name not in self._indexes:
                raise IndexError(f"unknown index {name!r}")
            del self._indexes[name]
            del self._index_keys[name]

    def list_indexes(self) -> List[IndexDefinition]:
        """List index definitions in creation order."""
        with self._lock:
            return list(self._indexes.values())

    def explain(self, filter: Optional[Mapping[str, Any]] = None) -> QueryPlan:
        """Report whether an index would serve this filter."""
        filter = {} if filter is None else _check_mapping(filter, "filter")
        with self._lock:
            fields = tuple(filter.keys())
            for path, cond in filter.items():
                if isinstance(cond, Mapping):
                    continue
                for name, definition in self._indexes.items():
                    if definition.field == path:
                        return QueryPlan(
                            version=DOCUMENT_STORE_VERSION,
                            strategy="index-scan",
                            index=name,
                            fields=fields,
                        )
            return QueryPlan(
                version=DOCUMENT_STORE_VERSION,
                strategy="collection-scan",
                index=None,
                fields=fields,
            )


def document_store_audit_event(
    seq: int, op: str, result: Optional[WriteResult] = None
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for a document-store write."""
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise DocumentError(f"seq must be a non-negative int, got {seq!r}")
    _check_str(op, "op")
    if op not in ("insert", "update", "delete"):
        raise DocumentError(f"unknown op: {op!r}")
    event: Dict[str, Any] = {
        "version": SCHEMA_PIN,
        "event": "document-store",
        "op": op,
        "audit_seq": seq,
    }
    if result is not None:
        event["result"] = result.as_dict()
    return event


def main() -> None:
    """Self-check: CRUD, indexes, operators, fail-closed paths."""
    store = DocumentStore()

    r1 = store.insert({"name": "alice", "age": 30})
    assert r1.op == "insert" and r1.doc_id == "doc-1"
    r2 = store.insert({"_id": "u-7", "name": "bob", "age": 25})
    assert r2.doc_id == "u-7"
    try:
        store.insert({"_id": "u-7", "name": "mallory"})
    except DuplicateKeyError:
        pass
    else:  # pragma: no cover
        raise AssertionError("duplicate _id accepted")

    assert store.count() == 2
    alice = store.find_one({"name": "alice"})
    assert alice is not None and alice.doc_id == "doc-1"
    assert store.find({"age": {"$gte": 28}}) and len(store.find({"age": {"$gte": 28}})) == 1

    store.create_index("name")
    plan = store.explain({"name": "alice"})
    assert plan.strategy == "index-scan" and plan.index is not None
    assert store.explain({"age": 30}).strategy == "collection-scan"
    assert store.find({"name": "alice"})[0].doc_id == "doc-1"

    upd = store.update({"name": "alice"}, {"$set": {"age": 31}, "$inc": {}})
    assert upd.matched == 1 and upd.modified == 1
    assert store.get("doc-1").payload["age"] == 31
    upd2 = store.update({"name": "alice"}, {"$unset": {"age": ""}})
    assert upd2.modified == 1 and "age" not in store.get("doc-1").payload
    try:
        store.update({"name": "alice"}, {"age": 99})  # bare replacement
    except QueryError:
        pass
    else:  # pragma: no cover
        raise AssertionError("bare replacement accepted")

    store.create_index("email", unique=True)
    store.update({"name": "alice"}, {"$set": {"email": "a@x.io"}})
    try:
        store.update({"name": "bob"}, {"$set": {"email": "a@x.io"}})
    except UniqueViolationError:
        pass
    else:  # pragma: no cover
        raise AssertionError("unique index not enforced")
    assert store.get("u-7").payload.get("email") is None  # failed update rolled back

    got = store.get("doc-1")
    got.payload["name"] = "hacked"  # caller-side mutation of the copy
    assert store.get("doc-1").payload["name"] == "alice"

    deleted = store.delete({"name": "bob"})
    assert deleted.deleted == 1 and store.count() == 1
    assert document_store_audit_event(0, "insert")["op"] == "insert"

    print("document-store OK: CRUD, indexes, operators, unique, isolation")


if __name__ == "__main__":
    main()
