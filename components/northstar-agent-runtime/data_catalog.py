"""Amundsen-shaped data catalog: a ledger for dataset/schema decisions.

A ``DataCatalog`` books host-reported dataset registrations, schema
definitions, and search queries as a deterministic single-host state
machine (Amundsen/DataHub research context):

- ``dataset(dataset_id, name, seq, columns=(), tags=(), owner="",
  description="")`` registers one dataset as a frozen ``DatasetRecord``
  pinned by a ``sha256:`` digest. Columns are host-reported
  ``(name, type)`` pairs whose types use a pinned data-warehouse
  vocabulary (``string``/``integer``/``number``/``boolean``/``timestamp``/
  ``date``/``array``/``struct``). Duplicate ids are refused fail-closed;
  retired ids are never recycled.
- ``schema(dataset_id, seq)`` is a pure read view returning a frozen
  ``SchemaReport`` of the dataset's pinned columns (names, types, and
  the schema digest). The seq is validated, never consumed, and no audit
  row is written.
- ``search(query, seq, tags=(), owner="")`` is a pure read view returning
  a frozen ``SearchReport`` of matching dataset ids sorted for
  determinism: name/description substring match plus tag-subset and
  owner filtering. No match is data, never an error.
- ``update_schema(dataset_id, seq, columns=())`` books a schema
  evolution as a frozen ``SchemaUpdateRecord`` (supersedes the previous
  schema; the record pins both the old and new schema digests).
- ``retire(dataset_id, seq, reason="")`` terminally retires a dataset
  (Amundsen deprecation semantics); the id can never be re-registered.

House style: frozen dataclasses, caller-supplied strictly increasing int
seqs (no wall-clock), RLock-guarded, fail-closed taxonomy, stdlib-only
plus the standard ``canonical_json`` try/except fallback, ``sha256:``
digest pins, ``audit.ndjson/1`` events, version pin
``data-catalog.v1``, schema pin ``northstar.data-catalog.v1``,
``main()`` self-check.

Honest scope: this module books *declared* datasets and validates
*host-reported* schemas against them. It is not a metadata crawler, it
cannot observe any real database, and a search hit means only "matches
the declared catalog" — never that the dataset exists or is fresh.
Dataset names, descriptions, tags, and column values never cross the
audit boundary (ids + digest pins only).
"""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import
    import json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Version pin for this module's record shape.
DATA_CATALOG_VERSION = "data-catalog.v1"

#: Schema pin carried by records and audit events.
DATA_CATALOG_SCHEMA = "northstar.data-catalog.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Pinned column-type vocabulary for dataset schemas.
COLUMN_TYPES = (
    "string",
    "integer",
    "number",
    "boolean",
    "timestamp",
    "date",
    "array",
    "struct",
)

#: Pin: maximum dataset id / name / owner / tag length in chars.
MAX_ID_CHARS = 128
MAX_NAME_CHARS = 256
MAX_TAG_CHARS = 64

#: Pin: maximum description length in chars.
MAX_DESCRIPTION_CHARS = 4096

#: Pin: maximum columns per schema and maximum tags per dataset.
MAX_COLUMNS = 1024
MAX_TAGS = 64

#: Audit kind vocabulary for data_catalog_audit_event().
AUDIT_KINDS = (
    "dataset-registered",
    "schema-updated",
    "retired",
    "rejected",
)

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


# ---------------------------------------------------------------------------
# Error taxonomy
# ---------------------------------------------------------------------------


class DataCatalogError(Exception):
    """Base class for all data_catalog errors."""


class BadDatasetError(DataCatalogError):
    """Dataset id / name / description / owner failed validation."""


class DuplicateDatasetError(DataCatalogError):
    """A dataset id is already registered (ids are never recycled)."""


class UnknownDatasetError(DataCatalogError):
    """No such dataset id in the catalog."""


class RetiredDatasetError(DataCatalogError):
    """The dataset is retired and cannot accept mutations."""


class BadSchemaError(DataCatalogError):
    """The schema argument failed validation."""


class BadColumnError(DataCatalogError):
    """A column definition failed validation."""


class BadTagError(DataCatalogError):
    """A tag failed validation."""


class SeqOrderError(DataCatalogError):
    """Caller seq failed validation (not a positive int, or rewind)."""


class AuditKindError(DataCatalogError):
    """Unknown audit kind passed to data_catalog_audit_event()."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_str(value: Any, what: str, max_chars: int) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadDatasetError(f"{what} must be a str, got {type(value).__name__}")
    if not value:
        raise BadDatasetError(f"{what} must not be empty")
    if len(value) > max_chars:
        raise BadDatasetError(f"{what} too long (>{max_chars} chars)")
    if _CONTROL_RE.search(value):
        raise BadDatasetError(f"{what} contains control characters")
    return value


def _check_id(dataset_id: Any) -> str:
    value = _check_str(dataset_id, "dataset_id", MAX_ID_CHARS)
    if not _ID_RE.match(value):
        raise BadDatasetError(
            "dataset_id must match [A-Za-z0-9][A-Za-z0-9._-]*"
        )
    return value


def _check_tag(tag: Any) -> str:
    if isinstance(tag, bool) or not isinstance(tag, str):
        raise BadTagError(f"tag must be a str, got {type(tag).__name__}")
    if not tag:
        raise BadTagError("tag must not be empty")
    if len(tag) > MAX_TAG_CHARS:
        raise BadTagError(f"tag too long (>{MAX_TAG_CHARS} chars)")
    if _CONTROL_RE.search(tag):
        raise BadTagError("tag contains control characters")
    return tag


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"seq must be an int, got {type(seq).__name__}")
    if seq <= 0:
        raise SeqOrderError(f"seq must be positive, got {seq}")
    return seq


def _check_columns(columns: Any) -> Tuple[Tuple[str, str], ...]:
    if isinstance(columns, (str, bytes)) or not isinstance(columns, Sequence):
        raise BadSchemaError("columns must be a sequence of (name, type) pairs")
    if len(columns) > MAX_COLUMNS:
        raise BadSchemaError(f"too many columns (>{MAX_COLUMNS})")
    seen: List[str] = []
    out: List[Tuple[str, str]] = []
    for entry in columns:
        if not isinstance(entry, (tuple, list)) or len(entry) != 2:
            raise BadColumnError("each column must be a (name, type) pair")
        raw_name, raw_type = entry
        name = _check_str(raw_name, "column name", MAX_NAME_CHARS)
        if not _ID_RE.match(name):
            raise BadColumnError("column name must match [A-Za-z0-9][A-Za-z0-9._-]*")
        if name in seen:
            raise BadColumnError(f"duplicate column name: {name!r}")
        seen.append(name)
        if isinstance(raw_type, bool) or not isinstance(raw_type, str):
            raise BadColumnError("column type must be a str")
        col_type = raw_type
        if col_type not in COLUMN_TYPES:
            raise BadColumnError(
                f"column type must be one of {COLUMN_TYPES}, got {col_type!r}"
            )
        out.append((name, col_type))
    return tuple(out)


def _digest(*parts: Any) -> str:
    canonical = jcs_canonical_json(
        ["northstar.data-catalog.v1", *[str(p) for p in parts]]
    )
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DatasetRecord:
    """Frozen registration record for one dataset."""

    dataset_id: str
    name: str
    columns: Tuple[Tuple[str, str], ...]
    tags: Tuple[str, ...]
    owner: str
    description: str
    digest: str
    schema_digest: str
    seq: int
    retired: bool = False

    def verify(self) -> bool:
        """Recompute the digest pins; True when untampered."""
        columns = tuple((str(n), str(t)) for n, t in self.columns)
        schema = _digest("schema", *columns)
        if schema != self.schema_digest:
            return False
        expected = _digest(
            "dataset",
            self.dataset_id,
            self.name,
            schema,
            *sorted(self.tags),
            self.owner,
        )
        return expected == self.digest


@dataclass(frozen=True)
class SchemaReport:
    """Pure read view of a dataset's pinned schema."""

    dataset_id: str
    columns: Tuple[Tuple[str, str], ...]
    schema_digest: str
    seq: int


@dataclass(frozen=True)
class SearchReport:
    """Pure read view of a search: matching dataset ids, sorted."""

    query: str
    tags: Tuple[str, ...]
    owner: str
    dataset_ids: Tuple[str, ...]
    seq: int


@dataclass(frozen=True)
class SchemaUpdateRecord:
    """Frozen booking of a schema evolution."""

    dataset_id: str
    old_schema_digest: str
    columns: Tuple[Tuple[str, str], ...]
    schema_digest: str
    seq: int

    def verify(self) -> bool:
        columns = tuple((str(n), str(t)) for n, t in self.columns)
        return _digest("schema", *columns) == self.schema_digest


@dataclass(frozen=True)
class RetireRecord:
    """Frozen terminal booking of a dataset retirement."""

    dataset_id: str
    reason: str
    seq: int


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def data_catalog_audit_event(
    kind: str,
    *,
    dataset_id: str = "",
    seq: int = 0,
    digest: str = "",
    reason: str = "",
) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1``-shaped audit event.

    The audit boundary carries ids + digest pins only: names, descriptions,
    tags, and column definitions never cross it.
    """
    if kind not in AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    event: Dict[str, Any] = {
        "schema": AUDIT_SCHEMA,
        "module": DATA_CATALOG_SCHEMA,
        "kind": kind,
        "dataset_id": dataset_id,
        "seq": _check_seq(seq) if seq else seq,
    }
    if digest:
        event["digest"] = digest
    if reason:
        event["reason"] = reason
    return event


# ---------------------------------------------------------------------------
# The catalog
# ---------------------------------------------------------------------------


class DataCatalog:
    """Amundsen-shaped dataset/schema catalog as a deterministic ledger."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = 0
        self._datasets: Dict[str, DatasetRecord] = {}
        self._retired: Dict[str, RetireRecord] = {}
        self._schema_history: Dict[str, List[SchemaUpdateRecord]] = {}
        self._audit: List[Dict[str, Any]] = []

    # -- internal plumbing ---------------------------------------------------

    def _claim(self, seq: int) -> int:
        seq = _check_seq(seq)
        with self._lock:
            if seq <= self._last_seq:
                raise SeqOrderError(
                    f"seq must be strictly increasing (last={self._last_seq})"
                )
            self._last_seq = seq
        return seq

    def _emit(self, kind: str, dataset_id: str, seq: int, digest: str = "") -> None:
        with self._lock:
            self._audit.append(
                data_catalog_audit_event(
                    kind, dataset_id=dataset_id, seq=seq, digest=digest
                )
            )

    def _fail(
        self, seq: int, exc: DataCatalogError, dataset_id: str = ""
    ) -> None:
        """Book a rejection (batch-21 discipline: failed mutations consume
        their seq) and raise the given exception."""
        try:
            seq = self._claim(seq)
        except SeqOrderError:
            raise exc
        self._emit("rejected", dataset_id, seq)
        raise exc

    # -- mutations -----------------------------------------------------------

    def dataset(
        self,
        dataset_id: str,
        name: str,
        seq: int,
        columns: Sequence[Tuple[str, str]] = (),
        tags: Sequence[str] = (),
        owner: str = "",
        description: str = "",
    ) -> DatasetRecord:
        """Register one dataset. Failed validations consume their seq."""
        dataset_id = _check_id(dataset_id)
        try:
            name = _check_str(name, "name", MAX_NAME_CHARS)
        except BadDatasetError as exc:
            self._fail(seq, exc, dataset_id)
        try:
            if description:
                description = _check_str(description, "description", MAX_DESCRIPTION_CHARS)
        except BadDatasetError as exc:
            self._fail(seq, exc, dataset_id)
        try:
            owner_checked = (
                _check_str(owner, "owner", MAX_NAME_CHARS) if owner else ""
            )
        except BadDatasetError as exc:
            self._fail(seq, exc, dataset_id)
        try:
            column_tuple = _check_columns(columns)
        except DataCatalogError as exc:
            self._fail(seq, exc, dataset_id)
        try:
            tag_tuple = tuple(sorted(_check_tag(t) for t in tags))
            if len(tag_tuple) > MAX_TAGS:
                raise BadTagError(f"too many tags (>{MAX_TAGS})")
            if len(set(tag_tuple)) != len(tag_tuple):
                raise BadTagError("duplicate tags")
        except DataCatalogError as exc:
            self._fail(seq, exc, dataset_id)
        with self._lock:
            if dataset_id in self._retired:
                seq = self._claim(seq)
                self._emit("rejected", dataset_id, seq)
                raise RetiredDatasetError(f"dataset {dataset_id!r} is retired")
            if dataset_id in self._datasets:
                seq = self._claim(seq)
                self._emit("rejected", dataset_id, seq)
                raise DuplicateDatasetError(f"dataset {dataset_id!r} already registered")
            seq = self._claim(seq)
            schema_digest = _digest("schema", *column_tuple)
            digest = _digest(
                "dataset", dataset_id, name, schema_digest, *tag_tuple, owner_checked
            )
            record = DatasetRecord(
                dataset_id=dataset_id,
                name=name,
                columns=column_tuple,
                tags=tag_tuple,
                owner=owner_checked,
                description=description,
                digest=digest,
                schema_digest=schema_digest,
                seq=seq,
            )
            self._datasets[dataset_id] = record
            self._schema_history[dataset_id] = []
        self._emit("dataset-registered", dataset_id, seq, digest)
        return record

    def update_schema(
        self, dataset_id: str, seq: int, columns: Sequence[Tuple[str, str]]
    ) -> SchemaUpdateRecord:
        """Book a schema evolution for a live dataset."""
        dataset_id = _check_id(dataset_id)
        try:
            column_tuple = _check_columns(columns)
        except DataCatalogError as exc:
            self._fail(seq, exc, dataset_id)
        with self._lock:
            record = self._datasets.get(dataset_id)
            if record is None:
                self._fail(seq, UnknownDatasetError(f"unknown dataset {dataset_id!r}"), dataset_id)
            if dataset_id in self._retired:
                self._fail(seq, RetiredDatasetError(f"dataset {dataset_id!r} is retired"), dataset_id)
            assert record is not None
            seq = self._claim(seq)
            new_digest = _digest("schema", *column_tuple)
            update = SchemaUpdateRecord(
                dataset_id=dataset_id,
                old_schema_digest=record.schema_digest,
                columns=column_tuple,
                schema_digest=new_digest,
                seq=seq,
            )
            self._datasets[dataset_id] = DatasetRecord(
                dataset_id=record.dataset_id,
                name=record.name,
                columns=column_tuple,
                tags=record.tags,
                owner=record.owner,
                description=record.description,
                digest=record.digest,
                schema_digest=new_digest,
                seq=record.seq,
                retired=False,
            )
            self._schema_history[dataset_id].append(update)
        self._emit("schema-updated", dataset_id, seq, new_digest)
        return update

    def retire(self, dataset_id: str, seq: int, reason: str = "") -> RetireRecord:
        """Terminally retire a dataset; the id is never recycled."""
        dataset_id = _check_id(dataset_id)
        if reason:
            try:
                reason = _check_str(reason, "reason", MAX_NAME_CHARS)
            except BadDatasetError as exc:
                self._fail(seq, exc, dataset_id)
        with self._lock:
            if dataset_id not in self._datasets:
                self._fail(seq, UnknownDatasetError(f"unknown dataset {dataset_id!r}"), dataset_id)
            if dataset_id in self._retired:
                self._fail(seq, RetiredDatasetError(f"dataset {dataset_id!r} already retired"), dataset_id)
            seq = self._claim(seq)
            record = RetireRecord(dataset_id=dataset_id, reason=reason, seq=seq)
            self._retired[dataset_id] = record
        self._emit("retired", dataset_id, seq)
        return record

    # -- pure read views -----------------------------------------------------

    def schema(self, dataset_id: str, seq: int) -> SchemaReport:
        """Return the pinned schema of a dataset. Pure read."""
        dataset_id = _check_id(dataset_id)
        _check_seq(seq)
        with self._lock:
            record = self._datasets.get(dataset_id)
            if record is None:
                raise UnknownDatasetError(f"unknown dataset {dataset_id!r}")
            return SchemaReport(
                dataset_id=dataset_id,
                columns=record.columns,
                schema_digest=record.schema_digest,
                seq=seq,
            )

    def search(
        self,
        query: str,
        seq: int,
        tags: Sequence[str] = (),
        owner: str = "",
        include_retired: bool = False,
    ) -> SearchReport:
        """Search the catalog: name/description substring + tag subset +
        owner filter. Pure read; no match is data."""
        _check_seq(seq)
        query = _check_str(query, "query", MAX_NAME_CHARS).lower()
        tag_tuple = tuple(sorted(_check_tag(t).lower() for t in tags))
        owner = _check_str(owner, "owner", MAX_NAME_CHARS).lower() if owner else ""
        with self._lock:
            hits: List[str] = []
            for dataset_id, record in self._datasets.items():
                if not include_retired and dataset_id in self._retired:
                    continue
                if owner and record.owner.lower() != owner:
                    continue
                if tag_tuple and not all(
                    t in {rt.lower() for rt in record.tags} for t in tag_tuple
                ):
                    continue
                haystack = (record.name + " " + record.description).lower()
                if query in haystack:
                    hits.append(dataset_id)
            return SearchReport(
                query=query,
                tags=tag_tuple,
                owner=owner,
                dataset_ids=tuple(sorted(hits)),
                seq=seq,
            )

    def dataset_view(self, dataset_id: str, seq: int) -> DatasetRecord:
        """Return the frozen registration record. Pure read."""
        dataset_id = _check_id(dataset_id)
        _check_seq(seq)
        with self._lock:
            record = self._datasets.get(dataset_id)
            if record is None:
                raise UnknownDatasetError(f"unknown dataset {dataset_id!r}")
            return record

    def dataset_ids(self, seq: int, include_retired: bool = False) -> Tuple[str, ...]:
        """Sorted dataset ids. Pure read."""
        _check_seq(seq)
        with self._lock:
            ids = list(self._datasets)
            if not include_retired:
                ids = [i for i in ids if i not in self._retired]
            return tuple(sorted(ids))

    def schema_history(
        self, dataset_id: str, seq: int
    ) -> Tuple[SchemaUpdateRecord, ...]:
        """Schema evolution history, oldest first. Pure read."""
        dataset_id = _check_id(dataset_id)
        _check_seq(seq)
        with self._lock:
            if dataset_id not in self._datasets:
                raise UnknownDatasetError(f"unknown dataset {dataset_id!r}")
            return tuple(self._schema_history[dataset_id])

    def stats(self, seq: int) -> Dict[str, int]:
        """Catalog counters. Pure read."""
        _check_seq(seq)
        with self._lock:
            return {
                "datasets": len(self._datasets),
                "retired": len(self._retired),
                "live": len(self._datasets) - len(self._retired),
            }

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        """The audit event ledger."""
        with self._lock:
            return tuple(self._audit)


def main() -> None:
    """Self-check: register, schema view, search, update, retire."""
    catalog = DataCatalog()
    record = catalog.dataset(
        "ds.analytics.sessions",
        "Sessions",
        1,
        columns=(("session_id", "string"), ("user_id", "string"), ("ts", "timestamp")),
        tags=("analytics", "pii"),
        owner="data-eng",
        description="Web session events",
    )
    assert record.verify()
    report = catalog.schema("ds.analytics.sessions", 2)
    assert report.columns == (("session_id", "string"), ("user_id", "string"), ("ts", "timestamp"))
    search = catalog.search("session", 3, tags=("analytics",))
    assert search.dataset_ids == ("ds.analytics.sessions",)
    update = catalog.update_schema(
        "ds.analytics.sessions", 4, (("session_id", "string"), ("user_id", "string"))
    )
    assert update.verify()
    retire = catalog.retire("ds.analytics.sessions", 5, reason="deprecated")
    assert retire.dataset_id == "ds.analytics.sessions"
    assert catalog.stats(6)["retired"] == 1
    print("data-catalog OK: dataset, schema, search, update, retire, pins")


if __name__ == "__main__":
    main()
