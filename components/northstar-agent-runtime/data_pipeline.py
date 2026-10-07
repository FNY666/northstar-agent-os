"""Data pipeline (ETL/ELT interface, thirtieth batch).

Airflow/dbt-shaped extract/transform/load bookkeeping as a deterministic
single-host ledger:

* :meth:`DataPipeline.extract` books a host-reported source batch as an
  immutable, digest-pinned :class:`ExtractRecord` (``ext-N`` ids).
* :meth:`DataPipeline.transform` applies a pinned vocabulary of pure,
  in-memory operations (``select`` / ``rename`` / ``filter`` / ``add`` /
  ``drop_null``) over an extraction and books the result as an immutable
  :class:`TransformRecord` (``trn-N`` ids) — this is ELT-shaped: transform
  runs inside the ledger, over already-extracted data.
* :meth:`DataPipeline.load` books delivery of a transformation's output
  rows to a named target as an immutable :class:`LoadRecord` (``lod-N``
  ids).

The semantics follow the standard ETL/ELT shape (Airflow extract,
dbt models, warehouse loads); the implementation is plain deterministic
bookkeeping — no network I/O, no scheduler, no real source connectors
anywhere.

House rules: no wall-clock (callers inject integer seqs), frozen
dataclasses, fail-closed validation (structural problems raise), RLock
guard for concurrent callers, stdlib-only, records sealed with
``sha256:`` digest pins over type-tagged canonical payloads (bool is not
int; floats refused; ``|int| >= 2**53`` refused — batch-5 JCS discipline).
Every mutation requires a strictly increasing seq; failed mutations
consume their seq too, so the audit trail stays totally ordered.
State transitions emit ``audit.ndjson/1`` events carrying ids, digests,
and row counts only — record values never cross the audit boundary.

Honest boundary: this module books *host-reported* source rows and
applies *host-specified* operations consistently (digests recompute,
transforms are exact over the ledger). It cannot prove a source row came
from a real database, and a load record means "the host reported rows to
target T", never "rows were written to T". Pair with ``data_lineage``
for provenance claims.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from threading import RLock
from typing import Any, Mapping

#: Version pin for this module's record shape.
DATA_PIPELINE_VERSION = "data-pipeline.v1"

#: Schema pin carried by records and audit events.
DATA_PIPELINE_SCHEMA = "northstar.data-pipeline.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Genesis marker for the first record in a hash chain.
_GENESIS = "genesis"

#: Audit event kinds.
KIND_EXTRACTED = "pipeline.extracted"
KIND_TRANSFORMED = "pipeline.transformed"
KIND_LOADED = "pipeline.loaded"
KIND_REJECTED = "pipeline.rejected"
_KINDS = (KIND_EXTRACTED, KIND_TRANSFORMED, KIND_LOADED, KIND_REJECTED)

#: Validation caps.
MAX_NAME_LEN = 128
MAX_ROWS = 10_000
MAX_FIELDS = 128
MAX_FIELD_NAME_LEN = 64
MAX_STR_VALUE_LEN = 4096
MAX_OPS = 64

#: Safe integer range for values (JCS >2^53 discipline).
_SAFE_INT = 2 ** 53

#: Pinned transform-operation vocabulary.
OP_SELECT = "select"
OP_RENAME = "rename"
OP_FILTER = "filter"
OP_ADD = "add"
OP_DROP_NULL = "drop_null"
_OPS = (OP_SELECT, OP_RENAME, OP_FILTER, OP_ADD, OP_DROP_NULL)

#: Pinned filter operators.
_FILTER_OPS = ("eq", "ne", "gt", "lt")


class DataPipelineError(ValueError):
    """A malformed request or a refused state transition."""


class SeqOrderError(DataPipelineError):
    """A mutation seq that is not strictly greater than the last one."""


class UnknownExtractError(DataPipelineError):
    """Reference to an extraction id the ledger does not hold."""


class UnknownTransformError(DataPipelineError):
    """Reference to a transformation id the ledger does not hold."""


class BadOperationError(DataPipelineError):
    """A transform operation outside the pinned vocabulary or malformed."""


class BadRecordError(DataPipelineError):
    """A source row that is not a well-formed record."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_seq(value: Any, field_name: str = "seq") -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise DataPipelineError(f"{field_name} must be a non-negative int")
    return value


def _check_name(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise DataPipelineError(f"{field_name} must be a non-empty string")
    if len(value) > MAX_NAME_LEN:
        raise DataPipelineError(f"{field_name} must be at most {MAX_NAME_LEN} chars")
    return value


def _check_field_name(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise DataPipelineError("field names must be non-empty strings")
    if len(value) > MAX_FIELD_NAME_LEN:
        raise DataPipelineError(
            f"field names must be at most {MAX_FIELD_NAME_LEN} chars"
        )
    return value


def _check_value(value: Any, field_name: str = "value") -> Any:
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int):
        if abs(value) >= _SAFE_INT:
            raise DataPipelineError(f"{field_name} must be within ±2^53")
        return value
    if isinstance(value, str):
        if len(value) > MAX_STR_VALUE_LEN:
            raise DataPipelineError(
                f"{field_name} must be at most {MAX_STR_VALUE_LEN} chars"
            )
        return value
    raise DataPipelineError(
        f"{field_name} must be str/int/bool/None "
        f"(held {type(value).__name__})"
    )


def _check_rows(value: Any) -> tuple:
    if not isinstance(value, (list, tuple)):
        raise BadRecordError("records must be a list/tuple of mappings")
    if len(value) > MAX_ROWS:
        raise BadRecordError(f"at most {MAX_ROWS} rows per extraction")
    rows = []
    for row in value:
        if not isinstance(row, Mapping):
            raise BadRecordError("each record must be a mapping")
        if len(row) > MAX_FIELDS:
            raise BadRecordError(f"at most {MAX_FIELDS} fields per record")
        items = []
        for key, val in row.items():
            _check_field_name(key)
            items.append((_check_field_name(key), _check_value(val, f"field {key!r}")))
        rows.append(tuple(sorted(items, key=lambda kv: kv[0])))
    return tuple(rows)


def _check_ops(value: Any) -> tuple:
    if not isinstance(value, (list, tuple)) or not value:
        raise BadOperationError("operations must be a non-empty list/tuple")
    if len(value) > MAX_OPS:
        raise BadOperationError(f"at most {MAX_OPS} operations per transform")
    return tuple(_check_op(op) for op in value)


def _check_op(value: Any) -> tuple:
    if not isinstance(value, Mapping):
        raise BadOperationError("each operation must be a mapping")
    name = value.get("op")
    if name not in _OPS:
        raise BadOperationError(f"unknown operation: {name!r}")
    if name == OP_SELECT:
        fields = value.get("fields")
        if not isinstance(fields, (list, tuple)) or not fields:
            raise BadOperationError("select requires a non-empty fields list")
        return ("select", tuple(_check_field_name(f) for f in fields))
    if name == OP_RENAME:
        mapping = value.get("mapping")
        if not isinstance(mapping, Mapping) or not mapping:
            raise BadOperationError("rename requires a non-empty mapping")
        pairs = tuple(
            (_check_field_name(k), _check_field_name(v))
            for k, v in mapping.items()
        )
        if len({k for k, _ in pairs}) != len(pairs):
            raise BadOperationError("rename source fields must be unique")
        if len({v for _, v in pairs}) != len(pairs):
            raise BadOperationError("rename target fields must be unique")
        return ("rename", tuple(sorted(pairs)))
    if name == OP_FILTER:
        field = _check_field_name(value.get("field"))
        fop = value.get("op_filter", value.get("operator"))
        if fop not in _FILTER_OPS:
            raise BadOperationError(f"filter operator must be one of {_FILTER_OPS}")
        cmp_value = _check_value(value.get("value"), "filter value")
        if isinstance(cmp_value, bool) and fop in ("gt", "lt"):
            raise BadOperationError("filter gt/lt do not apply to booleans")
        return ("filter", field, fop, cmp_value)
    if name == OP_ADD:
        field = _check_field_name(value.get("field"))
        const = _check_value(value.get("value"), "add value")
        return ("add", field, const)
    # OP_DROP_NULL
    field = _check_field_name(value.get("field"))
    return ("drop_null", field)


# ---------------------------------------------------------------------------
# Canonical encoding and digest pins
# ---------------------------------------------------------------------------


def _tag(value: Any) -> Any:
    # Type-tagged so bool != int and None != 0 in pins.
    if isinstance(value, bool):
        return ["bool", value]
    if value is None:
        return ["none", 0]
    if isinstance(value, int):
        return ["int", value]
    if isinstance(value, str):
        return ["str", value]
    if isinstance(value, dict):
        return ["dict", [[k, _tag(v)] for k, v in
                         sorted(value.items(), key=lambda kv: kv[0])]]
    if isinstance(value, (list, tuple)):
        return ["list", [_tag(v) for v in value]]
    raise DataPipelineError(f"cannot encode {type(value).__name__}")


def _canonical(obj: Any) -> bytes:
    return json.dumps(_tag(obj), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _pin(payload: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(_canonical(payload)).hexdigest()


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ExtractRecord:
    """One booked source batch.

    ``rows`` is a tuple of records; each record is a tuple of
    ``(field, value)`` pairs sorted by field name. ``prev_digest`` chains
    to the previous record's digest (``"genesis"`` for the first).
    """

    extract_id: str
    source_name: str
    rows: tuple
    row_count: int
    seq: int
    prev_digest: str
    record_digest: str

    def verify(self) -> bool:
        """Re-derive the digest pin from the record payload."""
        return self.record_digest == _pin(_extract_payload(self))


@dataclass(frozen=True)
class TransformRecord:
    """One booked transform run over an extraction."""

    transform_id: str
    extract_id: str
    operations: tuple
    rows: tuple
    row_count: int
    seq: int
    prev_digest: str
    record_digest: str

    def verify(self) -> bool:
        """Re-derive the digest pin from the record payload."""
        return self.record_digest == _pin(_transform_payload(self))


@dataclass(frozen=True)
class LoadRecord:
    """One booked load of a transform's rows to a named target."""

    load_id: str
    transform_id: str
    target: str
    row_count: int
    rows_digest: str
    seq: int
    prev_digest: str
    record_digest: str

    def verify(self) -> bool:
        """Re-derive the digest pin from the record payload."""
        return self.record_digest == _pin(_load_payload(self))


def _extract_payload(rec: ExtractRecord) -> dict:
    return {
        "id": rec.extract_id,
        "source_name": rec.source_name,
        "rows": [list(r) for r in rec.rows],
        "seq": rec.seq,
        "prev_digest": rec.prev_digest,
    }


def _transform_payload(rec: TransformRecord) -> dict:
    return {
        "id": rec.transform_id,
        "extract_id": rec.extract_id,
        "operations": [list(o) for o in rec.operations],
        "rows": [list(r) for r in rec.rows],
        "seq": rec.seq,
        "prev_digest": rec.prev_digest,
    }


def _load_payload(rec: LoadRecord) -> dict:
    return {
        "id": rec.load_id,
        "transform_id": rec.transform_id,
        "target": rec.target,
        "row_count": rec.row_count,
        "rows_digest": rec.rows_digest,
        "seq": rec.seq,
        "prev_digest": rec.prev_digest,
    }


# ---------------------------------------------------------------------------
# Transform execution
# ---------------------------------------------------------------------------


def _apply_op(rows: tuple, op: tuple) -> tuple:
    name = op[0]
    if name == "select":
        fields = set(op[1])
        return tuple(
            tuple((k, v) for k, v in row if k in fields) for row in rows
        )
    if name == "rename":
        mapping = dict(op[1])
        return tuple(
            tuple((mapping.get(k, k), v) for k, v in row) for row in rows
        )
    if name == "filter":
        _, field, fop, cmp_value = op
        out = []
        for row in rows:
            d = dict(row)
            if field not in d:
                continue
            val = d[field]
            if fop == "eq" and val == cmp_value:
                out.append(row)
            elif fop == "ne" and val != cmp_value:
                out.append(row)
            elif fop == "gt" and _comparable(val, cmp_value) and val > cmp_value:
                out.append(row)
            elif fop == "lt" and _comparable(val, cmp_value) and val < cmp_value:
                out.append(row)
        return tuple(out)
    if name == "add":
        _, field, const = op
        return tuple(row + ((field, const),) for row in rows)
    # drop_null
    _, field = op
    return tuple(
        row for row in rows
        if not (field in dict(row) and dict(row)[field] is None)
    )


def _comparable(a: Any, b: Any) -> bool:
    if isinstance(a, bool) or isinstance(b, bool):
        return False
    return type(a) is type(b) and isinstance(a, (int, str))


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def data_pipeline_audit_event(
    kind: str, seq: int, **detail: Any
) -> Mapping[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the data pipeline.

    Carries ids, digests, and row counts only — record values never cross
    the audit boundary.
    """
    if kind not in _KINDS:
        raise DataPipelineError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": "data_pipeline",
        "module_version": DATA_PIPELINE_VERSION,
        "seq": seq,
        "detail": dict(detail),
    }


# ---------------------------------------------------------------------------
# DataPipeline
# ---------------------------------------------------------------------------


class DataPipeline:
    """Append-only ETL/ELT ledger: extract, transform, load.

    All mutations require a strictly increasing caller-supplied ``seq``
    (logical time — no wall-clock reads anywhere). Failed mutations
    still consume their seq, keeping the audit trail totally ordered.
    RLock-guarded for concurrent callers.
    """

    def __init__(self) -> None:
        self._lock = RLock()
        self._extracts: dict[str, ExtractRecord] = {}
        self._transforms: dict[str, TransformRecord] = {}
        self._loads: dict[str, LoadRecord] = {}
        self._audit: list[Mapping[str, Any]] = []
        self._last_seq = -1
        self._next_ext = 0
        self._next_trn = 0
        self._next_lod = 0

    # -- internal ------------------------------------------------------

    def _mutation_seq(self, seq: int) -> int:
        _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must be strictly increasing (last {self._last_seq})"
            )
        self._last_seq = seq
        return seq

    def _reject(self, seq: int, reason: str) -> None:
        # Failed mutations consume their seq (batch discipline).
        self._mutation_seq(seq)
        self._audit.append(
            data_pipeline_audit_event(KIND_REJECTED, seq, reason=reason)
        )

    # -- extract --------------------------------------------------------

    def extract(self, source_name: str, seq: int, records: Any = ()) -> ExtractRecord:
        """Book a host-reported source batch."""
        with self._lock:
            try:
                _check_name(source_name, "source_name")
                rows = _check_rows(records)
                seq = self._mutation_seq(seq)
            except DataPipelineError as exc:
                # Validation that failed before seq assignment still burns
                # the caller's seq to keep the trail totally ordered.
                try:
                    self._mutation_seq(seq)
                except DataPipelineError:
                    pass
                self._audit.append(
                    data_pipeline_audit_event(KIND_REJECTED, seq, reason=str(exc))
                )
                raise
            self._next_ext += 1
            extract_id = f"ext-{self._next_ext}"
            prev = (list(self._extracts.values())[-1].record_digest
                    if self._extracts else _GENESIS)
            rec = ExtractRecord(
                extract_id=extract_id,
                source_name=source_name,
                rows=rows,
                row_count=len(rows),
                seq=seq,
                prev_digest=prev,
                record_digest="",
            )
            rec = _replace_digest(rec, _pin(_extract_payload(rec)))
            self._extracts[extract_id] = rec
            self._audit.append(
                data_pipeline_audit_event(
                    KIND_EXTRACTED, seq, extract_id=extract_id,
                    source_name=source_name, row_count=len(rows),
                    record_digest=rec.record_digest,
                )
            )
            return rec

    def get_extract(self, extract_id: str) -> ExtractRecord:
        """Fetch a booked extraction; unknown ids raise."""
        with self._lock:
            try:
                return self._extracts[extract_id]
            except KeyError:
                raise UnknownExtractError(f"unknown extract: {extract_id!r}")

    # -- transform -------------------------------------------------------

    def transform(self, extract_id: str, seq: int, operations: Any) -> TransformRecord:
        """Apply the pinned op vocabulary over an extraction's rows."""
        with self._lock:
            try:
                source = self._extracts[extract_id]
            except KeyError:
                self._reject(seq, f"unknown extract: {extract_id!r}")
                raise UnknownExtractError(f"unknown extract: {extract_id!r}")
            try:
                ops = _check_ops(operations)
                seq = self._mutation_seq(seq)
            except DataPipelineError as exc:
                try:
                    self._mutation_seq(seq)
                except DataPipelineError:
                    pass
                self._audit.append(
                    data_pipeline_audit_event(KIND_REJECTED, seq, reason=str(exc))
                )
                raise
            rows = source.rows
            for op in ops:
                rows = _apply_op(rows, op)
            self._next_trn += 1
            transform_id = f"trn-{self._next_trn}"
            prev = (list(self._transforms.values())[-1].record_digest
                    if self._transforms else _GENESIS)
            rec = TransformRecord(
                transform_id=transform_id,
                extract_id=extract_id,
                operations=ops,
                rows=rows,
                row_count=len(rows),
                seq=seq,
                prev_digest=prev,
                record_digest="",
            )
            rec = _replace_digest(rec, _pin(_transform_payload(rec)))
            self._transforms[transform_id] = rec
            self._audit.append(
                data_pipeline_audit_event(
                    KIND_TRANSFORMED, seq, transform_id=transform_id,
                    extract_id=extract_id, row_count=len(rows),
                    record_digest=rec.record_digest,
                )
            )
            return rec

    def get_transform(self, transform_id: str) -> TransformRecord:
        """Fetch a booked transformation; unknown ids raise."""
        with self._lock:
            try:
                return self._transforms[transform_id]
            except KeyError:
                raise UnknownTransformError(
                    f"unknown transform: {transform_id!r}"
                )

    # -- load ------------------------------------------------------------

    def load(self, transform_id: str, seq: int, target: str) -> LoadRecord:
        """Book delivery of a transform's rows to a named target."""
        with self._lock:
            try:
                source = self._transforms[transform_id]
            except KeyError:
                self._reject(seq, f"unknown transform: {transform_id!r}")
                raise UnknownTransformError(
                    f"unknown transform: {transform_id!r}"
                )
            try:
                _check_name(target, "target")
                seq = self._mutation_seq(seq)
            except DataPipelineError as exc:
                try:
                    self._mutation_seq(seq)
                except DataPipelineError:
                    pass
                self._audit.append(
                    data_pipeline_audit_event(KIND_REJECTED, seq, reason=str(exc))
                )
                raise
            self._next_lod += 1
            load_id = f"lod-{self._next_lod}"
            prev = (list(self._loads.values())[-1].record_digest
                    if self._loads else _GENESIS)
            rows_digest = "sha256:" + hashlib.sha256(
                _canonical([list(r) for r in source.rows])
            ).hexdigest()
            rec = LoadRecord(
                load_id=load_id,
                transform_id=transform_id,
                target=target,
                row_count=source.row_count,
                rows_digest=rows_digest,
                seq=seq,
                prev_digest=prev,
                record_digest="",
            )
            rec = _replace_digest(rec, _pin(_load_payload(rec)))
            self._loads[load_id] = rec
            self._audit.append(
                data_pipeline_audit_event(
                    KIND_LOADED, seq, load_id=load_id,
                    transform_id=transform_id, target=target,
                    row_count=source.row_count,
                    record_digest=rec.record_digest,
                )
            )
            return rec

    def get_load(self, load_id: str) -> LoadRecord:
        """Fetch a booked load; unknown ids raise."""
        with self._lock:
            try:
                return self._loads[load_id]
            except KeyError:
                raise DataPipelineError(f"unknown load: {load_id!r}")

    # -- views -----------------------------------------------------------

    def extract_ids(self) -> tuple:
        with self._lock:
            return tuple(self._extracts)

    def transform_ids(self) -> tuple:
        with self._lock:
            return tuple(self._transforms)

    def load_ids(self) -> tuple:
        with self._lock:
            return tuple(self._loads)

    def stats(self) -> Mapping[str, int]:
        with self._lock:
            return {
                "extracts": len(self._extracts),
                "transforms": len(self._transforms),
                "loads": len(self._loads),
                "audit_events": len(self._audit),
            }

    def audit_log(self) -> tuple:
        with self._lock:
            return tuple(self._audit)


def _replace_digest(rec: Any, digest: str) -> Any:
    return replace(rec, record_digest=digest)


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------


def main() -> None:
    pipe = DataPipeline()
    ext = pipe.extract("crm", 1, [
        {"id": 1, "name": "a", "age": 30},
        {"id": 2, "name": "b", "age": 17},
        {"id": 3, "name": "c", "age": None},
    ])
    assert ext.extract_id == "ext-1" and ext.row_count == 3
    assert ext.verify()
    trn = pipe.transform("ext-1", 2, [
        {"op": "filter", "field": "age", "op_filter": "gt", "value": 18},
        {"op": "drop_null", "field": "age"},
        {"op": "select", "fields": ["id", "name"]},
        {"op": "add", "field": "adult", "value": True},
        {"op": "rename", "mapping": {"name": "full_name"}},
    ])
    assert trn.row_count == 1, trn.row_count
    assert trn.verify()
    row = dict(trn.rows[0])
    assert row == {"id": 1, "full_name": "a", "adult": True}, row
    lod = pipe.load("trn-1", 3, "warehouse.users")
    assert lod.row_count == 1 and lod.verify()
    assert pipe.stats()["loads"] == 1
    kinds = [e["kind"] for e in pipe.audit_log()]
    assert kinds == [KIND_EXTRACTED, KIND_TRANSFORMED, KIND_LOADED], kinds
    print("data-pipeline OK: extract, transform, load, pins, audit")


if __name__ == "__main__":
    main()


__all__ = [
    "DATA_PIPELINE_VERSION",
    "DATA_PIPELINE_SCHEMA",
    "AUDIT_SCHEMA",
    "KIND_EXTRACTED",
    "KIND_TRANSFORMED",
    "KIND_LOADED",
    "KIND_REJECTED",
    "DataPipelineError",
    "SeqOrderError",
    "UnknownExtractError",
    "UnknownTransformError",
    "BadOperationError",
    "BadRecordError",
    "ExtractRecord",
    "TransformRecord",
    "LoadRecord",
    "DataPipeline",
    "data_pipeline_audit_event",
    "main",
]
