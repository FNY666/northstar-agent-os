"""RocksDB-shaped key-value store: put/get/scan as in-memory interface bookkeeping.

Research note: RocksDB (Facebook, 2012) is an embeddable key-value store
built on an LSM-tree. Its *interface* surface -- the part every client
programs against -- is small:

* **Exact-key operations** -- ``put`` / ``get`` / ``delete``. A ``get``
  miss is ordinary data, never an error; a ``delete`` of an absent key is
  a no-op (LSM tombstones make this convergent), reported here as
  ``existed=False`` rather than raised.
* **Range scans** -- ordered iteration (RocksDB ``Seek``/``Next``) over a
  sorted key space. Scans are bounded by an optional ``[start, end)``
  half-open range plus a ``limit``; the report is deterministic (key
  order, never insertion order).
* **Column families** -- independent namespaces sharing one database.
  The ``default`` family always exists; others are created explicitly
  and never recycled once dropped from use.

What this module does *not* do is the LSM machinery itself: there is no
memtable, no SST files, no compaction, no write batches, no write-ahead
log, no crash recovery. The backing map is a plain sorted dict. Values
are pinned by ``sha256:`` digests of the shared JCS canonical form; raw
values never cross the audit boundary.

Honest scope: this is interface bookkeeping, not a storage engine. It
cannot prove durability (a crash loses everything), replicate, or detect
a host lying about stored bytes. A booked ``PutRecord`` means "the caller
asked us to record this", never "the data is on disk".

Version pin: key-value-store.v1
Schema pin: northstar.key-value-store.v1
"""

from __future__ import annotations

import hashlib
import math
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Module version.
KEY_VALUE_STORE_VERSION = "key-value-store.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.key-value-store.v1"

#: Audit schema for emitted events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Default column family; always present.
DEFAULT_CF = "default"

#: Largest key length accepted (chars).
MAX_KEY_LEN = 4096

#: Default scan limit.
DEFAULT_SCAN_LIMIT = 1000


class KeyValueStoreError(Exception):
    """Base error for key-value store misuse."""


class BadKeyError(KeyValueStoreError):
    """Key is not a non-empty str within the length bound."""


class BadValueError(KeyValueStoreError):
    """Value is None, unsafe, or not JCS-canonicalizable."""


class BadColumnFamilyError(KeyValueStoreError):
    """Column-family name is malformed or unknown."""


class BadScanError(KeyValueStoreError):
    """Malformed scan bounds or limit."""


class SeqOrderError(KeyValueStoreError):
    """Caller seq did not strictly increase where required."""


class AuditKindError(KeyValueStoreError):
    """Unknown audit kind for the audit-event builder."""


def _check_key(key: Any) -> str:
    if isinstance(key, bool) or not isinstance(key, str):
        raise BadKeyError(f"key must be a str, got {type(key).__name__}")
    if not key:
        raise BadKeyError("key must not be empty")
    if len(key) > MAX_KEY_LEN:
        raise BadKeyError(f"key too long (>{MAX_KEY_LEN} chars)")
    return key


def _check_value(value: Any) -> Any:
    if value is None:
        raise BadValueError("value must not be None")
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        if abs(value) >= 2**53:
            raise BadValueError("int magnitude >= 2^53 is unsafe")
        return value
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise BadValueError("NaN/inf values refused at the boundary")
        return value
    try:
        jcs_canonical_json(value)
    except Exception as exc:
        raise BadValueError(f"value is not canonicalizable: {exc}") from exc
    return value


def _check_cf(cf: Any) -> str:
    if isinstance(cf, bool) or not isinstance(cf, str):
        raise BadColumnFamilyError(f"column family must be a str, got {type(cf).__name__}")
    if not cf:
        raise BadColumnFamilyError("column family must not be empty")
    if len(cf) > 256:
        raise BadColumnFamilyError("column family too long (>256 chars)")
    return cf


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"seq must be an int, got {type(seq).__name__}")
    if seq < 0:
        raise SeqOrderError(f"seq must be >= 0, got {seq}")
    return seq


def _digest_key(key: str) -> str:
    return "sha256:" + hashlib.sha256(key.encode("utf-8")).hexdigest()


def _digest_value(value: Any) -> str:
    tag = "bool:" if isinstance(value, bool) else type(value).__name__ + ":"
    return "sha256:" + hashlib.sha256(tag.encode() + jcs_canonical_json(value)).hexdigest()


@dataclass(frozen=True)
class PutRecord:
    """One completed put (frozen record)."""

    version: str
    column_family: str
    key_digest: str
    value_digest: str
    overwritten: bool
    seq: int

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "version": self.version,
            "column_family": self.column_family,
            "key_digest": self.key_digest,
            "value_digest": self.value_digest,
            "overwritten": self.overwritten,
            "seq": self.seq,
        }


@dataclass(frozen=True)
class GetOutcome:
    """One get result (frozen record). A miss is data, never raised."""

    version: str
    column_family: str
    key_digest: str
    found: bool
    value: Any
    seq: int

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "version": self.version,
            "column_family": self.column_family,
            "key_digest": self.key_digest,
            "found": self.found,
            "value": self.value,
            "seq": self.seq,
        }


@dataclass(frozen=True)
class DeleteRecord:
    """One delete (frozen record). Deleting a missing key is a no-op."""

    version: str
    column_family: str
    key_digest: str
    existed: bool
    seq: int

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "version": self.version,
            "column_family": self.column_family,
            "key_digest": self.key_digest,
            "existed": self.existed,
            "seq": self.seq,
        }


@dataclass(frozen=True)
class ScanReport:
    """One bounded range scan (frozen record), entries in key order."""

    version: str
    column_family: str
    entries: Tuple[Tuple[str, Any], ...]
    start_digest: str
    end_digest: str
    limit: int
    state_digest: str
    seq: int

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "version": self.version,
            "column_family": self.column_family,
            "entries": [(k, v) for k, v in self.entries],
            "limit": self.limit,
            "state_digest": self.state_digest,
            "seq": self.seq,
        }


@dataclass(frozen=True)
class ColumnFamilyRecord:
    """One column-family creation (frozen record)."""

    version: str
    column_family: str
    seq: int

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "version": self.version,
            "column_family": self.column_family,
            "seq": self.seq,
        }


class KeyValueStore:
    """RocksDB-shaped put/get/scan bookkeeping (single host, in-memory)."""

    def __init__(self, name: str) -> None:
        if isinstance(name, bool) or not isinstance(name, str) or not name:
            raise KeyValueStoreError("name must be a non-empty str")
        self._name = name
        self._lock = threading.RLock()
        self._last_seq = -1
        self._cfs: Dict[str, Dict[str, Any]] = {DEFAULT_CF: {}}
        self._writes = 0
        self._reads = 0
        self._hits = 0
        self._misses = 0
        self._deletes = 0
        self._scans = 0
        self._audit: List[dict] = []

    @property
    def name(self) -> str:
        return self._name

    def _use_seq(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must strictly increase, got {seq} after {self._last_seq}"
            )
        self._last_seq = seq
        return seq

    def _fail(self, seq: int, exc: Exception) -> None:
        """Book a failed mutation: the seq is consumed, rejection audited."""
        self._emit("rejected", seq, reason=type(exc).__name__)
        raise exc

    def _emit(self, kind: str, seq: int, **detail: Any) -> None:
        record = {
            "schema": AUDIT_SCHEMA,
            "kind": f"key-value-store.{kind}",
            "module": KEY_VALUE_STORE_VERSION,
            "seq": seq,
        }
        record.update(detail)
        self._audit.append(record)

    def column_family(self, cf: str, seq: int) -> ColumnFamilyRecord:
        """Create a column family (idempotent for an existing family)."""
        with self._lock:
            seq = self._use_seq(seq)
            try:
                cf = _check_cf(cf)
            except KeyValueStoreError as exc:
                self._fail(seq, exc)
            if cf not in self._cfs:
                self._cfs[cf] = {}
                self._emit("column-family-created", seq, column_family=cf)
            return ColumnFamilyRecord(
                version=KEY_VALUE_STORE_VERSION, column_family=cf, seq=seq
            )

    def _cf_or_fail(self, cf: str, seq: int) -> Dict[str, Any]:
        cf = _check_cf(cf)
        if cf not in self._cfs:
            raise BadColumnFamilyError(f"unknown column family {cf!r}")
        return self._cfs[cf]

    def put(self, cf: str, key: str, value: Any, seq: int) -> PutRecord:
        """Book a put. Overwriting an existing key is data, never raised."""
        with self._lock:
            seq = self._use_seq(seq)
            try:
                store = self._cf_or_fail(cf, seq)
                key = _check_key(key)
                value = _check_value(value)
            except KeyValueStoreError as exc:
                self._fail(seq, exc)
            overwritten = key in store
            store[key] = value
            self._writes += 1
            rec = PutRecord(
                version=KEY_VALUE_STORE_VERSION,
                column_family=cf,
                key_digest=_digest_key(key),
                value_digest=_digest_value(value),
                overwritten=overwritten,
                seq=seq,
            )
            self._emit(
                "put",
                seq,
                column_family=cf,
                key_digest=rec.key_digest,
                value_digest=rec.value_digest,
                overwritten=overwritten,
            )
            return rec

    def get(self, cf: str, key: str, seq: int) -> GetOutcome:
        """Book a get. A miss is data, never raised."""
        with self._lock:
            seq = self._use_seq(seq)
            try:
                store = self._cf_or_fail(cf, seq)
                key = _check_key(key)
            except KeyValueStoreError as exc:
                self._fail(seq, exc)
            self._reads += 1
            if key in store:
                self._hits += 1
                value = store[key]
                out = GetOutcome(
                    version=KEY_VALUE_STORE_VERSION,
                    column_family=cf,
                    key_digest=_digest_key(key),
                    found=True,
                    value=value,
                    seq=seq,
                )
                self._emit("get", seq, column_family=cf, key_digest=out.key_digest, hit=True)
                return out
            self._misses += 1
            out = GetOutcome(
                version=KEY_VALUE_STORE_VERSION,
                column_family=cf,
                key_digest=_digest_key(key),
                found=False,
                value=None,
                seq=seq,
            )
            self._emit("get", seq, column_family=cf, key_digest=out.key_digest, hit=False)
            return out

    def delete(self, cf: str, key: str, seq: int) -> DeleteRecord:
        """Book a delete (tombstone). A missing key is a valid no-op."""
        with self._lock:
            seq = self._use_seq(seq)
            try:
                store = self._cf_or_fail(cf, seq)
                key = _check_key(key)
            except KeyValueStoreError as exc:
                self._fail(seq, exc)
            existed = key in store
            if existed:
                del store[key]
            self._deletes += 1
            rec = DeleteRecord(
                version=KEY_VALUE_STORE_VERSION,
                column_family=cf,
                key_digest=_digest_key(key),
                existed=existed,
                seq=seq,
            )
            self._emit(
                "deleted",
                seq,
                column_family=cf,
                key_digest=rec.key_digest,
                existed=existed,
            )
            return rec

    def scan(
        self,
        cf: str,
        seq: int,
        start: Optional[str] = None,
        end: Optional[str] = None,
        limit: int = DEFAULT_SCAN_LIMIT,
    ) -> ScanReport:
        """Book a bounded range scan over ``[start, end)`` in key order."""
        with self._lock:
            seq = self._use_seq(seq)
            try:
                store = self._cf_or_fail(cf, seq)
                if start is not None:
                    start = _check_key(start)
                if end is not None:
                    end = _check_key(end)
                if start is not None and end is not None and start >= end:
                    raise BadScanError("scan start must be < end")
                if isinstance(limit, bool) or not isinstance(limit, int):
                    raise BadScanError(f"limit must be an int, got {type(limit).__name__}")
                if limit <= 0 or limit > 100_000:
                    raise BadScanError("limit must be in 1..100000")
            except KeyValueStoreError as exc:
                self._fail(seq, exc)
            picked: List[Tuple[str, Any]] = []
            for key in sorted(store.keys()):
                if start is not None and key < start:
                    continue
                if end is not None and key >= end:
                    break
                picked.append((key, store[key]))
                if len(picked) >= limit:
                    break
            self._scans += 1
            pins = [(k, _digest_value(v)) for k, v in picked]
            state = "sha256:" + hashlib.sha256(
                jcs_canonical_json(pins)
            ).hexdigest()
            rec = ScanReport(
                version=KEY_VALUE_STORE_VERSION,
                column_family=cf,
                entries=tuple(picked),
                start_digest=_digest_key(start) if start is not None else "",
                end_digest=_digest_key(end) if end is not None else "",
                limit=limit,
                state_digest=state,
                seq=seq,
            )
            self._emit("scanned", seq, column_family=cf, count=len(picked))
            return rec

    def stats(self) -> Dict[str, Any]:
        """Pure read view over counters (no seq consumed, no audit row)."""
        with self._lock:
            return {
                "schema": SCHEMA_PIN,
                "version": KEY_VALUE_STORE_VERSION,
                "column_families": sorted(self._cfs.keys()),
                "writes": self._writes,
                "reads": self._reads,
                "hits": self._hits,
                "misses": self._misses,
                "deletes": self._deletes,
                "scans": self._scans,
            }

    def audit_log(self) -> Tuple[dict, ...]:
        """Booked audit rows (tuple copy)."""
        with self._lock:
            return tuple(self._audit)


def key_value_store_audit_event(kind: str, seq: int, **fields: Any) -> dict:
    """Shape an ``audit.ndjson/1`` record for a key-value-store event."""
    allowed = {"column-family-created", "put", "get", "deleted", "scanned", "rejected"}
    if kind not in allowed:
        raise AuditKindError(f"unknown audit kind {kind!r}; allowed: {sorted(allowed)}")
    _check_seq(seq)
    record = {
        "schema": AUDIT_SCHEMA,
        "kind": f"key-value-store.{kind}",
        "module": KEY_VALUE_STORE_VERSION,
        "seq": seq,
    }
    for k, v in fields.items():
        if k in {"value", "values", "raw", "payload"}:
            raise AuditKindError("raw values are never logged; pass digests")
        record[k] = v
    return record


def main() -> None:
    kv = KeyValueStore("kv")
    assert kv.stats()["column_families"] == ["default"]

    r1 = kv.put("default", "a", 1, seq=1)
    assert not r1.overwritten
    assert kv.get("default", "a", seq=2).value == 1
    r2 = kv.put("default", "a", 2, seq=3)
    assert r2.overwritten and kv.get("default", "a", seq=4).value == 2

    assert not kv.get("default", "ghost", seq=5).found

    kv.put("default", "b", "x", seq=6)
    kv.put("default", "c", "y", seq=7)
    rep = kv.scan("default", seq=8, start="a", end="c")
    assert [k for k, _ in rep.entries] == ["a", "b"]
    assert len(kv.scan("default", seq=9).entries) == 3

    d1 = kv.delete("default", "a", seq=10)
    assert d1.existed and not kv.get("default", "a", seq=11).found
    assert not kv.delete("default", "a", seq=12).existed

    kv.column_family("meta", seq=13)
    kv.put("meta", "a", "isolated", seq=14)
    assert kv.get("meta", "a", seq=15).value == "isolated"
    assert kv.stats()["column_families"] == ["default", "meta"]

    # Fail-closed: bad key burns the seq and books a rejection.
    try:
        kv.put("default", "", "bad", seq=16)
    except BadKeyError:
        pass
    else:  # pragma: no cover
        raise AssertionError("empty key accepted")
    assert any(r["kind"] == "key-value-store.rejected" for r in kv.audit_log())

    # Seq must strictly increase.
    try:
        kv.put("default", "z", 1, seq=16)
    except SeqOrderError:
        pass
    else:  # pragma: no cover
        raise AssertionError("rewound seq accepted")

    assert key_value_store_audit_event("put", 1, key_digest="sha256:x")["seq"] == 1
    print("key-value-store OK: put, get, delete, scan, column-families, pins, audit")


if __name__ == "__main__":
    main()
