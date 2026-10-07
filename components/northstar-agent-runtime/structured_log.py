"""Structured JSON logging: level-gated, field-carrying log records.

Research note: structured logging (logfmt/JSON lines, as popularized by
Heroku's Twelve-Factor App and cemented by `zap`/`slog`) records each event
as a machine-parseable *record* (level, message, key/value fields) instead
of free text. A parser can then route, count, and alert on fields the code
set explicitly, rather than grepping prose. For a governed agent runtime,
every logged event is also audit-adjacent: it must be replayable from the
audit trail with an identical digest.

* **Level gating** — ``DEBUG < INFO < WARN < ERROR``. Entries below the
  logger's ``min_level`` are dropped and counted (``dropped_count``), never
  buffered, never emitted. Dropping is a configuration decision, not a
  silent failure.
* **Contextual fields** — ``with_fields(**kwargs)`` returns a derived
  logger whose bound fields are merged into every record it emits;
  per-call fields override bound ones on key conflict. The parent logger
  is never mutated.
* **Digest-pinned records** — every frozen ``LogRecord`` carries a
  ``sha256:`` digest over its canonical body (level, message, canonical
  fields, seq), so a log replay can be verified byte-for-byte.
* **No wall-clock** — records carry the caller-supplied logical ``seq``
  only; the host owns time (it can add its own timestamp in its emitter).
  This keeps the module deterministic and audit-replay exact.
* **Injectable emitter** — ``emitter(record)`` defaults to an in-memory
  ring buffer; production wires a real sink (file, socket, collector).
  ``drain()`` returns the buffered records and clears the buffer.
* **Fail-closed fields** — field keys must be non-empty strings and field
  values must be canonicalizable (None/bool/int/float/str, lists, and
  mappings of those). NaN/inf, non-canonicalizable objects, and integral
  floats with magnitude > 2**53 are refused (the same JCS float-loss caveat
  as the rest of the batch line: ``canonical_json`` silently pins colliding
  digests for ints that lose precision as IEEE-754 doubles).

Honest scope: this books log *records*, not log *delivery* — an emitted
record means "the host was handed this record", never "it was durably
written". Min-level drops are deliberate; field values are host-reported.
"""

from __future__ import annotations

import hashlib
import math
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")


#: Module version.
STRUCTURED_LOG_VERSION = "structured-log.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.structured-log.v1"

#: Integers beyond this magnitude are refused: the JCS float-loss caveat
#: found in batch 5 (``canonical_json`` silently pins colliding digests for
#: ints that lose precision when decoded as IEEE-754 doubles).
_MAX_SAFE_INT = 2 ** 53

#: Level ordering (lower = more verbose).
DEBUG = "debug"
INFO = "info"
WARN = "warn"
ERROR = "error"
_LEVEL_RANK = {DEBUG: 10, INFO: 20, WARN: 30, ERROR: 40}

#: Fixed audit vocabulary.
_AUDIT_KINDS = (
    "logger-created",
    "emitted",
    "dropped-below-min",
    "drained",
    "rejected",
)


class StructuredLogError(Exception):
    """Base error for the structured logger."""


class LevelError(StructuredLogError):
    """Raised for unknown log levels."""


class FieldsError(StructuredLogError):
    """Raised for non-canonicalizable log fields."""


def _check_seq(value: Any, name: str = "seq") -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise StructuredLogError(f"{name} must be an int, got {type(value).__name__}")
    if value < 0:
        raise StructuredLogError(f"{name} must be non-negative")
    return value


def _check_level(level: Any) -> str:
    if not isinstance(level, str) or level not in _LEVEL_RANK:
        raise LevelError(f"unknown log level {level!r}")
    return level


def _check_message(message: Any) -> str:
    if not isinstance(message, str) or not message:
        raise StructuredLogError(
            f"message must be a non-empty str, got {message!r}"
        )
    return message


def _canonicalize_value(value: Any) -> Any:
    """Fail-closed recursive canonicalizer for field values."""
    if value is None or isinstance(value, str):
        return value
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        if abs(value) >= _MAX_SAFE_INT:
            raise FieldsError(f"int field value out of safe range: {value!r}")
        return value
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise FieldsError(f"non-finite float field value: {value!r}")
        if value.is_integer() and abs(value) >= _MAX_SAFE_INT:
            raise FieldsError(f"integral float field value out of safe range: {value!r}")
        return value
    if isinstance(value, (list, tuple)):
        return [_canonicalize_value(v) for v in value]
    if isinstance(value, Mapping):
        mapping = _check_fields_mapping(value)
        return {k: _canonicalize_value(v) for k, v in mapping.items()}
    raise FieldsError(f"non-canonicalizable field value of type {type(value).__name__}")


def _check_fields_mapping(fields: Any) -> Mapping[str, Any]:
    if not isinstance(fields, Mapping):
        raise FieldsError(f"fields must be a mapping, got {type(fields).__name__}")
    for key in fields:
        if not isinstance(key, str) or not key:
            raise FieldsError(f"field key must be a non-empty str, got {key!r}")
    return fields


def _check_fields(fields: Any) -> tuple[tuple[str, Any], ...]:
    """Validate and normalize fields to sorted (key, canonical-value) pairs."""
    if fields is None:
        return ()
    mapping = _check_fields_mapping(fields)
    return tuple(sorted((k, _canonicalize_value(v)) for k, v in mapping.items()))


def _pin(body: Any) -> str:
    return "sha256:" + hashlib.sha256(jcs_canonical_json(body)).hexdigest()


@dataclass(frozen=True)
class LogRecord:
    """Frozen record of one emitted log entry."""

    seq: int
    level: str
    message: str
    fields: tuple  # sorted (key, canonical-value) pairs
    record_digest: str

    def fields_dict(self) -> dict[str, Any]:
        """Field pairs as a plain dict (fresh copy)."""
        return {k: v for k, v in self.fields}

    def verify(self) -> bool:
        """Re-derive the record digest; False on any tampering."""
        body = [self.level, self.message, [[k, v] for k, v in self.fields], self.seq]
        return _pin(body) == self.record_digest

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "version": STRUCTURED_LOG_VERSION,
            "seq": self.seq,
            "level": self.level,
            "message": self.message,
            "fields": {k: v for k, v in self.fields},
            "record_digest": self.record_digest,
        }


@dataclass(frozen=True)
class DrainReport:
    """Frozen report of one drain operation."""

    seq: int
    drained: int
    first_seq: int | None
    last_seq: int | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "version": STRUCTURED_LOG_VERSION,
            "seq": self.seq,
            "drained": self.drained,
            "first_seq": self.first_seq,
            "last_seq": self.last_seq,
        }


class StructuredLog:
    """Level-gated structured logger with bound context fields."""

    def __init__(
        self,
        min_level: str = INFO,
        max_buffer: int | None = None,
        emitter: Callable[[LogRecord], None] | None = None,
        bound_fields: tuple[tuple[str, Any], ...] = (),
    ) -> None:
        self._min_level = _check_level(min_level)
        if max_buffer is not None:
            if isinstance(max_buffer, bool) or not isinstance(max_buffer, int) \
                    or max_buffer <= 0:
                raise StructuredLogError(
                    f"max_buffer must be a positive int, got {max_buffer!r}"
                )
        if emitter is not None and not callable(emitter):
            raise StructuredLogError("emitter must be callable")
        self._max_buffer = max_buffer
        self._emitter = emitter
        self._bound_fields = tuple(bound_fields)  # validated by caller path
        self._buffer: list[LogRecord] = []
        self._lock = threading.RLock()
        self._emitted = 0
        self._dropped = 0

    # -- views ------------------------------------------------------------
    @property
    def min_level(self) -> str:
        return self._min_level

    @property
    def bound_fields(self) -> dict[str, Any]:
        return {k: v for k, v in self._bound_fields}

    def emitted_count(self) -> int:
        with self._lock:
            return self._emitted

    def dropped_count(self) -> int:
        with self._lock:
            return self._dropped

    def records(self) -> tuple[LogRecord, ...]:
        """Snapshot of the in-memory buffer."""
        with self._lock:
            return tuple(self._buffer)

    # -- derived loggers --------------------------------------------------
    def with_fields(self, fields: Mapping[str, Any] | None = None, **kwargs: Any) -> "StructuredLog":
        """Derived logger with extra bound fields; the parent is untouched.

        Per-call fields (including ``fields`` mapping) are validated now,
        fail-closed; later calls merge these under per-call fields.
        """
        merged: dict[str, Any] = dict(self._bound_fields)
        if fields is not None:
            merged.update(_check_fields_mapping(fields))
        merged.update(kwargs)
        new_bound = _check_fields(merged)
        derived = StructuredLog(
            min_level=self._min_level,
            max_buffer=self._max_buffer,
            emitter=self._emitter,
            bound_fields=new_bound,
        )
        return derived

    def with_min_level(self, min_level: str) -> "StructuredLog":
        """Derived logger with a different level gate, same bound fields."""
        return StructuredLog(
            min_level=min_level,
            max_buffer=self._max_buffer,
            emitter=self._emitter,
            bound_fields=self._bound_fields,
        )

    # -- logging ----------------------------------------------------------
    def _emit(self, level: str, message: str, seq: int,
              fields: Mapping[str, Any] | None) -> LogRecord:
        _check_level(level)
        _check_message(message)
        _check_seq(seq)
        merged: dict[str, Any] = dict(self._bound_fields)
        merged.update(dict(_check_fields(fields)))
        pairs = _check_fields(merged)
        body = [level, message, [[k, v] for k, v in pairs], seq]
        record = LogRecord(
            seq=seq,
            level=level,
            message=message,
            fields=pairs,
            record_digest=_pin(body),
        )
        with self._lock:
            if _LEVEL_RANK[level] < _LEVEL_RANK[self._min_level]:
                self._dropped += 1
                return record
            if self._emitter is not None:
                self._emitter(record)
            else:
                self._buffer.append(record)
                if self._max_buffer is not None:
                    while len(self._buffer) > self._max_buffer:
                        self._buffer.pop(0)
            self._emitted += 1
        return record

    def debug(self, message: str, seq: int, fields: Mapping[str, Any] | None = None) -> LogRecord:
        return self._emit(DEBUG, message, seq, fields)

    def info(self, message: str, seq: int, fields: Mapping[str, Any] | None = None) -> LogRecord:
        return self._emit(INFO, message, seq, fields)

    def warn(self, message: str, seq: int, fields: Mapping[str, Any] | None = None) -> LogRecord:
        return self._emit(WARN, message, seq, fields)

    def error(self, message: str, seq: int, fields: Mapping[str, Any] | None = None) -> LogRecord:
        return self._emit(ERROR, message, seq, fields)

    # -- drain ------------------------------------------------------------
    def drain(self, seq: int) -> DrainReport:
        """Return buffered records and clear the buffer."""
        _check_seq(seq)
        with self._lock:
            drained = len(self._buffer)
            first = self._buffer[0].seq if drained else None
            last = self._buffer[-1].seq if drained else None
            self._buffer.clear()
        return DrainReport(seq=seq, drained=drained, first_seq=first, last_seq=last)


def structured_log_audit_event(kind: str, seq: int, level: str = "",
                               record_digest: str = "") -> dict[str, Any]:
    """Shape a logger event as an ``audit.ndjson/1``-style record."""
    if kind not in _AUDIT_KINDS:
        raise StructuredLogError(f"unknown audit kind {kind!r}")
    _check_seq(seq)
    event = {
        "schema": "audit.ndjson/1",
        "event": kind,
        "audit_seq": seq,
        "module_version": STRUCTURED_LOG_VERSION,
        "module_schema": SCHEMA_PIN,
    }
    if level:
        event["level"] = level
    if record_digest:
        event["record_digest"] = record_digest
    return event


def main() -> None:
    """Self-check: gating, fields, with_fields, drain."""
    log = StructuredLog(min_level=INFO)
    rec = log.info("started", 0, {"run": 1})
    assert rec.level == "info" and rec.verify()
    assert rec.fields_dict() == {"run": 1}
    assert log.records() == (rec,)
    assert log.emitted_count() == 1 and log.dropped_count() == 0

    dropped = log.debug("verbose", 1)
    assert log.dropped_count() == 1 and log.records() == (rec,)

    child = log.with_fields(service="edge", shard=3)
    assert log.bound_fields == {}
    r2 = child.warn("slow", 2, {"shard": 4, "latency_ms": 250})
    assert r2.fields_dict() == {"service": "edge", "shard": 4, "latency_ms": 250}
    assert r2.verify()

    report = log.drain(3)
    assert report.drained == 1 and report.first_seq == 0 and report.last_seq == 0
    assert log.records() == ()
    assert report.as_dict()["drained"] == 1
    print("structured-log OK: gating, fields, with_fields, drain")


if __name__ == "__main__":
    main()
