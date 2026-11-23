"""Log aggregation — simulated centralized log collection/query (ELK/Loki shaped).

Research note (log-management literature): Elasticsearch/Logstash/Kibana
and Grafana Loki centralize *host-reported* log lines behind three
operations — **ingest** (sources ship timestamped lines with labels),
**query** (filter by label matchers, severity thresholds, and time
cursors over the booked lines), and **retention** (a policy that prunes
lines older than a pinned age). This module takes the intersection for
a single-host deterministic ledger:

* **Sources**: ``register_source`` books one named log source
  (an app, a host, a sidecar). Duplicate ids refused.
* **Collect**: ``collect`` books a batch of host-reported entries against
  a source. Each entry pins a severity from a pinned vocabulary and an
  optional label mapping (Loki-shaped ``{app, env, instance}`` style);
  every entry becomes a frozen, digest-pinned ``LogRecord``.
* **Query**: ``query`` is a pure read view over the booked records with
  label matchers, a minimum-severity threshold, a ``since_seq`` cursor,
  and a limit. Verdicts are data, never exceptions for "no hits".
* **Retention**: ``retention`` books a policy (max age in logical seqs)
  and prunes the source's records older than ``seq - max_age``,
  returning a frozen ``PruneReport`` pinning the pruned ids.

House rules: frozen dataclasses, caller-supplied strictly-increasing
int seqs on mutations (failed mutations consume their seq; bool/negative
/rewind refused), RLock-guarded, fail-closed taxonomy, stdlib-only
(``canonical_json`` sibling helper behind the standard try/except
fallback), ``sha256:`` digest pins over type-tagged canonical payloads,
``audit.ndjson/1`` events with message bodies and label values banned
from the audit boundary (ids + digest pins only).

Honest boundary: this module books *host-reported* lines
deterministically. It cannot observe the wire, cannot prove a line was
emitted by the claimed source, performs no real full-text indexing, and
measures no storage. An indexed record means "the host declared this
line", never "the line happened". Production still needs a real
collector, an index (Lucene/TSDB), and object storage behind retention.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import threading
from dataclasses import dataclass
from typing import Any, Mapping

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    _cj = None  # type: ignore

#: Version pin for this module's record shape.
LOG_AGGREGATION_VERSION = "log-aggregation.v1"

#: Schema pin carried by records and audit events.
LOG_AGGREGATION_SCHEMA = "northstar.log-aggregation.v1"

#: Canonical audit envelope schema.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Pinned severity vocabulary (Loki/ELK intersection).
LEVELS: tuple[str, ...] = (
    "debug", "info", "notice", "warning", "error", "critical",
)

#: Severity rank used by min-level query thresholds.
LEVEL_RANK: dict[str, int] = {name: rank for rank, name in enumerate(LEVELS)}

#: Hard caps keep the single-host ledger bounded.
MAX_MESSAGE_LEN = 65_536
MAX_LABELS_PER_ENTRY = 32
MAX_LABEL_KEY_LEN = 128
MAX_LABEL_VALUE_LEN = 512
MAX_QUERY_LIMIT = 10_000


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class LogAggregationError(Exception):
    """Base error for the log-aggregation module."""


class BadSourceError(LogAggregationError):
    """Source id or definition is malformed."""


class DuplicateSourceError(LogAggregationError):
    """Source id already registered."""


class UnknownSourceError(LogAggregationError):
    """No such source registered."""


class BadEntryError(LogAggregationError):
    """A collected entry is malformed."""


class BadQueryError(LogAggregationError):
    """A query argument is malformed."""


class BadRetentionError(LogAggregationError):
    """A retention policy argument is malformed."""


class SeqOrderError(LogAggregationError):
    """Caller seq did not strictly increase."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_seq(value: Any, field_name: str = "seq") -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SeqOrderError(f"{field_name} must be a non-negative int")
    return value


def _check_nonempty_str(value: Any, field_name: str, max_len: int) -> str:
    if not isinstance(value, str) or not value:
        raise LogAggregationError(f"{field_name} must be a non-empty string")
    if len(value) > max_len:
        raise LogAggregationError(
            f"{field_name} longer than {max_len} chars"
        )
    return value


def _canonical(obj: Any) -> bytes:
    if _cj is not None:
        return _cj.jcs_canonical_json(obj)  # type: ignore[attr-defined]
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _pin(payload: Any, seed: str = "") -> str:
    digest = hmac.new(
        seed.encode("utf-8"), _canonical(payload), hashlib.sha256
    ).hexdigest()
    return f"sha256:{digest}"


def _check_labels(value: Any) -> tuple[tuple[str, str], ...]:
    if value is None:
        return ()
    if not isinstance(value, Mapping):
        raise BadEntryError("labels must be a mapping or omitted")
    if len(value) > MAX_LABELS_PER_ENTRY:
        raise BadEntryError(
            f"more than {MAX_LABELS_PER_ENTRY} labels on one entry"
        )
    pairs: list[tuple[str, str]] = []
    for key, val in value.items():
        if not isinstance(key, str) or not key:
            raise BadEntryError("label keys must be non-empty strings")
        if not isinstance(val, str):
            raise BadEntryError("label values must be strings")
        if len(key) > MAX_LABEL_KEY_LEN:
            raise BadEntryError("label key too long")
        if len(val) > MAX_LABEL_VALUE_LEN:
            raise BadEntryError("label value too long")
        pairs.append((key, val))
    pairs.sort()
    return tuple(pairs)


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SourceRecord:
    """One registered log source."""

    source_id: str
    seq: int
    digest: str
    schema: str = LOG_AGGREGATION_SCHEMA

    def verify(self, seed: str = "") -> bool:
        return self.digest == _pin(
            ["source", self.source_id, self.seq], seed
        )


@dataclass(frozen=True)
class LogRecord:
    """One booked log line (host-reported, digest-pinned)."""

    record_id: str
    source_id: str
    level: str
    message: str
    labels: tuple[tuple[str, str], ...]
    seq: int
    digest: str
    schema: str = LOG_AGGREGATION_SCHEMA

    def verify(self, seed: str = "") -> bool:
        return self.digest == _pin(
            [
                "log",
                self.record_id,
                self.source_id,
                self.level,
                self.message,
                list(self.labels),
                self.seq,
            ],
            seed,
        )


@dataclass(frozen=True)
class IngestBatch:
    """One ``collect`` call: frozen batch + the records it booked."""

    batch_id: str
    source_id: str
    record_ids: tuple[str, ...]
    seq: int
    digest: str
    schema: str = LOG_AGGREGATION_SCHEMA


@dataclass(frozen=True)
class QueryResult:
    """One ``query`` read view (data, never raised for zero hits)."""

    hits: tuple[LogRecord, ...]
    cursor: int
    seq: int
    schema: str = LOG_AGGREGATION_SCHEMA


@dataclass(frozen=True)
class RetentionPolicy:
    """One booked retention policy (max age in logical seqs)."""

    source_id: str
    max_age: int
    seq: int
    digest: str
    schema: str = LOG_AGGREGATION_SCHEMA

    def verify(self, seed: str = "") -> bool:
        return self.digest == _pin(
            ["retention", self.source_id, self.max_age, self.seq], seed
        )


@dataclass(frozen=True)
class PruneReport:
    """One retention application: pruned record ids as data."""

    source_id: str
    pruned_ids: tuple[str, ...]
    remaining: int
    seq: int
    digest: str
    schema: str = LOG_AGGREGATION_SCHEMA


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------

KIND_SOURCE_REGISTERED = "log-aggregation.source-registered"
KIND_COLLECTED = "log-aggregation.collected"
KIND_QUERIED = "log-aggregation.queried"
KIND_RETENTION_APPLIED = "log-aggregation.retention-applied"
KIND_REJECTED = "log-aggregation.rejected"

_KINDS = (
    KIND_SOURCE_REGISTERED,
    KIND_COLLECTED,
    KIND_QUERIED,
    KIND_RETENTION_APPLIED,
    KIND_REJECTED,
)


def log_aggregation_audit_event(
    kind: str, seq: int, **detail: Any
) -> dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for this module.

    Message bodies and label values never cross the audit boundary —
    only ids, counts, and digest pins do.
    """
    if kind not in _KINDS:
        raise LogAggregationError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    banned = {"message", "labels", "messages"}
    if any(k in detail for k in banned):
        raise LogAggregationError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": LOG_AGGREGATION_VERSION,
        "detail": dict(detail),
        "seq": seq,
    }


# ---------------------------------------------------------------------------
# The ledger
# ---------------------------------------------------------------------------


class LogAggregation:
    """Deterministic log-collection/query/retention ledger.

    All mutations take a caller-supplied ``seq`` (monotonic logical
    time); no wall-clock is read anywhere. Failed mutations consume
    their seq (fail-closed ledger position). Queries are pure read
    views: the seq is validated, not consumed.
    """

    def __init__(self, seed: str = "") -> None:
        self._lock = threading.RLock()
        self._seed = seed
        self._last_seq = -1
        self._sources: dict[str, SourceRecord] = {}
        self._records: dict[str, LogRecord] = {}
        self._by_source: dict[str, list[str]] = {}
        self._policies: dict[str, RetentionPolicy] = {}
        self._next_record_no = 1
        self._next_batch_no = 1
        self._audit_log: list[dict[str, Any]] = []

    # -- internal ---------------------------------------------------------

    def _next_seq(self, seq: int) -> int:
        seq = _check_seq(seq)
        with self._lock:
            if seq <= self._last_seq:
                raise SeqOrderError(
                    f"seq must strictly increase "
                    f"(last={self._last_seq}, got={seq})"
                )
            self._last_seq = seq
        return seq

    def _emit(self, kind: str, seq: int, **detail: Any) -> None:
        self._audit_log.append(
            log_aggregation_audit_event(kind, seq, **detail)
        )

    def _reject(self, seq: int, reason: str) -> None:
        # Seq already consumed by _next_seq; only book the refusal.
        self._emit(KIND_REJECTED, seq, reason=reason)

    def _mint_record(
        self, source_id: str, level: str, message: str,
        labels: tuple[tuple[str, str], ...], seq: int,
    ) -> LogRecord:
        record_id = f"rec-{self._next_record_no}"
        self._next_record_no += 1
        digest = _pin(
            [
                "log", record_id, source_id, level, message,
                list(labels), seq,
            ],
            self._seed,
        )
        return LogRecord(
            record_id=record_id,
            source_id=source_id,
            level=level,
            message=message,
            labels=labels,
            seq=seq,
            digest=digest,
        )

    # -- sources ----------------------------------------------------------

    def register_source(self, source_id: str, seq: int) -> SourceRecord:
        """Book one log source."""
        seq = self._next_seq(seq)
        try:
            source_id = _check_nonempty_str(
                source_id, "source_id", 256
            ).strip()
            if not source_id:
                raise BadSourceError("source_id must not be blank")
        except LogAggregationError as exc:
            self._reject(seq, str(exc))
            raise
        with self._lock:
            if source_id in self._sources:
                self._reject(seq, f"duplicate source_id: {source_id!r}")
                raise DuplicateSourceError(
                    f"duplicate source_id: {source_id!r}"
                )
            rec = SourceRecord(
                source_id=source_id,
                seq=seq,
                digest=_pin(["source", source_id, seq], self._seed),
            )
            self._sources[source_id] = rec
            self._by_source[source_id] = []
            self._emit(
                KIND_SOURCE_REGISTERED,
                seq,
                source_id=source_id,
                digest=rec.digest,
            )
            return rec

    # -- collect ----------------------------------------------------------

    def collect(
        self, source_id: str, entries: Any, seq: int
    ) -> IngestBatch:
        """Book a batch of host-reported log entries.

        ``entries`` is a list of mappings, each with ``message`` (str),
        ``level`` (pinned vocabulary), and optional ``labels`` mapping.
        Any malformed entry refuses the whole batch fail-closed.
        """
        seq = self._next_seq(seq)
        with self._lock:
            if source_id not in self._sources:
                self._reject(seq, f"unknown source_id: {source_id!r}")
                raise UnknownSourceError(
                    f"unknown source_id: {source_id!r}"
                )
            if not isinstance(entries, list) or not entries:
                self._reject(seq, "entries must be a non-empty list")
                raise BadEntryError("entries must be a non-empty list")
            parsed: list[tuple[str, str, tuple[tuple[str, str], ...]]] = []
            try:
                for entry in entries:
                    if not isinstance(entry, Mapping):
                        raise BadEntryError("entry must be a mapping")
                    message = entry.get("message")
                    if not isinstance(message, str) or not message:
                        raise BadEntryError(
                            "entry message must be a non-empty string"
                        )
                    if len(message) > MAX_MESSAGE_LEN:
                        raise BadEntryError("entry message too long")
                    level = entry.get("level")
                    if level not in LEVELS:
                        raise BadEntryError(
                            f"entry level must be one of {LEVELS!r}"
                        )
                    labels = _check_labels(entry.get("labels"))
                    parsed.append((message, level, labels))
            except LogAggregationError as exc:
                self._reject(seq, str(exc))
                raise
            batch_id = f"ing-{self._next_batch_no}"
            self._next_batch_no += 1
            record_ids: list[str] = []
            for message, level, labels in parsed:
                rec = self._mint_record(
                    source_id, level, message, labels, seq
                )
                self._records[rec.record_id] = rec
                self._by_source[source_id].append(rec.record_id)
                record_ids.append(rec.record_id)
            batch = IngestBatch(
                batch_id=batch_id,
                source_id=source_id,
                record_ids=tuple(record_ids),
                seq=seq,
                digest=_pin(
                    ["ingest", batch_id, source_id, record_ids, seq],
                    self._seed,
                ),
            )
            self._emit(
                KIND_COLLECTED,
                seq,
                batch_id=batch_id,
                source_id=source_id,
                count=len(record_ids),
                digest=batch.digest,
            )
            return batch

    # -- query ------------------------------------------------------------

    def query(
        self,
        seq: int,
        source_id: str | None = None,
        min_level: str | None = None,
        labels: Mapping[str, str] | None = None,
        since_seq: int = 0,
        limit: int = 100,
    ) -> QueryResult:
        """Pure read view over the booked records.

        ``min_level`` keeps records at or above that severity;
        ``labels`` are exact label matchers (all must match);
        ``since_seq`` keeps records with seq > since_seq. Verdicts are
        data — zero hits is a hit-free result, never an exception.
        The seq is validated, not consumed; an audited read row is
        appended.
        """
        _check_seq(seq)
        since_seq = _check_seq(since_seq, "since_seq")
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise BadQueryError("limit must be an int")
        if limit < 1 or limit > MAX_QUERY_LIMIT:
            raise BadQueryError(
                f"limit must be in [1, {MAX_QUERY_LIMIT}]"
            )
        if min_level is not None and min_level not in LEVELS:
            raise BadQueryError(f"min_level must be one of {LEVELS!r}")
        matchers = _check_labels(labels)
        with self._lock:
            if source_id is not None and source_id not in self._sources:
                raise UnknownSourceError(
                    f"unknown source_id: {source_id!r}"
                )
            ids: list[str]
            if source_id is None:
                ids = [rid for sids in self._by_source.values()
                       for rid in sids]
            else:
                ids = list(self._by_source[source_id])
            matcher_map = dict(matchers)
            floor = LEVEL_RANK[min_level] if min_level else 0
            hits: list[LogRecord] = []
            for rid in ids:
                rec = self._records.get(rid)
                if rec is None:  # pruned under retention; skip
                    continue
                if rec.seq <= since_seq:
                    continue
                if LEVEL_RANK[rec.level] < floor:
                    continue
                rec_labels = dict(rec.labels)
                if any(rec_labels.get(k) != v
                       for k, v in matcher_map.items()):
                    continue
                hits.append(rec)
                if len(hits) >= limit:
                    break
            cursor = max((h.seq for h in hits), default=since_seq)
            result = QueryResult(
                hits=tuple(hits), cursor=cursor, seq=seq
            )
            self._emit(
                KIND_QUERIED,
                seq,
                source_id=source_id if source_id else "*",
                hit_count=len(hits),
                cursor=cursor,
            )
            return result

    # -- retention --------------------------------------------------------

    def retention(
        self, source_id: str, max_age: int, seq: int
    ) -> PruneReport:
        """Book a retention policy and prune older records now.

        Records of ``source_id`` with ``record.seq <= seq - max_age``
        are pruned (dropped from the queryable ledger; ids stay pinned
        in this report). Policies replace older ones latest-wins.
        """
        seq = self._next_seq(seq)
        if (isinstance(max_age, bool) or not isinstance(max_age, int)
                or max_age < 0):
            self._reject(seq, "max_age must be a non-negative int")
            raise BadRetentionError("max_age must be a non-negative int")
        with self._lock:
            if source_id not in self._sources:
                self._reject(seq, f"unknown source_id: {source_id!r}")
                raise UnknownSourceError(
                    f"unknown source_id: {source_id!r}"
                )
            policy = RetentionPolicy(
                source_id=source_id,
                max_age=max_age,
                seq=seq,
                digest=_pin(
                    ["retention", source_id, max_age, seq], self._seed
                ),
            )
            self._policies[source_id] = policy
            cutoff = seq - max_age
            pruned: list[str] = []
            kept: list[str] = []
            for rid in self._by_source[source_id]:
                rec = self._records.get(rid)
                if rec is None:
                    continue
                if rec.seq <= cutoff:
                    pruned.append(rid)
                    del self._records[rid]
                else:
                    kept.append(rid)
            self._by_source[source_id] = kept
            report = PruneReport(
                source_id=source_id,
                pruned_ids=tuple(pruned),
                remaining=len(kept),
                seq=seq,
                digest=_pin(
                    ["prune", source_id, pruned, len(kept), seq],
                    self._seed,
                ),
            )
            self._emit(
                KIND_RETENTION_APPLIED,
                seq,
                source_id=source_id,
                pruned_count=len(pruned),
                remaining=len(kept),
                digest=report.digest,
            )
            return report

    # -- views ------------------------------------------------------------

    def source(self, source_id: str) -> SourceRecord:
        with self._lock:
            if source_id not in self._sources:
                raise UnknownSourceError(
                    f"unknown source_id: {source_id!r}"
                )
            return self._sources[source_id]

    def source_ids(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._sources))

    def record(self, record_id: str) -> LogRecord:
        with self._lock:
            if record_id not in self._records:
                raise LogAggregationError(
                    f"unknown record_id: {record_id!r}"
                )
            return self._records[record_id]

    def stats(self) -> dict[str, int]:
        with self._lock:
            return {
                "sources": len(self._sources),
                "records": len(self._records),
                "policies": len(self._policies),
            }

    def audit_log(self) -> tuple[dict[str, Any], ...]:
        with self._lock:
            return tuple(self._audit_log)


def main() -> None:
    agg = LogAggregation(seed="self-check")
    agg.register_source("app-1", 1)
    batch = agg.collect(
        "app-1",
        [
            {"message": "boot ok", "level": "info",
             "labels": {"env": "prod"}},
            {"message": "disk 90%", "level": "warning"},
        ],
        2,
    )
    assert len(batch.record_ids) == 2
    result = agg.query(3, source_id="app-1", min_level="warning")
    assert len(result.hits) == 1
    assert result.hits[0].level == "warning"
    report = agg.retention("app-1", 0, 4)
    assert report.remaining == 0
    assert agg.stats()["records"] == 0
    assert all(
        rec.verify("self-check")
        for rec in (agg.source("app-1"),)
    )
    print("log-aggregation OK: source, collect, query, retention, pins")


if __name__ == "__main__":
    main()
