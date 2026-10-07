"""Tests for metrics_collection: simulated StatsD-style metric bookkeeping."""

import ast
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from metrics_collection import (
    AUDIT_SCHEMA,
    KIND_COLLECTED,
    KIND_FLUSHED,
    KIND_METRIC_DEFINED,
    KIND_REJECTED,
    AuditKindError,
    BadBucketError,
    BadMetricError,
    BadTagError,
    BadValueError,
    CounterDecreaseError,
    DuplicateMetricError,
    MetricTypeConflictError,
    MetricsCollection,
    MetricsCollectionError,
    SeqOrderError,
    UnknownMetricError,
    metrics_collection_audit_event,
)

MODULE_PATH = os.path.join(
    os.path.dirname(__file__), "..", "metrics_collection.py"
)

_STDLIB_ALLOW = {
    "hashlib",
    "hmac",
    "math",
    "re",
    "threading",
    "dataclasses",
    "typing",
    "__future__",
    "json",  # guarded fallback inside _canonical
    "canonical_json",  # standard guarded fallback across the batch line
}


def fresh(seed="t"):
    return MetricsCollection(seed=seed)


# --- pins -----------------------------------------------------------------


def test_version_schema_pins():
    import metrics_collection as mc

    assert mc.METRICS_COLLECTION_VERSION == "metrics-collection.v1"
    assert mc.METRICS_COLLECTION_SCHEMA == "northstar.metrics-collection.v1"
    assert AUDIT_SCHEMA == "audit.ndjson/1"
    assert set(mc.METRIC_TYPES) == {"counter", "gauge", "histogram"}


def test_stdlib_only():
    tree = ast.parse(open(MODULE_PATH).read())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imported.add(node.module.split(".")[0])
    assert imported <= _STDLIB_ALLOW, imported - _STDLIB_ALLOW


# --- definitions ----------------------------------------------------------


def test_define_roundtrip():
    mon = fresh()
    definition = mon.define_counter("req_total", 1, "requests")
    assert definition.name == "req_total"
    assert definition.metric_type == "counter"
    assert definition.verify(mon._seed)
    fetched = mon.definition("req_total", 2)
    assert fetched == definition


def test_define_duplicate_refused():
    mon = fresh()
    mon.define_gauge("depth", 1)
    try:
        mon.define_gauge("depth", 2)
        assert False, "expected DuplicateMetricError"
    except DuplicateMetricError:
        pass


def test_define_bad_names():
    mon = fresh()
    seq = 1
    for bad in ["", "has space", "9starts-digit", "a" * 129, "semi;colon"]:
        seq += 1
        try:
            mon.define_counter(bad, seq)
            assert False, f"expected BadMetricError for {bad!r}"
        except BadMetricError:
            pass


def test_define_histogram_bad_buckets():
    mon = fresh()
    seq = 1
    for bad in [[], [50, 10], [10, 10], ["x"], [-5]]:
        seq += 1
        try:
            mon.define_histogram("lat", seq, bad)
            assert False, f"expected BadBucketError for {bad!r}"
        except BadBucketError:
            pass


def test_define_histogram_roundtrip():
    mon = fresh()
    definition = mon.define_histogram("latency_ms", 1, [10, 50, 250])
    assert definition.metric_type == "histogram"
    assert definition.verify(mon._seed)


def test_tag_declaration_and_mismatch():
    mon = fresh()
    mon.define_counter("req_total", 1, tag_keys=["method", "code"])
    rec = mon.counter("req_total", 3, 2, tags={"method": "get", "code": "200"})
    assert rec.tags == (("code", "200"), ("method", "get"))
    try:
        mon.counter("req_total", 1, 3, tags={"method": "get"})
        assert False, "expected BadTagError"
    except BadTagError:
        pass
    try:
        mon.counter("req_total", 1, 4, tags={"method": "get", "code": "a b"})
        assert False, "expected BadTagError"
    except BadTagError:
        pass


# --- collection -----------------------------------------------------------


def test_counter_happy_and_negative_refused():
    mon = fresh()
    mon.define_counter("req_total", 1)
    rec = mon.counter("req_total", 7, 2)
    assert rec.value == 7.0
    assert rec.verify(mon._seed)
    mon.counter("req_total", 3, 3)
    agg = mon.aggregate("req_total", 4)
    assert agg.count == 2 and agg.sum == 10.0
    assert agg.min == 3.0 and agg.max == 7.0  # increment min/max
    assert agg.mean == 5.0
    try:
        mon.counter("req_total", -1, 5)
        assert False, "expected CounterDecreaseError"
    except CounterDecreaseError:
        pass


def test_gauge_free_movement():
    mon = fresh()
    mon.define_gauge("queue_depth", 1)
    mon.gauge("queue_depth", 12, 2)
    mon.gauge("queue_depth", -3, 3)
    mon.gauge("queue_depth", 4.5, 4)
    agg = mon.aggregate("queue_depth", 5)
    assert agg.max == 4.5 and agg.min == 4.5 and agg.count == 1


def test_histogram_buckets_and_quantiles():
    mon = fresh()
    mon.define_histogram("latency_ms", 1, [10, 50, 250, 1000])
    seq = 1
    for value in (5, 20, 60, 300, 2000):
        seq += 1
        mon.histogram("latency_ms", value, seq)
    agg = mon.aggregate("latency_ms", seq + 1)
    assert agg.count == 5
    assert agg.sum == 2385.0
    assert agg.min == 5.0 and agg.max == 2000.0
    assert agg.mean == 2385.0 / 5
    bounds = [b.cumulative_count for b in agg.buckets]
    assert bounds == [1, 2, 3, 4], bounds  # cumulative, 2000 above all
    # nearest-rank: n=5 -> p50 rank 3 -> bucket 250; p95/p99 rank 5 -> 1000
    assert agg.p50 == 250.0
    assert agg.p95 == 1000.0
    assert agg.p99 == 1000.0


def test_histogram_negative_refused():
    mon = fresh()
    mon.define_histogram("latency_ms", 1, [10, 50])
    try:
        mon.histogram("latency_ms", -1, 2)
        assert False, "expected BadValueError"
    except BadValueError:
        pass


def test_bad_values():
    mon = fresh()
    mon.define_counter("c", 1)
    mon.define_gauge("g", 2)
    seq = 2
    for bad in [True, float("nan"), float("inf"), 2**53, "x", None]:
        seq += 1
        try:
            mon.counter("c", bad, seq)
            assert False, f"expected BadValueError for {bad!r}"
        except BadValueError:
            pass
        seq += 1
        try:
            mon.gauge("g", bad, seq)
            assert False, f"expected BadValueError for {bad!r}"
        except BadValueError:
            pass


def test_unknown_metric_and_type_conflict():
    mon = fresh()
    try:
        mon.counter("nope", 1, 1)
        assert False, "expected UnknownMetricError"
    except UnknownMetricError:
        pass
    mon.define_gauge("depth", 2)
    try:
        mon.counter("depth", 1, 3)
        assert False, "expected MetricTypeConflictError"
    except MetricTypeConflictError:
        pass


# --- seq discipline -------------------------------------------------------


def test_seq_ordering_and_failed_mutation_consumes_seq():
    mon = fresh()
    mon.define_counter("c", 1)
    for bad in [1, 0, -1, True, 1.5, "2"]:
        try:
            mon.counter("c", 1, bad)
            assert False, f"expected SeqOrderError for {bad!r}"
        except SeqOrderError:
            pass
    # failed mutation (negative increment) consumed its seq
    try:
        mon.counter("c", -5, 2)
    except CounterDecreaseError:
        pass
    try:
        mon.counter("c", 1, 2)
        assert False, "seq 2 was consumed by the failed mutation"
    except SeqOrderError:
        pass
    rec = mon.counter("c", 1, 3)
    assert rec.seq == 3


def test_views_do_not_consume_seq():
    mon = fresh()
    mon.define_counter("c", 1)
    mon.counter("c", 5, 2)
    assert mon.aggregate("c", 2).sum == 5.0  # same seq OK on a view
    assert mon.series(2) == ("c",)
    assert mon.stats(2)["samples"] == 1
    mon.counter("c", 1, 3)  # mutation still needs seq > 2
    try:
        mon.counter("c", 1, 3)
        assert False, "expected SeqOrderError"
    except SeqOrderError:
        pass


# --- flush ----------------------------------------------------------------


def test_flush_semantics():
    mon = fresh()
    mon.define_counter("req_total", 1)
    mon.define_gauge("queue_depth", 2)
    mon.define_histogram("latency_ms", 3, [10, 50])
    mon.counter("req_total", 7, 4)
    mon.gauge("queue_depth", 12, 5)
    mon.histogram("latency_ms", 5, 6)
    mon.histogram("latency_ms", 40, 7)
    report = mon.flush(8)
    assert report.verify(mon._seed)
    assert len(report.aggregates) == 3
    by_name = {a.name: a for a in report.aggregates}
    assert by_name["req_total"].sum == 7.0
    assert by_name["queue_depth"].max == 12.0
    assert by_name["latency_ms"].count == 2
    assert [b.cumulative_count for b in by_name["latency_ms"].buckets] == [1, 2]
    # post-flush state: counters reset, gauges retained, buckets emptied
    assert mon.aggregate("req_total", 9).count == 0
    assert mon.aggregate("queue_depth", 9).max == 12.0
    assert mon.aggregate("latency_ms", 9).count == 0
    # counter keeps working after flush
    mon.counter("req_total", 2, 10)
    assert mon.aggregate("req_total", 11).sum == 2.0


def test_flush_empty_registry():
    mon = fresh()
    report = mon.flush(1)
    assert report.aggregates == ()
    assert report.verify(mon._seed)


# --- audit ----------------------------------------------------------------


def test_audit_shapes_and_bans():
    mon = fresh()
    mon.define_counter("req_total", 1)
    mon.counter("req_total", 7, 2)
    report = mon.flush(3)
    kinds = [e["kind"] for e in mon.audit_log(4)]
    assert kinds == [KIND_METRIC_DEFINED, KIND_COLLECTED, KIND_FLUSHED]
    for event in mon.audit_log(4):
        assert event["schema"] == AUDIT_SCHEMA
        assert "samples" not in event["detail"]
        assert "values" not in event["detail"]
    flushed = mon.audit_log(4)[2]
    assert flushed["detail"]["digest"] == report.digest
    try:
        metrics_collection_audit_event("bogus.kind", 5)
        assert False, "expected AuditKindError"
    except AuditKindError:
        pass
    try:
        metrics_collection_audit_event(KIND_COLLECTED, 5, {"samples": [1]})
        assert False, "expected banned-key refusal"
    except MetricsCollectionError:
        pass


def test_rejected_is_audited():
    mon = fresh()
    mon.define_counter("c", 1)
    try:
        mon.counter("c", -1, 2)
    except CounterDecreaseError:
        pass
    kinds = [e["kind"] for e in mon.audit_log(3)]
    assert kinds == [KIND_METRIC_DEFINED, KIND_REJECTED]


def test_cross_instance_digest_determinism():
    a = fresh(seed="same")
    b = fresh(seed="same")
    a.define_counter("c", 1)
    b.define_counter("c", 1)
    a.counter("c", 5, 2)
    b.counter("c", 5, 2)
    assert a.aggregate("c", 3).digest == b.aggregate("c", 3).digest
    c = fresh(seed="other")
    c.define_counter("c", 1)
    c.counter("c", 5, 2)
    assert c.aggregate("c", 3).digest != a.aggregate("c", 3).digest


# --- main / misc ----------------------------------------------------------


def test_series_and_stats_views():
    mon = fresh()
    assert mon.series(0) == ()
    mon.define_gauge("b_gauge", 1)
    mon.define_counter("a_counter", 2)
    assert mon.series(3) == ("a_counter", "b_gauge")
    stats = mon.stats(3)
    assert stats["metrics"] == {"counter": 1, "gauge": 1, "histogram": 0}
    assert stats["samples"] == 0


def test_empty_aggregates():
    mon = fresh()
    mon.define_gauge("g", 1)
    agg = mon.aggregate("g", 2)
    assert agg.count == 0 and agg.mean is None
    mon.define_histogram("h", 3, [10])
    hagg = mon.aggregate("h", 4)
    assert hagg.count == 0 and hagg.p50 is None
    assert len(hagg.buckets) == 1


def test_tagged_series_isolation():
    mon = fresh()
    mon.define_counter("req_total", 1, tag_keys=["method"])
    mon.counter("req_total", 3, 2, tags={"method": "get"})
    mon.counter("req_total", 7, 3, tags={"method": "post"})
    get = mon.aggregate("req_total", 4, tags={"method": "get"})
    post = mon.aggregate("req_total", 4, tags={"method": "post"})
    assert get.sum == 3.0 and post.sum == 7.0


def test_main_self_check():
    proc = subprocess.run(
        [sys.executable, MODULE_PATH],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert "metrics-collection OK" in proc.stdout
