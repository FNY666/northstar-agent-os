"""Tests for time_series_db: write/query/downsample, seq discipline, audit."""

import ast
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from time_series_db import (
    AUDIT_SCHEMA,
    AGGREGATORS,
    SCHEMA_PIN,
    TIME_SERIES_DB_VERSION,
    AuditKindError,
    BadAggregatorError,
    BadFieldError,
    BadMeasurementError,
    BadTagError,
    BadTimestampError,
    BadWindowError,
    SeqOrderError,
    TimeSeriesDB,
    TimeSeriesDBError,
    time_series_db_audit_event,
)

MODULE_PATH = os.path.join(
    os.path.dirname(__file__), "..", "time_series_db.py"
)

_STDLIB_ALLOW = {
    "hashlib",
    "dataclasses",
    "typing",
    "__future__",
}


def fresh():
    return TimeSeriesDB()


# --- pins ------------------------------------------------------------------


def test_version_pins():
    assert TIME_SERIES_DB_VERSION == "time-series-db.v1"
    assert SCHEMA_PIN == "northstar.time-series-db.v1"
    assert AUDIT_SCHEMA == "audit.ndjson/1"
    assert set(AGGREGATORS) == {"mean", "sum", "min", "max", "count"}


def test_stdlib_only():
    tree = ast.parse(open(MODULE_PATH).read())
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module.split(".")[0])
    assert imports <= _STDLIB_ALLOW, imports - _STDLIB_ALLOW


# --- write -----------------------------------------------------------------


def test_write_roundtrip():
    db = fresh()
    rec = db.write("cpu", {"host": "a", "dc": "east"}, {"usage": 42, "ok": True}, 1)
    assert rec.measurement == "cpu"
    assert rec.tags == (("dc", "east"), ("host", "a"))
    assert rec.timestamp == 1  # defaults to seq
    assert rec.digest.startswith("sha256:")
    assert rec.verify()
    rec2 = db.write("cpu", {"host": "a"}, {"usage": 43}, 2, timestamp=100)
    assert rec2.timestamp == 100
    assert rec2.digest != rec.digest
    try:
        rec.timestamp = 999
        assert False, "record must be frozen"
    except AttributeError:
        pass


def test_write_bad_inputs():
    db = fresh()
    bad = [
        ("", {"h": "a"}, {"v": 1}, 1),
        (123, {"h": "a"}, {"v": 1}, 2),
        ("cpu", {"h": ""}, {"v": 1}, 3),
        ("cpu", {"h": "a"}, {}, 4),
        ("cpu", {"h": "a"}, {"v": True}, 5),  # bool field is allowed
        ("cpu", {"h": "a"}, {"v": 2**60}, 6),  # unsafe int refused
        ("cpu", {"h": "a"}, {"v": float("nan")}, 7),
        ("cpu", {"h": "a"}, {"v": 1}, 8, -1),  # bad timestamp
        ("cpu", {"h": "a"}, {"v": 1}, True),  # bool seq refused
    ]
    for args in bad[:4]:
        try:
            db.write(*args)
            assert False, f"should raise: {args}"
        except (BadMeasurementError, BadTagError, BadFieldError):
            pass
    try:
        db.write(*bad[5])
        assert False
    except BadFieldError:
        pass
    try:
        db.write(*bad[6])
        assert False
    except BadFieldError:
        pass
    try:
        db.write("cpu", {"h": "a"}, {"v": 1}, bad[7][3], timestamp=bad[7][4])
        assert False
    except BadTimestampError:
        pass
    try:
        db.write("cpu", {"h": "a"}, {"v": 1}, True)
        assert False
    except SeqOrderError:
        pass


# --- query -----------------------------------------------------------------


def test_query_filter_by_tags():
    db = fresh()
    db.write("cpu", {"host": "a"}, {"usage": 10}, 1)
    db.write("cpu", {"host": "b"}, {"usage": 20}, 2)
    db.write("mem", {"host": "a"}, {"free": 99}, 3)
    q = db.query("cpu", 4, tags={"host": "b"})
    assert q.count == 1
    assert q.points[0].fields[0][0] == "usage"
    q2 = db.query("cpu", 4)
    assert q2.count == 2
    q3 = db.query("mem", 4)
    assert q3.count == 1
    q4 = db.query("nope", 4)
    assert q4.count == 0 and q4.points == ()


def test_query_time_range():
    db = fresh()
    db.write("cpu", {}, {"v": 1}, 1, timestamp=100)
    db.write("cpu", {}, {"v": 2}, 2, timestamp=200)
    db.write("cpu", {}, {"v": 3}, 3, timestamp=300)
    assert db.query("cpu", 4, start=200).count == 2
    assert db.query("cpu", 4, stop=200).count == 1
    assert db.query("cpu", 4, start=100, stop=300).count == 2
    assert db.query("cpu", 4, start=400).count == 0


def test_query_pure_read():
    db = fresh()
    db.write("cpu", {}, {"v": 1}, 1)
    # Rewind on a view is allowed: views never consume seq.
    db.query("cpu", 0)
    assert len(db.audit_log()) == 1  # only the write, no query rows
    s = db.stats(0)
    assert s.points_total == 1
    assert db.measurement_ids(0) == ("cpu",)
    sr = db.series("cpu", 0)
    assert sr.series_count == 1 and sr.point_count == 1


# --- downsample ------------------------------------------------------------


def test_downsample_mean_buckets():
    db = fresh()
    db.write("cpu", {"h": "a"}, {"usage": 10}, 1, timestamp=10)
    db.write("cpu", {"h": "a"}, {"usage": 30}, 2, timestamp=40)
    db.write("cpu", {"h": "a"}, {"usage": 50}, 3, timestamp=110)
    ds = db.downsample("cpu", 4, 100, aggregator="mean")
    assert ds.bucket_count == 2
    assert ds.verify()
    first = ds.buckets[0]
    assert first.bucket_start == 0
    assert first.field == "usage" and first.count == 2
    assert first.result == "40/2", first.result
    second = ds.buckets[1]
    assert second.bucket_start == 100 and second.result == "50/1"


def test_downsample_aggregators():
    db = fresh()
    db.write("cpu", {}, {"usage": 10, "label": "x"}, 1, timestamp=5)
    db.write("cpu", {}, {"usage": 30}, 2, timestamp=15)
    summ = db.downsample("cpu", 3, 100, aggregator="sum")
    assert summ.buckets[0].result == "40"  # int stays int
    assert summ.buckets[0].field == "usage"
    assert all(b.field != "label" for b in summ.buckets)  # str skipped
    mn = db.downsample("cpu", 4, 100, aggregator="min")
    assert mn.buckets[0].result == "10"
    mx = db.downsample("cpu", 5, 100, aggregator="max")
    assert mx.buckets[0].result == "30"
    cnt = db.downsample("cpu", 6, 100, aggregator="count")
    assert cnt.buckets[0].field == "*" and cnt.buckets[0].result == "2"


def test_downsample_bad_inputs():
    db = fresh()
    db.write("cpu", {}, {"v": 1}, 1)
    seq = 2
    for bad_window in (0, -5, True, "x"):
        try:
            db.downsample("cpu", seq, bad_window)
            assert False, f"should raise: {bad_window}"
        except BadWindowError:
            pass
        seq += 1
    try:
        db.downsample("cpu", seq, 100, aggregator="median")
        assert False
    except BadAggregatorError:
        pass
    try:
        db.downsample("cpu", seq, 100)
        assert False, "seq reuse must raise"
    except SeqOrderError:
        pass


# --- seq discipline --------------------------------------------------------


def test_seq_ordering():
    db = fresh()
    try:
        db.write("cpu", {}, {"v": 1}, -1)
        assert False
    except SeqOrderError:
        pass
    db.write("cpu", {}, {"v": 1}, 1)
    try:
        db.write("cpu", {}, {"v": 2}, 1)  # rewind
        assert False
    except SeqOrderError:
        pass
    # Failed mutation consumes its seq: next fresh seq is 3.
    try:
        db.write("", {}, {"v": 2}, 2)
        assert False
    except BadMeasurementError:
        pass
    db.write("cpu", {}, {"v": 2}, 3)
    s = db.stats(4)
    assert s.writes == 2 and s.rejected == 1
    kinds = [r["kind"] for r in db.audit_log()]
    assert "time-series-db.rejected" in kinds


# --- audit -----------------------------------------------------------------


def test_audit_shapes():
    db = fresh()
    db.write("cpu", {"host": "a"}, {"usage": 42}, 1)
    db.downsample("cpu", 2, 100)
    rows = db.audit_log()
    assert rows[0]["schema"] == "audit.ndjson/1"
    assert rows[0]["kind"] == "time-series-db.written"
    assert rows[0]["measurement"] == "cpu"
    assert rows[0]["field_count"] == 1
    for banned in ("fields", "tags", "value", "payload", "raw"):
        assert banned not in rows[0], banned
    assert rows[1]["kind"] == "time-series-db.downsampled"
    try:
        time_series_db_audit_event("nope", 3)
        assert False
    except AuditKindError:
        pass
    try:
        time_series_db_audit_event("written", 3, value=1)
        assert False
    except TimeSeriesDBError:
        pass


# --- determinism -----------------------------------------------------------


def test_bool_int_digest_separation():
    db = fresh()
    ri = db.write("cpu", {}, {"v": 1}, 1)
    rb = db.write("cpu", {}, {"v": True}, 2)
    assert ri.digest != rb.digest
    assert ri.fields[0][1][0] == "i" and rb.fields[0][1][0] == "b"


def test_cross_instance_digest_determinism():
    a, b = fresh(), fresh()
    ra = a.write("cpu", {"h": "x"}, {"v": 7, "f": 1.5}, 1, timestamp=50)
    rb = b.write("cpu", {"h": "x"}, {"f": 1.5, "v": 7}, 1, timestamp=50)
    assert ra.digest == rb.digest
    da = a.downsample("cpu", 2, 100)
    dbb = b.downsample("cpu", 2, 100)
    assert da.digest == dbb.digest


# --- main ------------------------------------------------------------------


def test_main_self_check():
    proc = subprocess.run(
        [sys.executable, MODULE_PATH],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert "time-series-db OK" in proc.stdout
