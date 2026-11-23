"""Tests for the stream_processing module."""

import ast
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import stream_processing as sp_mod
from stream_processing import (
    STREAM_PROCESSING_VERSION,
    STREAM_PROCESSING_SCHEMA,
    KIND_TUMBLING,
    KIND_SLIDING,
    StreamProcessing,
    StreamProcessingError,
    DuplicateStreamError,
    UnknownStreamError,
    BadWindowError,
    DuplicateWindowError,
    UnknownWindowError,
    BadAggregateError,
    BadJoinError,
    DuplicateJoinError,
    UnknownJoinError,
    SeqOrderError,
    AuditKindError,
)


def fresh() -> StreamProcessing:
    return StreamProcessing()


# ---------------------------------------------------------------------------
# Pins and style
# ---------------------------------------------------------------------------


def test_version_pins():
    assert STREAM_PROCESSING_VERSION == "stream-processing.v1"
    assert STREAM_PROCESSING_SCHEMA == "northstar.stream-processing.v1"
    assert sp_mod.KIND_TUMBLING == "tumbling"
    assert sp_mod.KIND_SLIDING == "sliding"


def test_stdlib_only():
    tree = ast.parse(Path(sp_mod.__file__).read_text())
    allowed = {
        "hashlib", "threading", "dataclasses", "typing", "json",
        "canonical_json", "__future__",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed, a.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


def test_main_self_check():
    out = subprocess.run(
        [sys.executable, str(Path(sp_mod.__file__))],
        capture_output=True, text=True,
    )
    assert out.returncode == 0
    assert "stream-processing OK" in out.stdout


# ---------------------------------------------------------------------------
# Streams and events
# ---------------------------------------------------------------------------


def test_register_stream_roundtrip():
    sp = fresh()
    rec = sp.register_stream("orders", 1, key_fields=["customer"])
    assert rec.verify()
    assert sp.stream_record("orders").digest == rec.digest
    assert sp.stream_ids() == ("orders",)


def test_register_stream_duplicate_refused():
    sp = fresh()
    sp.register_stream("orders", 1)
    with pytest.raises(DuplicateStreamError):
        sp.register_stream("orders", 2)


def test_register_stream_bad_id():
    sp = fresh()
    with pytest.raises(StreamProcessingError):
        sp.register_stream("   ", 1)


def test_ingest_and_late_flag():
    sp = fresh()
    sp.register_stream("s", 1)
    e1 = sp.ingest("s", {"k": 1}, 10, 9, 2)
    e2 = sp.ingest("s", {"k": 1}, 20, 4, 3)  # out-of-order -> late
    assert e1.late is False and e2.late is True
    assert e1.verify() and e2.verify()
    assert len(sp.events_for("s")) == 2


def test_ingest_unknown_stream():
    sp = fresh()
    with pytest.raises(UnknownStreamError):
        sp.ingest("nope", "k", 1, 0, 1)


# ---------------------------------------------------------------------------
# Windows and aggregation
# ---------------------------------------------------------------------------


def test_window_tumbling_roundtrip():
    sp = fresh()
    sp.register_stream("s", 1)
    rec = sp.window("w", "s", KIND_TUMBLING, 10, 2)
    assert rec.verify()
    assert rec.slide_seq == 10
    assert sp.window_ids() == ("w",)


def test_window_sliding_roundtrip():
    sp = fresh()
    sp.register_stream("s", 1)
    rec = sp.window("w", "s", KIND_SLIDING, 10, 2, slide_seq=5)
    assert rec.verify()
    assert rec.slide_seq == 5


def test_window_bad_specs():
    sp = fresh()
    sp.register_stream("s", 1)
    with pytest.raises(BadWindowError):
        sp.window("w1", "s", "session", 10, 2)
    with pytest.raises(BadWindowError):
        sp.window("w2", "s", KIND_TUMBLING, 10, 3, slide_seq=5)
    with pytest.raises(BadWindowError):
        sp.window("w3", "s", KIND_SLIDING, 10, 4, slide_seq=10)
    with pytest.raises(DuplicateWindowError):
        sp.window("w4", "s", KIND_TUMBLING, 10, 5)
        sp.window("w4", "s", KIND_TUMBLING, 10, 6)


def test_window_unknown_stream():
    sp = fresh()
    with pytest.raises(UnknownStreamError):
        sp.window("w", "nope", KIND_TUMBLING, 10, 1)


def test_aggregate_sum_count_avg():
    sp = fresh()
    sp.register_stream("s", 1)
    sp.ingest("s", "k", 10, 2, 2)
    sp.ingest("s", "k", 20, 5, 3)
    sp.ingest("s", "k", "junk", 7, 4)  # skipped for numeric fns
    sp.window("w", "s", KIND_TUMBLING, 10, 5)
    total = sp.aggregate("w", 20, "sum")
    assert total.value == 30 and total.count == 3 and total.skipped == 1
    n = sp.aggregate("w", 21, "count")
    assert n.value == 3
    avg = sp.aggregate("w", 22, "avg")
    assert avg.value == 15.0


def test_aggregate_min_max_empty_window():
    sp = fresh()
    sp.register_stream("s", 1)
    sp.window("w", "s", KIND_TUMBLING, 10, 2)
    r = sp.aggregate("w", 20, "min")
    assert r.value is None and r.count == 0
    r2 = sp.aggregate("w", 21, "max")
    assert r2.value is None


def test_aggregate_bad_function():
    sp = fresh()
    sp.register_stream("s", 1)
    sp.window("w", "s", KIND_TUMBLING, 10, 2)
    with pytest.raises(BadAggregateError):
        sp.aggregate("w", 10, "median")


# ---------------------------------------------------------------------------
# Joins
# ---------------------------------------------------------------------------


def test_join_inner_and_left():
    sp = fresh()
    sp.register_stream("a", 1)
    sp.register_stream("b", 2)
    sp.ingest("a", "k1", 1, 3, 3)
    sp.ingest("a", "k2", 2, 4, 4)
    sp.ingest("b", "k1", 9, 5, 5)
    sp.window("wa", "a", KIND_TUMBLING, 10, 6)
    sp.window("wb", "b", KIND_TUMBLING, 10, 7)
    sp.join("j", "wa", "wb", 8, how="inner", tolerance_seq=2)
    r = sp.evaluate_join("j", 9)
    assert r.matched == 1
    assert r.pairs[0].left_event_id is not None
    assert r.pairs[0].right_event_id is not None
    assert r.pairs[0].verify()
    assert r.verify()

    sp.join("j2", "wa", "wb", 10, how="left", tolerance_seq=2)
    r2 = sp.evaluate_join("j2", 11)
    assert r2.matched == 1 and r2.unmatched_left == 1
    assert any(p.right_event_id is None for p in r2.pairs)


def test_join_bad_specs():
    sp = fresh()
    sp.register_stream("a", 1)
    sp.register_stream("b", 2)
    sp.window("wa", "a", KIND_TUMBLING, 10, 3)
    sp.window("wb", "b", KIND_TUMBLING, 10, 4)
    with pytest.raises(BadJoinError):
        sp.join("j1", "wa", "wb", 5, how="outer")
    with pytest.raises(UnknownWindowError):
        sp.join("j2", "wa", "nope", 6)
    sp.join("j3", "wa", "wb", 7)
    with pytest.raises(DuplicateJoinError):
        sp.join("j3", "wa", "wb", 8)


def test_join_tolerance_boundary():
    sp = fresh()
    sp.register_stream("a", 1)
    sp.register_stream("b", 2)
    sp.ingest("a", "k", 1, 0, 3)
    sp.ingest("b", "k", 2, 10, 4)
    sp.window("wa", "a", KIND_TUMBLING, 100, 5)
    sp.window("wb", "b", KIND_TUMBLING, 100, 6)
    sp.join("j", "wa", "wb", 7, tolerance_seq=5)
    assert sp.evaluate_join("j", 8).matched == 0
    sp.join("j2", "wa", "wb", 9, tolerance_seq=10)
    assert sp.evaluate_join("j2", 10).matched == 1


def test_join_unknown_lookup():
    sp = fresh()
    with pytest.raises(UnknownJoinError):
        sp.join_record("nope")
    with pytest.raises(StreamProcessingError):
        sp.evaluate_join("nope", 1)


# ---------------------------------------------------------------------------
# Seq discipline
# ---------------------------------------------------------------------------


def test_seq_rewind_and_bool_refused():
    sp = fresh()
    sp.register_stream("s", 1)
    with pytest.raises(SeqOrderError):
        sp.register_stream("t", 1)
    with pytest.raises(SeqOrderError):
        sp.register_stream("t", True)


def test_failed_mutation_consumes_seq():
    sp = fresh()
    sp.register_stream("s", 1)
    with pytest.raises(DuplicateStreamError):
        sp.register_stream("s", 2)
    with pytest.raises(SeqOrderError):
        sp.register_stream("t", 2)  # seq 2 consumed by the failed mutation


# ---------------------------------------------------------------------------
# Audit and views
# ---------------------------------------------------------------------------


def test_audit_shapes_and_leak_ban():
    sp = fresh()
    sp.register_stream("s", 1)
    sp.ingest("s", "k", "v", 0, 2)
    kinds = [e["kind"] for e in sp.audit_log()]
    assert "stream.stream-registered" in kinds
    assert "stream.event-ingested" in kinds
    for e in sp.audit_log():
        assert e["schema"] == "audit.ndjson/1"
        assert "key" not in e["detail"] and "value" not in e["detail"]
    with pytest.raises(AuditKindError):
        sp_mod.stream_processing_audit_event("bogus", {}, 3)


def test_views_pure_read():
    sp = fresh()
    sp.register_stream("s", 1)
    st = sp.stats(2)
    assert st["streams"] == 1 and st["events"] == 0
    d = sp.as_dict(3)
    assert d["version"] == "stream-processing.v1"
    assert set(d["streams"]) == {"s"}
