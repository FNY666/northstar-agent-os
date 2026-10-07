"""Tests for the source/sink/transform topology facade of stream_processing.

The core stream/window/aggregate/join machinery is covered by
``test_stream_processing.py`` (batch 35); this file covers only the additive
Kafka Streams / Flink-shaped topology API: ``source()``, ``sink()``,
``transform()``, and ``run_transform()``.
"""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

import stream_processing as sp_mod
from stream_processing import (
    STREAM_PROCESSING_SCHEMA,
    STREAM_PROCESSING_VERSION,
    AUDIT_SCHEMA,
    KIND_SOURCE_BOUND,
    KIND_SINK_BOUND,
    KIND_TRANSFORM_BOUND,
    KIND_TRANSFORM_RUN,
    KIND_REJECTED,
    StreamProcessing,
    UnknownStreamError,
    DuplicateSourceError,
    DuplicateSinkError,
    UnknownTransformError,
    DuplicateTransformError,
    BadTransformError,
    SeqOrderError,
)


HERE = Path(__file__).resolve()


def _two_streams(sp: StreamProcessing, start: int = 1):
    """Register 'in' and 'out' streams; return (next_seq)."""
    sp.register_stream("in", start)
    sp.register_stream("out", start + 1)
    return start + 2


def _kinds(sp: StreamProcessing):
    return [e["kind"] for e in sp.audit_log()]


def test_version_pins():
    sp = StreamProcessing()
    n = _two_streams(sp)
    src = sp.source("src-1", "in", n)
    assert src.schema == STREAM_PROCESSING_SCHEMA
    assert sp_mod.stream_processing_audit_event(
        KIND_SOURCE_BOUND, {"source_id": "src-1"}, n + 1
    )["schema"] == AUDIT_SCHEMA
    assert sp_mod.stream_processing_audit_event(
        KIND_SOURCE_BOUND, {"source_id": "src-1"}, n + 1
    )["module"] == STREAM_PROCESSING_VERSION


def test_source_roundtrip():
    sp = StreamProcessing()
    n = _two_streams(sp)
    rec = sp.source("src-1", "in", n)
    assert rec.source_id == "src-1" and rec.stream_id == "in"
    assert rec.verify()
    assert sp.source_record("src-1") is rec
    assert sp.source_ids() == ("src-1",)
    assert KIND_SOURCE_BOUND in _kinds(sp)


def test_source_unknown_stream_rejects():
    sp = StreamProcessing()
    with pytest.raises(UnknownStreamError):
        sp.source("src-1", "nope", 1)
    # Failed mutation consumed its seq; rejection is audited.
    assert KIND_REJECTED in _kinds(sp)
    with pytest.raises(SeqOrderError):
        sp.register_stream("x", 1)


def test_source_duplicate_rejects():
    sp = StreamProcessing()
    n = _two_streams(sp)
    sp.source("src-1", "in", n)
    with pytest.raises(DuplicateSourceError):
        sp.source("src-1", "in", n + 1)


def test_sink_roundtrip():
    sp = StreamProcessing()
    n = _two_streams(sp)
    rec = sp.sink("snk-1", "out", n)
    assert rec.sink_id == "snk-1" and rec.stream_id == "out"
    assert rec.verify()
    assert sp.sink_record("snk-1") is rec
    assert sp.sink_ids() == ("snk-1",)
    assert KIND_SINK_BOUND in _kinds(sp)


def test_sink_unknown_stream_rejects():
    sp = StreamProcessing()
    with pytest.raises(UnknownStreamError):
        sp.sink("snk-1", "nope", 1)
    assert KIND_REJECTED in _kinds(sp)


def test_sink_duplicate_rejects():
    sp = StreamProcessing()
    n = _two_streams(sp)
    sp.sink("snk-1", "out", n)
    with pytest.raises(DuplicateSinkError):
        sp.sink("snk-1", "in", n + 1)


def test_transform_roundtrip():
    sp = StreamProcessing()
    n = _two_streams(sp)
    rec = sp.transform("t1", "in", "out", n)
    assert rec.transform_id == "t1"
    assert rec.function == "identity"
    assert rec.options == ()
    assert rec.verify()
    assert sp.transform_record("t1") is rec
    assert sp.transform_ids() == ("t1",)
    assert KIND_TRANSFORM_BOUND in _kinds(sp)


def test_transform_bad_function_rejects():
    sp = StreamProcessing()
    n = _two_streams(sp)
    with pytest.raises(BadTransformError):
        sp.transform("t1", "in", "out", n, function="join")
    assert KIND_REJECTED in _kinds(sp)
    with pytest.raises(SeqOrderError):
        sp.transform("t1", "in", "out", n)


def test_transform_unknown_stream_rejects():
    sp = StreamProcessing()
    sp.register_stream("in", 1)
    with pytest.raises(UnknownStreamError):
        sp.transform("t1", "in", "nope", 2)
    with pytest.raises(UnknownStreamError):
        sp.transform("t2", "nope", "in", 3)


def test_transform_self_loop_and_duplicate_reject():
    sp = StreamProcessing()
    n = _two_streams(sp)
    with pytest.raises(BadTransformError):
        sp.transform("t1", "in", "in", n)
    sp.transform("t1", "in", "out", n + 1)
    with pytest.raises(DuplicateTransformError):
        sp.transform("t1", "in", "out", n + 2)
    with pytest.raises(UnknownTransformError):
        sp.run_transform("nope", n + 3)


def test_run_transform_identity():
    sp = StreamProcessing()
    n = _two_streams(sp)
    sp.ingest("in", "k1", 10, 0, n)
    sp.ingest("in", "k2", 20, 1, n + 1)
    sp.transform("t1", "in", "out", n + 2)
    run = sp.run_transform("t1", n + 3)
    assert run.verify()
    assert run.input_count == 2 and run.output_count == 2
    assert len(run.input_event_ids) == 2 == len(run.output_event_ids)
    outs = sp.events_for("out")
    assert sorted(e.value for e in outs) == [10, 20]
    assert sorted(e.key for e in outs) == ["k1", "k2"]
    assert KIND_TRANSFORM_RUN in _kinds(sp)


def test_run_transform_filter_and_project():
    sp = StreamProcessing()
    n = _two_streams(sp)
    sp.ingest("in", "a", {"amount": 10, "ccy": "usd"}, 0, n)
    sp.ingest("in", "b", {"amount": 99, "ccy": "eur"}, 1, n + 1)
    sp.ingest("in", "c", 7, 2, n + 2)  # non-mapping value: dropped by both
    sp.transform(
        "f1", "in", "out", n + 3, function="filter",
        options={"field": "amount", "value": 10},
    )
    run = sp.run_transform("f1", n + 4)
    assert run.output_count == 1
    outs = sp.events_for("out")
    assert len(outs) == 1 and outs[0].value == {"amount": 10, "ccy": "usd"}
    # Project keeps only the pinned fields, sorted and deduped.
    sp.transform(
        "p1", "in", "out", n + 5, function="project",
        options={"fields": ["ccy", "amount", "ccy"]},
    )
    trec = sp.transform_record("p1")
    assert trec.options == (("fields", ("amount", "ccy")),)
    assert trec.verify()
    run2 = sp.run_transform("p1", n + 6)
    assert run2.output_count == 2
    vals = sorted(
        (e.value for e in sp.events_for("out")[1:]),
        key=lambda v: v["amount"],
    )
    assert vals == [{"amount": 10, "ccy": "usd"}, {"amount": 99, "ccy": "eur"}]


def test_transform_audit_carries_no_raw_values():
    sp = StreamProcessing()
    n = _two_streams(sp)
    sp.transform(
        "f1", "in", "out", n, function="filter",
        options={"field": "amount", "value": 10},
    )
    detail = [e for e in sp.audit_log() if e["kind"] == KIND_TRANSFORM_BOUND][0]
    assert "value" not in detail["detail"]
    assert detail["detail"]["option_keys"] == ["field", "value"]
    with pytest.raises(Exception):
        sp_mod.stream_processing_audit_event(
            KIND_TRANSFORM_RUN, {"value": 1}, n + 1
        )


def test_main_self_check():
    r = subprocess.run(
        [sys.executable, str(HERE.parent.parent / "stream_processing.py")],
        capture_output=True, text=True,
    )
    assert r.returncode == 0
    assert "source, sink, transform" in r.stdout
    tree = ast.parse((HERE.parent.parent / "stream_processing.py").read_text())
    imports = {
        n.names[0].name.split(".")[0]
        for n in ast.walk(tree)
        if isinstance(n, ast.Import)
    } | {
        n.module.split(".")[0]
        for n in ast.walk(tree)
        if isinstance(n, ast.ImportFrom) and n.module
    }
    stdlib = {
        "__future__", "hashlib", "threading", "dataclasses", "typing",
        "json", "canonical_json",
    }
    assert imports <= stdlib, imports - stdlib
