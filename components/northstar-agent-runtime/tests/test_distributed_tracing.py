"""Tests for distributed_tracing: 15 cases."""

import ast
import os
import subprocess
import sys
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import distributed_tracing
from distributed_tracing import (
    DISTRIBUTED_TRACING_VERSION,
    DISTRIBUTED_TRACING_SCHEMA,
    AUDIT_SCHEMA,
    SPAN_KINDS,
    SPAN_STATUSES,
    EXPORT_FORMATS,
    DistributedTracing,
    DistributedTracingError,
    BadFormatError,
    BadSpanError,
    BadTraceError,
    DuplicateSpanError,
    FinishedSpanError,
    SeqOrderError,
    UnknownSpanError,
    UnknownTraceError,
    distributed_tracing_audit_event,
)


def test_version_and_schema_pins():
    assert DISTRIBUTED_TRACING_VERSION == "distributed-tracing.v1"
    assert DISTRIBUTED_TRACING_SCHEMA == "northstar.distributed-tracing.v1"
    assert AUDIT_SCHEMA == "audit.ndjson/1"
    assert set(SPAN_KINDS) == {"internal", "server", "client", "producer", "consumer"}
    assert set(SPAN_STATUSES) == {"unset", "ok", "error"}
    assert set(EXPORT_FORMATS) == {"jaeger", "zipkin"}


def test_stdlib_only():
    src = open(distributed_tracing.__file__).read()
    tree = ast.parse(src)
    allowed = {
        "hashlib", "threading", "dataclasses", "typing",
        "canonical_json", "json", "__future__",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed, a.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


def test_span_roundtrip_and_duplicate():
    dt = DistributedTracing()
    rec = dt.span("s1", "tr-1", "handle", 1, kind="server",
                 tags={"http.method": "GET"})
    assert rec.span_id == "s1" and rec.trace_id == "tr-1"
    assert rec.parent_span_id is None and rec.start_seq == 1
    assert rec.verify()
    try:
        dt.span("s1", "tr-1", "handle", 2)
        assert False, "expected DuplicateSpanError"
    except DuplicateSpanError:
        pass


def test_span_bad_inputs():
    dt = DistributedTracing()
    for bad in ("", "   "):
        for kwargs in ({"span_id": bad}, {"trace_id": bad}, {"name": bad}):
            try:
                dt.span(kwargs.get("span_id", "s"), kwargs.get("trace_id", "t"),
                        kwargs.get("name", "n"), 1)
                assert False, f"expected error for {kwargs}"
            except DistributedTracingError:
                pass
    try:
        dt.span("s", "t", "n", 2, kind="bogus")
        assert False
    except BadSpanError:
        pass
    try:
        dt.span("s", "t", "n", 3, tags={"k": object()})
        assert False
    except BadSpanError:
        pass
    # orphan parent refused
    try:
        dt.span("child", "t", "n", 4, parent_span_id="ghost")
        assert False
    except UnknownSpanError:
        pass
    # self-parent refused
    try:
        dt.span("loop", "t", "n", 5, parent_span_id="loop")
        assert False
    except BadSpanError:
        pass
    # parent in another trace refused
    dt.span("p", "tr-a", "root", 6)
    try:
        dt.span("c", "tr-b", "child", 7, parent_span_id="p")
        assert False
    except BadSpanError:
        pass


def test_parent_child_linkage():
    dt = DistributedTracing()
    dt.span("root", "tr-1", "serve", 1, kind="server")
    child = dt.span("leaf", "tr-1", "query", 2, parent_span_id="root",
                    kind="client")
    assert child.parent_span_id == "root" and child.verify()
    report = dt.trace("tr-1", 3)
    assert report.span_ids == ("root", "leaf")


def test_finish_span_roundtrip_and_terminality():
    dt = DistributedTracing()
    dt.span("s1", "tr-1", "work", 1)
    fin = dt.finish_span("s1", 2, status="ok")
    assert fin.end_seq == 2 and fin.duration == 1 and fin.status == "ok"
    assert fin.verify()
    try:
        dt.finish_span("s1", 3)
        assert False, "expected FinishedSpanError"
    except FinishedSpanError:
        pass
    try:
        dt.finish_span("ghost", 4)
        assert False
    except UnknownSpanError:
        pass
    try:
        dt.span("s2", "tr-1", "x", 5)
        dt.finish_span("s2", 6, status="bogus")
        assert False
    except BadSpanError:
        pass


def test_trace_view_and_read_does_not_consume_seq():
    dt = DistributedTracing()
    dt.span("a", "tr-1", "alpha", 1)
    dt.span("b", "tr-1", "beta", 2)
    dt.finish_span("b", 3, status="error")
    rep = dt.trace("tr-1", 4)
    assert rep.verify()
    assert rep.open_spans == 1 and rep.finished_spans == 1
    assert rep.span_ids == ("a", "b")  # ordered by start_seq
    # read view did not consume seq 4: next mutation at seq 4 must work
    dt.span("c", "tr-1", "gamma", 4)
    try:
        dt.trace("tr-missing", 5)
        assert False
    except UnknownTraceError:
        pass


def test_export_jaeger_shape_and_determinism():
    dt = DistributedTracing()
    dt.span("root", "tr-9", "handle", 1)
    dt.span("child", "tr-9", "db", 2, parent_span_id="root")
    dt.finish_span("child", 3)
    dt.finish_span("root", 4)
    rec = dt.export("tr-9", 5, format="jaeger")
    assert rec.verify() and rec.span_count == 2
    doc = rec.document
    assert doc["traceID"] == "tr-9"
    assert len(doc["spans"]) == 2
    child_doc = [s for s in doc["spans"] if s["spanID"] == "child"][0]
    assert child_doc["operationName"] == "db"
    assert child_doc["references"][0]["refType"] == "CHILD_OF"
    assert child_doc["references"][0]["spanID"] == "root"
    # deterministic across instances
    dt2 = DistributedTracing()
    dt2.span("root", "tr-9", "handle", 1)
    dt2.span("child", "tr-9", "db", 2, parent_span_id="root")
    dt2.finish_span("child", 3)
    dt2.finish_span("root", 4)
    rec2 = dt2.export("tr-9", 5, format="jaeger")
    assert rec2.digest == rec.digest


def test_export_zipkin_shape_and_errors():
    dt = DistributedTracing()
    dt.span("s1", "tr-1", "work", 1, kind="client", tags={"k": "v"})
    dt.finish_span("s1", 2)
    rec = dt.export("tr-1", 3, format="zipkin")
    assert rec.verify()
    spans = rec.document["traces"]
    assert len(spans) == 1
    assert spans[0]["traceId"] == "tr-1" and spans[0]["id"] == "s1"
    assert spans[0]["tags"] == [{"key": "k", "value": "v"}]
    try:
        dt.export("tr-1", 4, format="opentracing")
        assert False
    except BadFormatError:
        pass
    try:
        dt.export("tr-missing", 5)
        assert False
    except UnknownTraceError:
        pass


def test_seq_ordering_and_bool_refusal():
    dt = DistributedTracing()
    dt.span("s1", "tr-1", "a", 5)
    for bad in (5, 4, 0, True, "6", 5.0, -1):
        try:
            dt.span(f"s-{bad}", "tr-1", "b", bad)
            assert False, f"expected SeqOrderError for {bad!r}"
        except SeqOrderError:
            pass


def test_failed_mutation_consumes_seq():
    dt = DistributedTracing()
    dt.span("s1", "tr-1", "a", 1)
    try:
        dt.span("s1", "tr-1", "dup", 2)  # duplicate: fails
        assert False
    except DuplicateSpanError:
        pass
    # seq 2 was consumed by the failure; reusing it must now fail
    try:
        dt.span("s2", "tr-1", "b", 2)
        assert False, "expected SeqOrderError"
    except SeqOrderError:
        pass
    # and the failure was audited
    kinds = [e["kind"] for e in dt.audit_log()]
    assert "trace.rejected" in kinds


def test_audit_shapes_and_leak_ban():
    ev = distributed_tracing_audit_event(
        "trace.span-started", {"span_id": "s", "trace_id": "t"}, 1)
    assert ev["schema"] == AUDIT_SCHEMA and ev["seq"] == 1
    assert ev["module"] == DISTRIBUTED_TRACING_VERSION
    try:
        distributed_tracing_audit_event(
            "trace.span-started", {"tags": {"k": "v"}}, 2)
        assert False
    except DistributedTracingError:
        pass
    try:
        distributed_tracing_audit_event("trace.bogus", {}, 3)
        assert False
    except DistributedTracingError:
        pass
    # end-to-end: started + finished events, no tag leakage
    dt = DistributedTracing()
    dt.span("s1", "tr-1", "n", 1, tags={"secret": "x"})
    dt.finish_span("s1", 2)
    log = dt.audit_log()
    assert [e["kind"] for e in log] == ["trace.span-started", "trace.span-finished"]
    for e in log:
        assert "tags" not in e["detail"]


def test_concurrency_smoke():
    dt = DistributedTracing()
    errors = []

    def work(i):
        try:
            dt.span(f"s{i}", "tr-c", f"op{i}", 1 + i)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=work, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert len(dt.span_ids()) == 8


def test_main_self_check():
    r = subprocess.run(
        [sys.executable, "-c", "import sys; sys.path.insert(0, '.'); "
         "import distributed_tracing; distributed_tracing.main()"],
        cwd=os.path.join(os.path.dirname(__file__), ".."),
        capture_output=True, text=True,
    )
    assert r.returncode == 0, r.stderr
    assert "distributed-tracing OK" in r.stdout


def test_standalone_import():
    r = subprocess.run(
        [sys.executable, "-c",
         "import distributed_tracing; distributed_tracing.main()"],
        cwd="/tmp", capture_output=True, text=True,
        env={**os.environ,
             "PYTHONPATH": os.path.join(os.path.dirname(__file__), "..")},
    )
    assert r.returncode == 0, r.stderr
