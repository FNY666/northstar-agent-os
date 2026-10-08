"""Tests for log_aggregation.py (ELK/Loki-shaped simulated bookkeeping)."""

from __future__ import annotations

import ast
import subprocess
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import log_aggregation as la  # noqa: E402
from log_aggregation import LogAggregation  # noqa: E402

THIS = Path(__file__).resolve()


def _entry(**kw):
    base = {"message": "hello", "level": "info"}
    base.update(kw)
    return base


# -- pins -------------------------------------------------------------------


def test_version_and_schema_pins():
    assert la.LOG_AGGREGATION_VERSION == "log-aggregation.v1"
    assert la.LOG_AGGREGATION_SCHEMA == "northstar.log-aggregation.v1"
    assert la.AUDIT_SCHEMA == "audit.ndjson/1"
    assert la.LEVELS == (
        "debug", "info", "notice", "warning", "error", "critical",
    )


def test_stdlib_only_ast():
    tree = ast.parse(THIS.parent.parent.joinpath(
        "log_aggregation.py").read_text())
    allowed = {
        "hashlib", "hmac", "json", "threading", "dataclasses",
        "typing", "canonical_json", "__future__",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed


def test_main_self_check():
    out = subprocess.run(
        [sys.executable, str(THIS.parent.parent / "log_aggregation.py")],
        capture_output=True, text=True, check=True,
    ).stdout
    assert "log-aggregation OK" in out


# -- sources ----------------------------------------------------------------


def test_register_source_roundtrip():
    agg = LogAggregation(seed="s1")
    rec = agg.register_source("app-1", 1)
    assert rec.source_id == "app-1"
    assert rec.verify("s1")
    assert agg.source("app-1") is rec
    assert agg.source_ids() == ("app-1",)


def test_register_source_duplicate_and_bad():
    agg = LogAggregation()
    agg.register_source("app-1", 1)
    with pytest.raises(la.DuplicateSourceError):
        agg.register_source("app-1", 2)
    for bad in ("", 123, None):
        with pytest.raises(la.LogAggregationError):
            agg.register_source(bad, 3)
    with pytest.raises(la.UnknownSourceError):
        agg.source("nope")


# -- collect ----------------------------------------------------------------


def test_collect_roundtrip_and_verify():
    agg = LogAggregation(seed="s2")
    agg.register_source("app-1", 1)
    batch = agg.collect(
        "app-1",
        [_entry(message="boot ok", labels={"env": "prod"}),
         _entry(message="slow query", level="warning")],
        2,
    )
    assert batch.batch_id == "ing-1"
    assert len(batch.record_ids) == 2
    rec = agg.record(batch.record_ids[0])
    assert rec.verify("s2")
    assert rec.level == "info"
    assert dict(rec.labels) == {"env": "prod"}
    assert agg.stats() == {"sources": 1, "records": 2, "policies": 0}


def test_collect_bad_entries_fail_closed():
    agg = LogAggregation()
    agg.register_source("app-1", 1)
    bad_entries = [
        [{"message": "", "level": "info"}],
        [{"message": "x", "level": "bogus"}],
        [{"level": "info"}],
        [{"message": "x", "level": "info", "labels": {"k": 1}}],
        [{"message": "x", "level": "info", "labels": "nope"}],
        "not-a-list",
        [],
    ]
    seq = 2
    for entries in bad_entries:
        with pytest.raises(la.LogAggregationError):
            agg.collect("app-1", entries, seq)
        seq += 1  # failed mutations consume their seq
    assert agg.stats()["records"] == 0


def test_collect_unknown_source():
    agg = LogAggregation()
    with pytest.raises(la.UnknownSourceError):
        agg.collect("ghost", [_entry()], 1)


# -- seq discipline ----------------------------------------------------------


def test_seq_rewind_and_bool_refused():
    agg = LogAggregation()
    agg.register_source("app-1", 5)
    with pytest.raises(la.SeqOrderError):
        agg.register_source("app-2", 5)  # not strictly increasing
    with pytest.raises(la.SeqOrderError):
        agg.register_source("app-2", True)
    with pytest.raises(la.SeqOrderError):
        agg.register_source("app-2", -1)




def test_seq_rewind_is_audited_without_consuming_state():
    agg = LogAggregation()
    agg.register_source("app-1", 5)
    with pytest.raises(la.SeqOrderError):
        agg.register_source("app-2", 5)
    rejected = [event for event in agg.audit_log()
                if event["kind"] == la.KIND_REJECTED]
    assert rejected and rejected[-1]["seq"] == 5
    assert rejected[-1]["detail"]["reason"] == (
        "seq must strictly increase (last=5, got=5)"
    )
    # The precondition failure does not consume the failed sequence.
    agg.register_source("app-2", 6)
    assert agg.source_ids() == ("app-1", "app-2")


def test_failed_mutation_consumes_seq_and_audits_rejected():
    agg = LogAggregation()
    agg.register_source("app-1", 1)
    with pytest.raises(la.DuplicateSourceError):
        agg.register_source("app-1", 2)
    # seq 2 is burned: next valid mutation must be > 2
    with pytest.raises(la.SeqOrderError):
        agg.register_source("app-2", 2)
    agg.register_source("app-2", 3)
    kinds = [e["kind"] for e in agg.audit_log()]
    assert la.KIND_REJECTED in kinds


# -- query ------------------------------------------------------------------


def _seeded() -> LogAggregation:
    agg = LogAggregation(seed="q")
    agg.register_source("app-1", 1)
    agg.register_source("app-2", 2)
    agg.collect(
        "app-1",
        [_entry(message="a1", level="debug", labels={"env": "prod"}),
         _entry(message="a2", level="error", labels={"env": "prod"}),
         _entry(message="a3", level="critical",
                labels={"env": "staging"})],
        3,
    )
    agg.collect("app-2", [_entry(message="b1", level="warning")], 4)
    return agg


def test_query_filters():
    agg = _seeded()
    assert len(agg.query(5, source_id="app-1").hits) == 3
    res = agg.query(6, min_level="error")
    assert {h.message for h in res.hits} == {"a2", "a3"}
    res = agg.query(7, labels={"env": "prod"})
    assert {h.message for h in res.hits} == {"a1", "a2"}
    res = agg.query(8, since_seq=3)
    assert {h.message for h in res.hits} == {"b1"}
    res = agg.query(9, source_id="app-1", limit=2)
    assert len(res.hits) == 2 and res.cursor == 3
    res = agg.query(10, labels={"env": "missing"})
    assert res.hits == ()  # zero hits is data, not an error


def test_query_read_view_seq_not_consumed():
    agg = _seeded()
    agg.query(5)
    agg.query(5)  # same seq twice is fine: reads don't consume
    with pytest.raises(la.SeqOrderError):
        agg.register_source("app-3", 4)  # still blocked behind last seq


def test_query_bad_inputs():
    agg = _seeded()
    with pytest.raises(la.UnknownSourceError):
        agg.query(5, source_id="ghost")
    with pytest.raises(la.BadQueryError):
        agg.query(5, min_level="bogus")
    for bad_limit in (0, -1, True, "10", 10_001):
        with pytest.raises(la.BadQueryError):
            agg.query(5, limit=bad_limit)


# -- retention --------------------------------------------------------------


def test_retention_prunes_and_books_policy():
    agg = _seeded()
    report = agg.retention("app-1", 0, 5)
    assert report.pruned_ids == ("rec-1", "rec-2", "rec-3")
    assert report.remaining == 0
    assert agg.query(6, source_id="app-1").hits == ()
    assert agg.query(7).hits[0].message == "b1"  # other source kept
    policy = agg._policies["app-1"]
    assert policy.verify("q") and policy.max_age == 0


def test_retention_bad_inputs():
    agg = _seeded()
    with pytest.raises(la.UnknownSourceError):
        agg.retention("ghost", 0, 5)
    seq = 6
    for bad in (-1, True, "x"):
        with pytest.raises(la.BadRetentionError):
            agg.retention("app-1", bad, seq)
        seq += 1  # failed mutations consume their seq


# -- audit ------------------------------------------------------------------


def test_audit_shapes_and_leak_ban():
    agg = _seeded()
    agg.query(5)
    agg.retention("app-2", 10, 6)
    kinds = [e["kind"] for e in agg.audit_log()]
    for want in (la.KIND_SOURCE_REGISTERED, la.KIND_COLLECTED,
                 la.KIND_QUERIED, la.KIND_RETENTION_APPLIED):
        assert want in kinds
    for event in agg.audit_log():
        assert event["schema"] == "audit.ndjson/1"
        assert "message" not in event["detail"]
        assert "labels" not in event["detail"]
    with pytest.raises(la.LogAggregationError):
        la.log_aggregation_audit_event(
            la.KIND_COLLECTED, 9, message="leak")


def test_cross_instance_digest_determinism():
    a = LogAggregation(seed="same")
    b = LogAggregation(seed="same")
    for agg, s in ((a, 1), (b, 1)):
        agg.register_source("app", s)
        agg.collect("app", [_entry(message="m")], s + 1)
    assert (a.record("rec-1").digest ==
            b.record("rec-1").digest)


def test_concurrency_smoke():
    agg = LogAggregation()
    agg.register_source("app", 1)
    # The API requires caller-supplied mutation seqs to be strictly increasing.
    # Serialize allocation with the call so thread scheduling cannot violate
    # that contract before the implementation sees the request.
    seq_lock = threading.Lock()
    next_seq = 2
    worker_errors = []
    results = []

    def worker():
        nonlocal next_seq
        completed = 0
        while True:
            with seq_lock:
                if next_seq >= 200:
                    break
                seq = next_seq
                next_seq += 1
                try:
                    agg.collect("app", [_entry(message=f"m{seq}")], seq)
                except Exception as exc:  # pragma: no cover - asserted below
                    worker_errors.append(exc)
                    break
                completed += 1
        results.append(completed)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert worker_errors == []
    assert sum(results) == 198
    assert agg.stats()["records"] == 198
