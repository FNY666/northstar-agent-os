"""Tests for bulkhead_pattern (15 pytest-style tests)."""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

import bulkhead_pattern as bp

MODULE_PATH = Path(__file__).resolve().parent.parent / "bulkhead_pattern.py"

ALLOWED_STDLIB = {
    "hashlib", "hmac", "threading", "dataclasses", "typing",
    "__future__", "json", "canonical_json",
}


def test_version_and_schema_pins():
    assert bp.BULKHEAD_PATTERN_VERSION == "bulkhead-pattern.v1"
    assert bp.BULKHEAD_PATTERN_SCHEMA == "northstar.bulkhead-pattern.v1"
    assert bp.AUDIT_SCHEMA == "audit.ndjson/1"


def test_stdlib_only_ast():
    tree = ast.parse(MODULE_PATH.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in ALLOWED_STDLIB, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in ALLOWED_STDLIB, node.module


def test_isolate_roundtrip_and_verify():
    m = bp.BulkheadPattern()
    rec = m.isolate("payments", 8, seq=1)
    assert rec.bulkhead_id == "payments"
    assert rec.capacity == 8
    assert rec.digest.startswith("sha256:")
    assert rec.verify()
    assert m.bulkhead("payments") is rec
    assert m.bulkhead_ids() == ("payments",)


def test_isolate_duplicate_and_bad_inputs():
    m = bp.BulkheadPattern()
    m.isolate("a", 1, seq=1)
    with pytest.raises(bp.DuplicateBulkheadError):
        m.isolate("a", 1, seq=2)
    for bad_id in ("", "   ", None, 7):
        with pytest.raises(bp.BulkheadError):
            m.isolate(bad_id, 1, seq=3)
    for bad_cap in (0, -1, True, 1.5, "3", 2**53):
        with pytest.raises(bp.BulkheadError):
            m.isolate(f"cap-{bad_cap}", bad_cap, seq=4)


def test_limit_grant_and_in_flight():
    m = bp.BulkheadPattern()
    m.isolate("db", 2, seq=1)
    g1 = m.limit("db", "r1", seq=2)
    g2 = m.limit("db", "r2", seq=3)
    assert g1.verdict == bp.VERDICT_GRANTED and g1.reason == ""
    assert g2.verdict == bp.VERDICT_GRANTED
    assert g1.verify() and g2.verify()
    assert m.admission("r1") is g1
    assert m.stats()["live"] == 2


def test_limit_rejected_is_data_not_exception():
    m = bp.BulkheadPattern()
    m.isolate("api", 1, seq=1)
    m.limit("api", "r1", seq=2)
    rej = m.limit("api", "r2", seq=3)  # must not raise
    assert rej.verdict == bp.VERDICT_REJECTED
    assert rej.reason == bp.REASON_FULL
    assert rej.verify()
    assert m.stats()["rejected_total"] == 1
    assert m.stats()["live"] == 1  # rejected request occupies no slot


def test_compartments_are_independent():
    m = bp.BulkheadPattern()
    m.isolate("fast", 1, seq=1)
    m.isolate("slow", 1, seq=2)
    m.limit("fast", "r1", seq=3)
    full = m.limit("fast", "r2", seq=4)
    ok = m.limit("slow", "r3", seq=5)
    assert full.verdict == bp.VERDICT_REJECTED
    assert ok.verdict == bp.VERDICT_GRANTED  # saturation of fast is invisible to slow


def test_limit_unknown_bulkhead_and_duplicate_request():
    m = bp.BulkheadPattern()
    with pytest.raises(bp.UnknownBulkheadError):
        m.limit("nope", "r1", seq=1)
    m.isolate("x", 2, seq=2)
    m.limit("x", "r1", seq=3)
    with pytest.raises(bp.DuplicateRequestError):
        m.limit("x", "r1", seq=4)


def test_release_frees_slot_and_record():
    m = bp.BulkheadPattern()
    m.isolate("q", 1, seq=1)
    m.limit("q", "r1", seq=2)
    full = m.limit("q", "r2", seq=3)
    assert full.verdict == bp.VERDICT_REJECTED
    rel = m.release("r1", seq=4)
    assert rel.request_id == "r1" and rel.bulkhead_id == "q"
    assert rel.verify()
    again = m.limit("q", "r3", seq=5)
    assert again.verdict == bp.VERDICT_GRANTED
    assert m.stats()["live"] == 1


def test_release_unknown_or_released_raises():
    m = bp.BulkheadPattern()
    with pytest.raises(bp.UnknownRequestError):
        m.release("ghost", seq=1)
    m.isolate("z", 1, seq=2)
    m.limit("z", "r1", seq=3)
    m.release("r1", seq=4)
    with pytest.raises(bp.UnknownRequestError):  # already released -> not live
        m.release("r1", seq=5)


def test_monitor_pure_view_no_seq_consumption():
    m = bp.BulkheadPattern()
    m.isolate("b", 4, seq=1)
    m.isolate("a", 2, seq=2)
    m.limit("a", "r1", seq=3)
    m.limit("a", "r2", seq=4)
    m.limit("a", "r3", seq=5)  # rejected
    report = m.monitor(seq=4)  # rewind is fine: pure view
    assert report.verify()
    views = {v.bulkhead_id: v for v in report.compartments}
    assert views["a"].in_flight == 2
    assert views["a"].capacity == 2
    assert views["a"].utilization == "2/2"
    assert views["a"].granted_total == 2
    assert views["a"].rejected_total == 1
    assert views["b"].utilization == "0/4"
    assert len(m.audit_log()) == 5  # no audit row for monitor


def test_seq_ordering_and_failed_mutation_consumes_seq():
    m = bp.BulkheadPattern()
    m.isolate("s", 1, seq=1)
    with pytest.raises(bp.SeqOrderError):
        m.isolate("s2", 1, seq=1)  # rewind
    with pytest.raises(bp.BulkheadError):
        m.isolate("s3", 1, seq=True)  # bool refused
    with pytest.raises(bp.DuplicateBulkheadError):
        m.isolate("s", 1, seq=2)  # failed mutation consumes seq 2
    kinds = [e["kind"] for e in m.audit_log()]
    assert kinds.count(bp.KIND_REJECTED) == 1
    assert m.isolate("s2", 1, seq=3).bulkhead_id == "s2"  # seq 2 was burned


def test_audit_shapes_and_bad_kind():
    m = bp.BulkheadPattern()
    m.isolate("aud", 1, seq=1)
    m.limit("aud", "r1", seq=2)
    m.release("r1", seq=3)
    log = m.audit_log()
    assert [e["kind"] for e in log] == [
        bp.KIND_ISOLATED, bp.KIND_ADMITTED, bp.KIND_RELEASED,
    ]
    for e in log:
        assert e["schema"] == "audit.ndjson/1"
        assert e["module"] == "bulkhead_pattern"
        assert e["module_version"] == "bulkhead-pattern.v1"
    with pytest.raises(bp.BulkheadError):
        bp.bulkhead_pattern_audit_event("bogus.kind", 4)


def test_cross_instance_digest_determinism():
    a = bp.BulkheadPattern(seed="s")
    b = bp.BulkheadPattern(seed="s")
    a.isolate("d", 3, seq=1)
    b.isolate("d", 3, seq=1)
    assert a.bulkhead("d").digest == b.bulkhead("d").digest
    assert a.monitor(seq=1).digest == b.monitor(seq=1).digest


def test_unknown_lookups():
    m = bp.BulkheadPattern()
    with pytest.raises(bp.UnknownBulkheadError):
        m.bulkhead("missing")
    with pytest.raises(bp.UnknownRequestError):
        m.admission("missing")


def test_main_subprocess():
    proc = subprocess.run(
        [sys.executable, str(MODULE_PATH)], capture_output=True, text=True
    )
    assert proc.returncode == 0, proc.stderr
    assert "bulkhead-pattern OK" in proc.stdout
