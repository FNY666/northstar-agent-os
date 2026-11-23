"""Tests for lb_health: backend registration, probe outcomes, drain/restore."""

import ast
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from lb_health import (
    LBHealth,
    LBHealthError,
    UnknownBackendError,
    DuplicateBackendError,
    BadBackendError,
    BadOutcomeError,
    AlreadyDrainedError,
    NotDrainedError,
    SeqOrderError,
    LB_HEALTH_VERSION,
    LB_HEALTH_SCHEMA,
    AUDIT_SCHEMA,
    OUTCOMES,
    lb_health_audit_event,
)


def fresh(**kw):
    return LBHealth(**kw)


# 1 -------------------------------------------------------------------------


def test_version_pins():
    assert LB_HEALTH_VERSION == "lb-health.v1"
    assert LB_HEALTH_SCHEMA == "northstar.lb-health.v1"
    assert AUDIT_SCHEMA == "audit.ndjson/1"
    assert OUTCOMES == ("healthy", "unhealthy")


def test_stdlib_only_ast():
    path = os.path.join(os.path.dirname(__file__), "..", "lb_health.py")
    with open(path) as fh:
        tree = ast.parse(fh.read())
    allowed = {
        "hashlib", "threading", "dataclasses", "typing", "json",
        "canonical_json", "__future__",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


def test_main_selfcheck():
    import subprocess

    path = os.path.join(os.path.dirname(__file__), "..", "lb_health.py")
    out = subprocess.run(
        [sys.executable, path], capture_output=True, text=True, timeout=30
    )
    assert out.returncode == 0, out.stderr
    assert "lb-health OK" in out.stdout


# 2 -------------------------------------------------------------------------


def test_register_roundtrip():
    lb = fresh()
    rec = lb.register_backend("web-1", "10.0.0.1:8080", 1, weight=3)
    assert rec.verify()
    assert rec.backend_id == "web-1"
    assert rec.address == "10.0.0.1:8080"
    assert rec.weight == 3
    assert lb.backend("web-1") == rec
    assert lb.health_state("web-1") == "healthy"
    assert lb.backend_ids() == ("web-1",)


def test_register_duplicate():
    lb = fresh()
    lb.register_backend("web-1", "10.0.0.1:8080", 1)
    with pytest.raises(DuplicateBackendError):
        lb.register_backend("web-1", "10.0.0.9:8080", 2)


@pytest.mark.parametrize(
    "backend_id,address,weight",
    [
        ("", "10.0.0.1:8080", 1),
        ("  ", "10.0.0.1:8080", 1),
        ("web-1", "", 1),
        ("web-1", "noport", 1),
        ("web-1", ":8080", 1),
        ("web-1", "10.0.0.1:0", 1),
        ("web-1", "10.0.0.1:99999", 1),
        ("web-1", "10.0.0.1:notaport", 1),
        ("web-1", "10.0.0.1:8080", 0),
        ("web-1", "10.0.0.1:8080", -2),
        ("web-1", "10.0.0.1:8080", True),
        ("web-1", "10.0.0.1:8080", 1.5),
    ],
)
def test_register_bad_inputs(backend_id, address, weight):
    lb = fresh()
    with pytest.raises(LBHealthError):
        lb.register_backend(backend_id, address, 1, weight=weight)


def test_constructor_bad_thresholds():
    with pytest.raises(LBHealthError):
        LBHealth(fail_threshold=0)
    with pytest.raises(LBHealthError):
        LBHealth(success_threshold=True)


# 3 -------------------------------------------------------------------------


def test_check_roundtrip():
    lb = fresh()
    lb.register_backend("web-1", "10.0.0.1:8080", 1)
    rec = lb.check("web-1", 2, "healthy")
    assert rec.verify()
    assert rec.check_id == "chk-1"
    assert rec.outcome == "healthy"
    assert rec.state == "healthy"
    assert rec.consecutive_healthy == 1
    assert rec.consecutive_unhealthy == 0


def test_check_unknown_backend():
    lb = fresh()
    with pytest.raises(UnknownBackendError):
        lb.check("ghost", 1, "healthy")


def test_check_bad_outcome():
    lb = fresh()
    lb.register_backend("web-1", "10.0.0.1:8080", 1)
    with pytest.raises(BadOutcomeError):
        lb.check("web-1", 2, "flapping")
    with pytest.raises(BadOutcomeError):
        lb.check("web-1", 3, "")


def test_fail_threshold_flip():
    lb = fresh(fail_threshold=3)
    lb.register_backend("web-1", "10.0.0.1:8080", 1)
    assert lb.check("web-1", 2, "unhealthy").state == "healthy"
    assert lb.check("web-1", 3, "unhealthy").state == "healthy"
    rec = lb.check("web-1", 4, "unhealthy")
    assert rec.state == "unhealthy"
    assert lb.health_state("web-1") == "unhealthy"


def test_success_threshold_recover():
    lb = fresh(fail_threshold=2, success_threshold=2)
    lb.register_backend("web-1", "10.0.0.1:8080", 1)
    lb.check("web-1", 2, "unhealthy")
    lb.check("web-1", 3, "unhealthy")
    assert lb.health_state("web-1") == "unhealthy"
    lb.check("web-1", 4, "healthy")
    assert lb.health_state("web-1") == "unhealthy"
    rec = lb.check("web-1", 5, "healthy")
    assert rec.state == "healthy"
    assert rec.consecutive_unhealthy == 0


def test_counters_reset_on_flip():
    lb = fresh(fail_threshold=2, success_threshold=2)
    lb.register_backend("web-1", "10.0.0.1:8080", 1)
    lb.check("web-1", 2, "unhealthy")
    rec = lb.check("web-1", 3, "healthy")
    assert rec.consecutive_unhealthy == 0
    assert rec.consecutive_healthy == 1
    assert lb.health_state("web-1") == "healthy"


# 4 -------------------------------------------------------------------------


def test_drain_roundtrip():
    lb = fresh()
    lb.register_backend("web-1", "10.0.0.1:8080", 1)
    rec = lb.drain("web-1", 2, "deploys in flight")
    assert rec.verify()
    assert lb.health_state("web-1") == "draining"
    assert lb.drained_ids() == ("web-1",)
    assert lb.pool(2).backends == ()


def test_drain_unknown():
    lb = fresh()
    with pytest.raises(UnknownBackendError):
        lb.drain("ghost", 1, "nope")


def test_drain_double_refusal():
    lb = fresh()
    lb.register_backend("web-1", "10.0.0.1:8080", 1)
    lb.drain("web-1", 2, "first")
    with pytest.raises(AlreadyDrainedError):
        lb.drain("web-1", 3, "second")


def test_restore_roundtrip():
    lb = fresh()
    lb.register_backend("web-1", "10.0.0.1:8080", 1)
    lb.drain("web-1", 2, "rolling restart")
    rec = lb.restore("web-1", 3)
    assert rec.verify()
    assert lb.health_state("web-1") == "healthy"
    assert lb.drained_ids() == ()
    assert dict(lb.pool(3).backends) == {"web-1": 1}


def test_restore_not_drained():
    lb = fresh()
    lb.register_backend("web-1", "10.0.0.1:8080", 1)
    with pytest.raises(NotDrainedError):
        lb.restore("web-1", 2)


def test_check_while_drained_accumulates():
    lb = fresh(fail_threshold=2)
    lb.register_backend("web-1", "10.0.0.1:8080", 1)
    lb.drain("web-1", 2, "maintenance")
    rec = lb.check("web-1", 3, "unhealthy")
    assert rec.state == "draining"  # drain masks, counters still move
    assert rec.consecutive_unhealthy == 1
    lb.check("web-1", 4, "unhealthy")
    lb.restore("web-1", 5)
    # Counters survived the drain, so the backend is unhealthy after restore.
    assert lb.health_state("web-1") == "unhealthy"
    assert lb.pool(5).backends == ()


# 5 -------------------------------------------------------------------------


def test_pool_eligibility():
    lb = fresh(fail_threshold=1)
    lb.register_backend("ok", "10.0.0.1:80", 1, weight=5)
    lb.register_backend("sick", "10.0.0.2:80", 2, weight=2)
    lb.register_backend("gone", "10.0.0.3:80", 3, weight=1)
    lb.check("sick", 4, "unhealthy")
    lb.drain("gone", 5, "retired")
    report = lb.pool(5)
    assert report.verify()
    assert report.backends == (("ok", 5),)


def test_pool_is_pure_read():
    lb = fresh()
    lb.register_backend("web-1", "10.0.0.1:8080", 1)
    lb.pool(99)  # validates shape, consumes nothing
    # A mutation can still claim seq 2 (pool did not move the ledger).
    lb.register_backend("web-2", "10.0.0.2:8080", 2)
    assert lb.backend_ids() == ("web-1", "web-2")


def test_health_state_unknown():
    lb = fresh()
    with pytest.raises(UnknownBackendError):
        lb.health_state("ghost")


# 6 -------------------------------------------------------------------------


def test_seq_ordering():
    lb = fresh()
    lb.register_backend("web-1", "10.0.0.1:8080", 1)
    with pytest.raises(SeqOrderError):
        lb.check("web-1", 1, "healthy")  # rewind
    with pytest.raises(SeqOrderError):
        lb.check("web-1", True, "healthy")  # bool
    with pytest.raises(SeqOrderError):
        lb.drain("web-1", -1, "bad")
    with pytest.raises(SeqOrderError):
        lb.pool("2")  # non-int on a pure view


def test_failed_mutation_consumes_seq():
    lb = fresh()
    lb.register_backend("web-1", "10.0.0.1:8080", 1)
    with pytest.raises(DuplicateBackendError):
        lb.register_backend("web-1", "10.0.0.9:8080", 2)
    # seq 2 was burned by the refusal; seq 2 now rewinds.
    with pytest.raises(SeqOrderError):
        lb.check("web-1", 2, "healthy")


def test_audit_shapes():
    lb = fresh()
    lb.register_backend("web-1", "10.0.0.1:8080", 1)
    lb.check("web-1", 2, "healthy")
    lb.drain("web-1", 3, "restart")
    lb.restore("web-1", 4)
    log = lb.audit_log()
    kinds = [e["kind"] for e in log]
    assert kinds == [
        "lb-health.backend-registered",
        "lb-health.checked",
        "lb-health.drained",
        "lb-health.restored",
    ]
    for e in log:
        assert e["schema"] == AUDIT_SCHEMA
        assert e["module"] == LB_HEALTH_VERSION
    assert log[1]["detail"]["state"] == "healthy"
    with pytest.raises(LBHealthError):
        lb_health_audit_event("nope", {}, 9)
    with pytest.raises(LBHealthError):
        lb_health_audit_event("lb-health.checked", {"outcomes": []}, 9)
