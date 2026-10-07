"""Tests for model_monitoring.py (drift-detection bookkeeping ledger)."""

import ast
import subprocess
import sys
from pathlib import Path

import pytest

import model_monitoring as mm
from model_monitoring import (
    ModelMonitoring,
    model_monitoring_audit_event,
    MODEL_MONITORING_VERSION,
    MODEL_MONITORING_SCHEMA,
    AUDIT_SCHEMA,
    KIND_BASELINE,
    KIND_TRACKED,
    KIND_DRIFT,
    KIND_ALERT,
    KIND_REJECTED,
    ModelMonitoringError,
    BadModelError,
    DuplicateModelError,
    UnknownModelError,
    BadDistributionError,
    DistributionMismatchError,
    BadValueError,
    BadThresholdError,
    BadReasonError,
    DuplicateAlertError,
    SeqOrderError,
    AuditKindError,
)

MODULE = Path(mm.__file__)

GOOD = {"age": [100, 200, 300], "tenure": [150, 250]}
SHIFTED = {"age": [300, 200, 100], "tenure": [150, 250]}


def fresh(seq_start=1):
    return ModelMonitoring(), seq_start


# ---------------------------------------------------------------------------


def test_version_and_schema_pins():
    assert MODEL_MONITORING_VERSION == "model-monitoring.v1"
    assert MODEL_MONITORING_SCHEMA == "northstar.model-monitoring.v1"
    assert AUDIT_SCHEMA == "audit.ndjson/1"


def test_stdlib_only():
    tree = ast.parse(MODULE.read_text())
    allowed = {
        "hashlib",
        "math",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
        "canonical_json",
        "json",
    }
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module.split(".")[0])
    assert imports <= allowed, f"non-stdlib imports: {imports - allowed}"


def test_baseline_roundtrip():
    m = ModelMonitoring()
    rec = m.baseline("churn-v3", GOOD, 1)
    assert rec.model_id == "churn-v3"
    assert rec.seq == 1
    assert rec.digest.startswith("sha256:")
    assert rec.verify()
    assert rec.schema == MODEL_MONITORING_SCHEMA
    assert m.model_ids(1) == ("churn-v3",)
    view = m.baseline_record("churn-v3", 1)
    assert view == rec
    assert m.baseline_record("nope", 1) is None
    with pytest.raises(Exception):
        rec.model_id = "x"  # frozen


def test_baseline_duplicate_and_bad_inputs():
    m = ModelMonitoring()
    m.baseline("m1", GOOD, 1)
    # duplicate consumes its seq and books a rejection
    with pytest.raises(DuplicateModelError):
        m.baseline("m1", GOOD, 2)
    kinds = [e["kind"] for e in m.audit_log()]
    assert kinds[-1] == KIND_REJECTED
    # bad ids / distributions; each failure consumes its seq
    bad_ids = ["", "x" * 300, 123, True, None]
    s = 3
    for bad in bad_ids:
        with pytest.raises(ModelMonitoringError):
            m.baseline(bad, GOOD, s)
        s += 1
    bad_dists = [
        {},
        [],
        "nope",
        {"age": []},
        {"age": [0, 0]},
        {"age": [1, -2]},
        {"age": [1, True]},
        {"age": [1, 1.5]},
        {123: [1, 2]},
        {"": [1, 2]},
        {"age": [2**54]},
    ]
    for bad in bad_dists:
        with pytest.raises(BadDistributionError):
            m.baseline(f"bad-{s}", bad, s)
        s += 1


def test_track_roundtrip():
    m = ModelMonitoring()
    m.baseline("m1", GOOD, 1)
    rec = m.track("m1", "accuracy", 0.91, 2)
    assert rec.model_id == "m1"
    assert rec.metric == "accuracy"
    assert rec.value == 0.91
    assert rec.verify()
    assert rec.metric_id == "track-1"
    hist = m.metric_history("m1", 2)
    assert hist == (rec,)
    m.track("m1", "f1", 0.75, 3)
    assert len(m.metric_history("m1", 3)) == 2
    assert m.metric_history("other", 3) == ()


def test_track_bad_inputs():
    m = ModelMonitoring()
    m.baseline("m1", GOOD, 1)
    with pytest.raises(UnknownModelError):
        m.track("ghost", "accuracy", 0.9, 2)
    bad = [
        ("m1", "", 0.9),
        ("m1", 123, 0.9),
        ("m1", "accuracy", True),
        ("m1", "accuracy", float("nan")),
        ("m1", "accuracy", float("inf")),
        ("m1", "accuracy", 2**54),
        ("m1", "accuracy", "high"),
    ]
    s = 3
    for model_id, metric, value in bad:
        with pytest.raises(ModelMonitoringError):
            m.track(model_id, metric, value, s)
        s += 1


def test_drift_no_drift():
    m = ModelMonitoring()
    m.baseline("m1", GOOD, 1)
    report = m.drift("m1", GOOD, 2)
    assert report.verify()
    assert not report.verdict
    assert report.max_psi == 0.0
    assert report.drifted_features == ()
    assert [f for f, _ in report.feature_psi] == ["age", "tenure"]
    assert all(psi == 0.0 for _, psi in report.feature_psi)
    hist = m.drift_history("m1", 2)
    assert hist == (report,)


def test_drift_detected():
    m = ModelMonitoring()
    m.baseline("m1", GOOD, 1)
    report = m.drift("m1", SHIFTED, 2)
    assert report.verify()
    assert report.verdict
    assert report.drifted_features == ("age",)
    assert report.max_psi > 0.25
    # deterministic across instances
    m2 = ModelMonitoring()
    m2.baseline("m1", GOOD, 1)
    report2 = m2.drift("m1", SHIFTED, 2)
    assert report2.feature_psi == report.feature_psi
    assert report2.digest == report.digest
    # custom threshold: high threshold suppresses the verdict
    calm = m.drift("m1", SHIFTED, 3, threshold=10.0)
    assert not calm.verdict


def test_drift_bad_inputs():
    m = ModelMonitoring()
    m.baseline("m1", GOOD, 1)
    with pytest.raises(UnknownModelError):
        m.drift("ghost", GOOD, 2)
    with pytest.raises(DistributionMismatchError):
        m.drift("m1", {"age": [100, 200, 300]}, 3)  # missing feature
    with pytest.raises(DistributionMismatchError):
        m.drift("m1", {"age": [100, 200], "tenure": [150, 250]}, 4)  # bin count changed
    with pytest.raises(BadDistributionError):
        m.drift("m1", {}, 5)
    s = 6
    for bad in (0, -1, True, float("nan"), float("inf"), "0.25"):
        with pytest.raises(BadThresholdError):
            m.drift("m1", GOOD, s, threshold=bad)
        s += 1


def test_alert_roundtrip():
    m = ModelMonitoring()
    m.baseline("m1", GOOD, 1)
    rec = m.alert("a-1", "m1", "data-drift", 2)
    assert rec.alert_id == "a-1"
    assert rec.reason == "data-drift"
    assert rec.verify()
    assert m.alerts_for("m1", 2) == (rec,)
    m.alert("a-2", "m1", "manual", 3)
    assert len(m.alerts_for("m1", 3)) == 2


def test_alert_bad_inputs():
    m = ModelMonitoring()
    m.baseline("m1", GOOD, 1)
    with pytest.raises(UnknownModelError):
        m.alert("a-1", "ghost", "data-drift", 2)
    m.alert("dup", "m1", "data-drift", 3)  # first booking succeeds
    with pytest.raises(DuplicateAlertError):
        m.alert("dup", "m1", "data-drift", 4)
    with pytest.raises(DuplicateAlertError):
        m.alert("dup", "m1", "data-drift", 5)
    with pytest.raises(BadReasonError):
        m.alert("a-2", "m1", "the-sky-is-falling", 6)
    s = 7
    for bad in ("", 123, True, None):
        with pytest.raises(ModelMonitoringError):
            m.alert(bad, "m1", "manual", s)
        s += 1


def test_seq_ordering():
    m = ModelMonitoring()
    m.baseline("m1", GOOD, 1)
    # rewind raises bare without consuming
    with pytest.raises(SeqOrderError):
        m.baseline("m2", GOOD, 1)
    m.baseline("m2", GOOD, 2)  # seq 2 still fresh
    with pytest.raises(SeqOrderError):
        m.track("m1", "accuracy", 0.9, 2)
    # malformed seqs
    for bad in (True, "3", 1.5, None):
        with pytest.raises(SeqOrderError):
            m.track("m1", "accuracy", 0.9, bad)
    # failed mutations consume their seq (then a rewind is refused)
    with pytest.raises(BadModelError):
        m.track("m1", "", 0.9, 3)
    with pytest.raises(SeqOrderError):
        m.track("m1", "accuracy", 0.9, 3)


def test_audit_shapes_and_leak_ban():
    m = ModelMonitoring()
    m.baseline("m1", GOOD, 1)
    m.track("m1", "accuracy", 0.91, 2)
    m.drift("m1", SHIFTED, 3)
    m.alert("a-1", "m1", "data-drift", 4)
    kinds = [e["kind"] for e in m.audit_log()]
    assert kinds == [KIND_BASELINE, KIND_TRACKED, KIND_DRIFT, KIND_ALERT]
    for e in m.audit_log():
        assert e["schema"] == AUDIT_SCHEMA
        assert e["module"] == "model_monitoring"
        assert e["digest"].startswith("sha256:")
        for k in ("value", "distribution", "candidate", "payload", "raw"):
            assert k not in e["detail"], f"leak: {k}"
    # banned keys and bad kinds refused at the boundary
    with pytest.raises(AuditKindError):
        model_monitoring_audit_event(KIND_TRACKED, 9, model_id="m1", value=0.9)
    with pytest.raises(AuditKindError):
        model_monitoring_audit_event("nope", 9)


def test_views_read_purity():
    m = ModelMonitoring()
    m.baseline("m1", GOOD, 1)
    n = len(m.audit_log())
    # views validate shape, consume nothing, write no audit rows
    assert m.stats(0)["models"] == 1  # rewind allowed on views
    assert m.model_ids(1) == ("m1",)
    assert m.baseline_record("m1", 1) is not None
    assert m.metric_history("m1", 1) == ()
    assert len(m.audit_log()) == n
    # malformed seqs still refused on views
    with pytest.raises(SeqOrderError):
        m.stats("x")
    stats = m.stats(1)
    assert stats["metrics"] == 0 and stats["drift_checks"] == 0
    assert stats["alerts"] == 0 and stats["last_seq"] == 1


def test_main_self_check():
    r = subprocess.run(
        [sys.executable, str(MODULE)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert r.returncode == 0, r.stderr
    assert "model-monitoring OK" in r.stdout
