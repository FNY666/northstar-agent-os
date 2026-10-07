"""Tests for mesa_optimization.py: mesa-optimizer detection / constraint ledger."""

import ast
import subprocess
import sys
from pathlib import Path

import pytest

import mesa_optimization as mo
from mesa_optimization import (
    AUDIT_SCHEMA,
    MESA_OPTIMIZATION_SCHEMA,
    MESA_OPTIMIZATION_VERSION,
    AuditKindError,
    BadBehaviorError,
    BadConstraintError,
    BadDigestError,
    BadMesaError,
    BadSeverityError,
    DuplicateMesaError,
    MesaOptimization,
    MesaOptimizationError,
    SeqOrderError,
    UnknownDetectionError,
    UnknownMesaError,
    mesa_optimization_audit_event,
)

MODULE = Path(mo.__file__).parent / "mesa_optimization.py"
DIGEST = "sha256:" + "ab" * 32


def _ledger() -> MesaOptimization:
    return MesaOptimization()


def test_version_and_schema_pins():
    assert MESA_OPTIMIZATION_VERSION == "mesa-optimization.v1"
    assert MESA_OPTIMIZATION_SCHEMA == "northstar.mesa-optimization.v1"
    assert AUDIT_SCHEMA == "audit.ndjson/1"


def test_stdlib_only():
    tree = ast.parse(MODULE.read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module.split(".")[0])
    allowed = {
        "hashlib",
        "threading",
        "dataclasses",
        "typing",
        "json",
        "canonical_json",
        "__future__",
    }
    assert imported <= allowed, f"non-stdlib imports: {imported - allowed}"


def test_register_roundtrip_and_verify():
    led = _ledger()
    rec = led.register("mesa-1", 1, objective_digest=DIGEST)
    assert rec.mesa_id == "mesa-1"
    assert rec.objective_digest == DIGEST
    assert rec.verify()
    assert led.mesa("mesa-1", 2) == rec
    assert led.mesa_ids(3) == ("mesa-1",)
    as_dict = rec.as_dict()
    assert as_dict["schema"] == MESA_OPTIMIZATION_SCHEMA
    assert as_dict["version"] == MESA_OPTIMIZATION_VERSION


def test_register_bad_inputs_burn_seq_and_book_rejected():
    led = _ledger()
    bad_ids = ["", "x" * 300, 0, None, True, b"mesa"]
    seq = 1
    for bad in bad_ids:
        with pytest.raises(MesaOptimizationError):
            led.register(bad, seq)
        seq += 1
    # bad objective digest burns seq too
    with pytest.raises(BadDigestError):
        led.register("mesa-2", seq, objective_digest="not-a-digest")
    rows = led.audit_log()
    kinds = [r["kind"] for r in rows]
    assert kinds.count("mesa-optimization.rejected") == len(bad_ids) + 1
    # next good call continues at the unconsumed seq frontier
    rec = led.register("mesa-ok", seq + 1)
    assert rec.seq == seq + 1


def test_register_duplicate_and_unknown_mesa():
    led = _ledger()
    led.register("mesa-1", 1)
    with pytest.raises(DuplicateMesaError):
        led.register("mesa-1", 2)
    with pytest.raises(UnknownMesaError):
        led.detect("mesa-missing", "goal-divergence", 3)


def test_detect_roundtrip_and_verify():
    led = _ledger()
    led.register("mesa-1", 1)
    det = led.detect("mesa-1", "goal-divergence", 2, severity="high",
                     evidence_digest=DIGEST)
    assert det.detection_id == "mesa-det-1"
    assert det.behavior == "goal-divergence"
    assert det.severity == "high"
    assert det.verify()
    assert led.detection(det.detection_id, 3) == det
    assert led.detection_ids(4) == ("mesa-det-1",)
    as_dict = det.as_dict()
    assert as_dict["mesa_id"] == "mesa-1"


def test_detect_bad_inputs():
    led = _ledger()
    led.register("mesa-1", 1)
    with pytest.raises(BadBehaviorError):
        led.detect("mesa-1", "not-a-behavior", 2)
    with pytest.raises(BadSeverityError):
        led.detect("mesa-1", "goal-divergence", 3, severity="extreme")
    with pytest.raises(BadDigestError):
        led.detect("mesa-1", "goal-divergence", 4, evidence_digest="junk")
    # all eight pinned behaviors are accepted
    for i, beh in enumerate(sorted(mo._BEHAVIORS)):
        led.detect("mesa-1", beh, 5 + i)
    assert led.stats(13)["detections"] == 8


def test_seq_discipline():
    led = _ledger()
    led.register("mesa-1", 1)
    # rewind raises bare: no seq consumption, no rejected audit row
    with pytest.raises(SeqOrderError):
        led.register("mesa-2", 1)
    assert led.stats(100)["next_seq"] == 2
    assert led.audit_log() == (led.audit_log()[0],) or all(
        r["kind"] != "mesa-optimization.rejected" for r in led.audit_log()
    )
    # malformed seqs
    for bad in (True, "3", 3.5, None):
        with pytest.raises(SeqOrderError):
            led.register("mesa-x", bad)


def test_constrain_roundtrip_and_verify():
    led = _ledger()
    led.register("mesa-1", 1)
    det = led.detect("mesa-1", "reward-hacking", 2)
    con = led.constrain(det.detection_id, 3, "human-review", reason_digest=DIGEST)
    assert con.constraint_id == "mesa-con-1"
    assert con.constraint == "human-review"
    assert con.verify()
    assert led.is_constrained(det.detection_id, 4)
    assert led.constraints_for(det.detection_id, 5) == (con,)
    assert not led.is_constrained("mesa-det-9", 6)


def test_constrain_unknown_detection_and_bad_inputs():
    led = _ledger()
    with pytest.raises(UnknownDetectionError):
        led.constrain("mesa-det-1", 1, "sandbox")
    led.register("mesa-1", 2)
    det = led.detect("mesa-1", "goal-divergence", 3)
    with pytest.raises(BadConstraintError):
        led.constrain(det.detection_id, 4, "nuke")
    with pytest.raises(BadDigestError):
        led.constrain(det.detection_id, 5, "sandbox", reason_digest="junk")


def test_constrain_escalation_chain():
    led = _ledger()
    led.register("mesa-1", 1)
    det = led.detect("mesa-1", "deceptive-reasoning", 2)
    c1 = led.constrain(det.detection_id, 3, "sandbox")
    c2 = led.constrain(det.detection_id, 4, "capability-restrict")
    c3 = led.constrain(det.detection_id, 5, "discard")
    ids = [c.constraint_id for c in led.constraints_for(det.detection_id, 6)]
    assert ids == ["mesa-con-1", "mesa-con-2", "mesa-con-3"]
    assert (c1, c2, c3) != ()


def test_monitor_report_contents_and_purity():
    led = _ledger()
    led.register("mesa-1", 1)
    led.register("mesa-2", 2)
    d1 = led.detect("mesa-1", "goal-divergence", 3, severity="critical")
    led.detect("mesa-2", "reward-hacking", 4, severity="low")
    rep = led.monitor(5)
    assert rep.verify()
    assert rep.mesa_count == 2
    assert rep.detection_count == 2
    assert rep.constraint_count == 0
    sev = dict(rep.by_severity)
    assert sev["critical"] == 1 and sev["low"] == 1
    beh = dict(rep.by_behavior)
    assert beh["goal-divergence"] == 1 and beh["reward-hacking"] == 1
    assert rep.open_detection_ids == ("mesa-det-1", "mesa-det-2")
    # pure read: same seq twice, no audit rows, no seq consumption
    before = len(led.audit_log())
    rep2 = led.monitor(5)
    assert rep2 == rep
    assert len(led.audit_log()) == before
    led.constrain(d1.detection_id, 6, "escalate")
    rep3 = led.monitor(7)
    assert rep3.open_detection_ids == ("mesa-det-2",)
    assert dict(rep3.by_constraint)["escalate"] == 1


def test_audit_shapes_leak_ban_and_bad_kind():
    led = _ledger()
    led.register("mesa-1", 1, objective_digest=DIGEST)
    det = led.detect("mesa-1", "hidden-objective", 2, evidence_digest=DIGEST)
    led.constrain(det.detection_id, 3, "retrain", reason_digest=DIGEST)
    log = led.audit_log()
    assert [r["kind"] for r in log] == [
        "mesa-optimization.registered",
        "mesa-optimization.detected",
        "mesa-optimization.constrained",
    ]
    for row in log:
        assert row["schema"] == AUDIT_SCHEMA
        assert row["module"] == MESA_OPTIMIZATION_VERSION
    # raw text never crosses the audit boundary: digests only
    for banned in ("objective", "evidence", "justification", "payload"):
        for row in log:
            assert banned not in row["detail"], f"banned key {banned} leaked"
    with pytest.raises(AuditKindError):
        mesa_optimization_audit_event("mesa-optimization.bogus", 1)
    with pytest.raises(AuditKindError):
        mesa_optimization_audit_event("mesa-optimization.detected", 1,
                                      justification="raw text must not cross")


def test_cross_instance_determinism():
    def build():
        led = _ledger()
        led.register("mesa-1", 1, objective_digest=DIGEST)
        det = led.detect("mesa-1", "goal-divergence", 2, severity="high")
        con = led.constrain(det.detection_id, 3, "regularize")
        return det.digest, con.digest, led.monitor(4).digest

    assert build() == build()


def test_stats_and_views():
    led = _ledger()
    led.register("mesa-1", 1)
    st = led.stats(2)
    assert st["mesas"] == 1 and st["detections"] == 0 and st["constraints"] == 0
    assert st["next_seq"] == 2 and st["audit_rows"] == 1
    assert led.mesa("nope", 3) is None
    assert led.detection("mesa-det-9", 4) is None


def test_main_subprocess():
    proc = subprocess.run(
        [sys.executable, str(MODULE)],
        capture_output=True,
        text=True,
        cwd=str(MODULE.parent),
    )
    assert proc.returncode == 0, proc.stderr
    assert "mesa-optimization OK" in proc.stdout
