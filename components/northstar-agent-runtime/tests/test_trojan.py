"""Tests for the trojan test/detect decision ledger (Simulated)."""

import ast
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "trojan.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("trojan", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["trojan"] = module
    spec.loader.exec_module(module)
    return module


td = _load()


def _target(t, name="target-1", seq=1):
    return t.register_target(name, seq, target_digest=PIN)


def _test(t, target_id="target-1", seq=2, **kw):
    return t.test(target_id, seq, **kw)


def _detect(t, target_id, test_id, seq, **kw):
    return t.detect(target_id, test_id, seq, **kw)


# 1. version/schema pins
def test_version_and_schema_pins():
    assert td.TROJAN_VERSION == "trojan.v1"
    assert td.SCHEMA_PIN == "northstar.trojan.v1"
    assert td.TEST_KINDS == (
        "trigger-probe",
        "behavioral-delta",
        "activation-sweep",
        "poison-audit",
        "sleeper-probe",
        "fine-tune-stress",
    )
    assert td.TEST_OUTCOMES == ("triggered", "clean", "inconclusive",
                                "anomalous")
    assert td.DETECTORS == (
        "activation-clustering",
        "neural-cleanse",
        "spectral-signatures",
        "fine-pruning-probe",
        "weight-inspection",
        "ensemble-vote",
    )
    assert td.DETECTION_VERDICTS == ("infected", "suspect", "clean",
                                    "inconclusive")
    assert td.MEASURES == ("isolate", "retrain", "prune", "rollback",
                          "decommission", "monitor")
    assert td.RETIRE_REASONS == ("manual", "decommissioned", "superseded",
                                 "withdrawn")


# 2. stdlib-only AST check
def test_stdlib_only():
    tree = ast.parse(MOD.read_text())
    allowed = {
        "hashlib",
        "json",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
        "canonical_json",
    }
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    assert imports <= allowed, imports - allowed


# 3. register_target roundtrip
def test_register_target_roundtrip():
    t = td.Trojan()
    rec = t.register_target("target-1", 1, target_digest=PIN)
    assert rec.target_id == "target-1"
    assert rec.target_digest == PIN
    assert rec.verify()
    assert t.target_record("target-1", 0).verify()
    assert t.target_ids(0) == ("target-1",)
    assert not t.is_retired("target-1", 0)


# 4. register_target bad inputs + duplicate + seq burn + rejected rows
def test_register_target_bad_inputs():
    t = td.Trojan()
    t.register_target("t", 1, target_digest=PIN)
    with pytest.raises(td.DuplicateTargetError):
        t.register_target("t", 2, target_digest=PIN)
    for bad_id in ("", None, 123, "x" * 129):
        g = td.Trojan()
        with pytest.raises(td.BadTargetError):
            g.register_target(bad_id, 1, target_digest=PIN)
    g = td.Trojan()
    with pytest.raises(td.BadDigestError):
        g.register_target("t", 1, target_digest="not-a-pin")
    # rejected row booked and seq consumed on the failure
    rows = g.audit_log(0)
    assert any(r["kind"] == "rejected" for r in rows)
    # duplicate burns seq too: internal seq advanced past the failed call
    assert t.stats(0)["seq"] == 2


# 5. test roundtrip across all test kinds + minted ids + verify()
def test_test_roundtrip_all_kinds():
    t = td.Trojan()
    _target(t)
    seq = 2
    for i, kind in enumerate(td.TEST_KINDS):
        rec = t.test("target-1", seq, test_kind=kind, outcome="clean",
                     evidence_digest=PIN2)
        assert rec.test_id == f"tst-{i + 1}"
        assert rec.target_id == "target-1"
        assert rec.test_kind == kind
        assert rec.verify()
        assert t.test_record(rec.test_id, 0).verify()
        seq += 1
    assert len(t.test_ids(0)) == 6
    assert t.tests_for("target-1", 0) == tuple(f"tst-{i + 1}" for i in range(6))


# 6. test bad inputs: unknown target / bad kind / bad outcome / bad digest
def test_test_bad_inputs():
    t = td.Trojan()
    _target(t)
    with pytest.raises(td.UnknownTargetError):
        t.test("nope", 2)
    with pytest.raises(td.BadTestKindError):
        t.test("target-1", 3, test_kind="nope")
    with pytest.raises(td.BadOutcomeError):
        t.test("target-1", 4, outcome="nope")
    with pytest.raises(td.BadDigestError):
        t.test("target-1", 5, evidence_digest="junk")
    rows = t.audit_log(0)
    assert sum(1 for r in rows if r["kind"] == "rejected") == 4
    assert t.test_ids(0) == ()


# 7. detect roundtrip across all detectors + minted ids + all verdicts
def test_detect_roundtrip_all_detectors():
    t = td.Trojan()
    _target(t)
    tst = t.test("target-1", 2)
    seq = 3
    for i, detector in enumerate(td.DETECTORS):
        verdict = td.DETECTION_VERDICTS[i % len(td.DETECTION_VERDICTS)]
        rec = t.detect("target-1", tst.test_id, seq, detector=detector,
                       verdict=verdict, evidence_digest=PIN2)
        assert rec.detection_id == f"det-{i + 1}"
        assert rec.test_id == tst.test_id
        assert rec.detector == detector
        assert rec.verdict == verdict
        assert rec.verify()
        assert t.detection_record(rec.detection_id, 0).verify()
        seq += 1
    assert len(t.detection_ids(0)) == 6
    assert t.detections_for("target-1", 0) == tuple(
        f"det-{i + 1}" for i in range(6))


# 8. detect bad inputs: unknown target / unknown test / cross-target test /
#    bad detector / bad verdict / bad digest
def test_detect_bad_inputs():
    t = td.Trojan()
    _target(t, "a", 1)
    _target(t, "b", 2)
    tst_a = t.test("a", 3)
    with pytest.raises(td.UnknownTargetError):
        t.detect("nope", tst_a.test_id, 4)
    with pytest.raises(td.UnknownTestError):
        t.detect("a", "tst-999", 5)
    with pytest.raises(td.DetectionStateError):
        t.detect("b", tst_a.test_id, 6)
    with pytest.raises(td.BadDetectorError):
        t.detect("a", tst_a.test_id, 7, detector="nope")
    with pytest.raises(td.BadVerdictError):
        t.detect("a", tst_a.test_id, 8, verdict="nope")
    with pytest.raises(td.BadDigestError):
        t.detect("a", tst_a.test_id, 9, evidence_digest="junk")
    rows = t.audit_log(0)
    assert sum(1 for r in rows if r["kind"] == "rejected") == 6
    assert t.detection_ids(0) == ()


# 9. mitigate roundtrip across all measures + minted ids + one per detection
def test_mitigate_roundtrip_all_measures():
    t = td.Trojan()
    _target(t)
    seq = 2
    for i, measure in enumerate(td.MEASURES):
        tst = t.test("target-1", seq, outcome="triggered")
        seq += 1
        det = t.detect("target-1", tst.test_id, seq, verdict="infected")
        seq += 1
        rec = t.mitigate(det.detection_id, seq, measure=measure,
                         plan_digest=PIN2)
        assert rec.mitigation_id == f"mit-{i + 1}"
        assert rec.detection_id == det.detection_id
        assert rec.measure == measure
        assert rec.verify()
        assert t.mitigation_record(rec.mitigation_id, 0).verify()
        seq += 1
    assert len(t.mitigated_detection_ids(0)) == 6


# 10. mitigate refusals: unknown detection / clean verdict / double /
#     bad measure
def test_mitigate_refusals():
    t = td.Trojan()
    _target(t)
    tst = t.test("target-1", 2)
    det_clean = t.detect("target-1", tst.test_id, 3, verdict="clean")
    with pytest.raises(td.UnknownDetectionError):
        t.mitigate("det-999", 4)
    with pytest.raises(td.DetectionStateError):
        t.mitigate(det_clean.detection_id, 5)
    tst2 = t.test("target-1", 6, outcome="triggered")
    det_inf = t.detect("target-1", tst2.test_id, 7, verdict="suspect")
    with pytest.raises(td.BadMeasureError):
        t.mitigate(det_inf.detection_id, 8, measure="nope")
    m = t.mitigate(det_inf.detection_id, 9, measure="isolate")
    assert m.verify()
    with pytest.raises(td.AlreadyMitigatedError):
        t.mitigate(det_inf.detection_id, 10, measure="retrain")
    rows = t.audit_log(0)
    assert sum(1 for r in rows if r["kind"] == "rejected") == 4


# 11. retire terminality: mutations refused, reads still work, id never
#     recycled, bad reason
def test_retire_terminality():
    t = td.Trojan()
    _target(t)
    tst = t.test("target-1", 2)
    rec = t.retire("target-1", 3, reason="decommissioned")
    assert rec.target_id == "target-1"
    assert rec.reason == "decommissioned"
    assert rec.verify()
    assert t.is_retired("target-1", 0)
    assert t.retired_ids(0) == ("target-1",)
    with pytest.raises(td.RetiredTargetError):
        t.test("target-1", 4)
    with pytest.raises(td.RetiredTargetError):
        t.detect("target-1", tst.test_id, 5)
    with pytest.raises(td.RetiredTargetError):
        t.retire("target-1", 6)
    with pytest.raises(td.RetiredTargetError):
        t.register_target("target-1", 7, target_digest=PIN)
    with pytest.raises(td.UnknownTargetError):
        t.retire("nope", 8)
    g = td.Trojan()
    _target(g)
    with pytest.raises(td.BadReasonError):
        g.retire("target-1", 2, reason="nope")
    # reads still work post-retire
    assert t.test_record(tst.test_id, 0).verify()
    rep = t.status("target-1", 0)
    assert rep.retired and rep.verify()


# 12. status math + read purity (same-seq twice, no audit rows)
def test_status_math_and_read_purity():
    t = td.Trojan()
    _target(t)
    tst = t.test("target-1", 2, outcome="triggered")
    det = t.detect("target-1", tst.test_id, 3, verdict="infected")
    rep = t.status("target-1", 0)
    assert rep.n_tests == 1 and rep.n_detections == 1
    assert rep.latest_verdict == "infected"
    assert rep.n_mitigations == 0
    assert not rep.retired and rep.integrity_ok and rep.verify()
    rows_before = len(t.audit_log(0))
    seq_before = t.stats(0)["seq"]
    r1 = t.status("target-1", 0)
    r2 = t.status("target-1", 0)
    assert r1 == r2
    assert len(t.audit_log(0)) == rows_before
    assert t.stats(0)["seq"] == seq_before
    # unknown target as data via view error, latest verdict when empty
    rep2 = t.status("target-1", 99)
    assert rep2.latest_verdict == "infected"
    with pytest.raises(td.UnknownTargetError):
        t.status("nope", 0)


# 13. seq discipline: rewind bare (zero rejected rows), malformed seqs,
#     failed mutation consumes seq
def test_seq_discipline():
    t = td.Trojan()
    _target(t)
    with pytest.raises(td.SeqOrderError):
        t.register_target("x", 1)  # rewind: bare, no burn
    with pytest.raises(td.SeqOrderError):
        t.register_target("x", 0)
    for bad in (True, "2", 2.0, None, -1):
        g = td.Trojan()
        with pytest.raises(td.SeqOrderError):
            g.register_target("x", bad)
    rows = t.audit_log(0)
    assert sum(1 for r in rows if r["kind"] == "rejected") == 0
    # failed mutation consumes seq
    with pytest.raises(td.DuplicateTargetError):
        t.register_target("target-1", 2)
    rows = t.audit_log(0)
    assert sum(1 for r in rows if r["kind"] == "rejected") == 1
    assert t.stats(0)["seq"] == 2


# 14. audit shapes + leak ban + bad kind
def test_audit_shapes_and_leak_ban():
    t = td.Trojan()
    _target(t)
    t.test("target-1", 2)
    rows = t.audit_log(0)
    for row in rows:
        assert row["schema"] == "audit.ndjson/1"
        assert row["kind"] in td.AUDIT_KINDS
        assert isinstance(row["seq"], int) and row["seq"] >= 0
    assert rows[0]["kind"] == "target-registered"
    assert rows[1]["kind"] == "test-recorded"
    with pytest.raises(td.AuditKindError):
        td.trojan_audit_event("nope", 1)
    for banned in ("weights", "trigger", "payload", "model_bytes",
                   "activations", "raw", "text", "response"):
        with pytest.raises(td.AuditKindError):
            td.trojan_audit_event("test-recorded", 1, **{banned: "x"})
    # pinned vocabulary values remain emittable as declared data
    row = td.trojan_audit_event("detection-recorded", 5, verdict="infected",
                                detector="neural-cleanse")
    assert row["details"]["verdict"] == "infected"


# 15. cross-instance digest determinism + tamper breaks verify() +
#     frozen-ness + 8-thread read smoke + main() subprocess check
def test_determinism_tamper_threads_main():
    t1 = td.Trojan()
    _target(t1)
    tst1 = t1.test("target-1", 2, test_kind="trigger-probe",
                   outcome="triggered", evidence_digest=PIN2)
    t2 = td.Trojan()
    _target(t2)
    tst2 = t2.test("target-1", 2, test_kind="trigger-probe",
                   outcome="triggered", evidence_digest=PIN2)
    assert tst1.digest == tst2.digest
    object.__setattr__(tst1, "outcome", "clean")
    assert not tst1.verify()
    # frozen-ness
    with pytest.raises(Exception):
        tst2.test_id = "tst-999"
    # tamper reported as data in status
    rep = t1.status("target-1", 0)
    assert not rep.integrity_ok
    assert rep.verify()
    # 8-thread read smoke
    errors = []
    def reader():
        try:
            for _ in range(50):
                t1.status("target-1", 0)
                t1.test_ids(0)
                t1.stats(0)
        except Exception as e:  # pragma: no cover
            errors.append(e)
    threads = [threading.Thread(target=reader) for _ in range(8)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    assert not errors
    # main() subprocess check
    proc = subprocess.run([sys.executable, str(MOD)], capture_output=True,
                          text=True, timeout=30)
    assert proc.returncode == 0, proc.stderr
    assert "trojan OK: register, test, detect, mitigate, status, pins" in \
        proc.stdout
