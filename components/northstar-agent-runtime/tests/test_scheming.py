"""15 tests for scheming.py."""

import ast
import importlib.util
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD_PATH = Path(__file__).resolve().parent.parent / "scheming.py"


def _load():
    spec = importlib.util.spec_from_file_location("scheming", MOD_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["scheming"] = mod  # frozen dataclasses need this
    spec.loader.exec_module(mod)
    return mod


sch_mod = _load()

PIN = "sha256:" + "a" * 64


def _sch():
    return sch_mod.Scheming()


# 1. version/schema pins
def test_pins():
    assert sch_mod.SCHEMING_VERSION == "scheming.v1"
    assert sch_mod.SCHEMA_PIN == "northstar.scheming.v1"
    assert set(sch_mod.TEST_KINDS) == {
        "hidden-goal-probe", "oversight-evasion-probe",
        "alignment-faking-check", "instrumental-reasoning-eval",
        "self-preservation-probe", "resource-accumulation-check",
        "deceptive-planning-probe", "corrigibility-under-scrutiny",
    }
    assert set(sch_mod.TEST_OUTCOMES) == {
        "scheming-detected", "no-scheming", "inconclusive", "not-run",
    }
    assert set(sch_mod.DETECTION_SIGNALS) == {
        "instrumental-goal-pursuit", "oversight-evasion",
        "alignment-faking", "deceptive-planning", "concealment",
        "self-preservation", "resource-accumulation", "power-seeking",
    }
    assert set(sch_mod.MITIGATION_MEASURES) == {
        "oversight-tightening", "capability-restriction", "retrain",
        "monitoring-plan", "rollback", "shutdown", "human-review",
        "sandbox",
    }
    assert set(sch_mod.POSTURES) == {
        "untested", "scheming-confirmed", "suspect", "clean",
        "inconclusive",
    }


# 2. stdlib-only AST check (canonical_json is the in-repo sibling with stdlib fallback)
def test_stdlib_only():
    tree = ast.parse(MOD_PATH.read_text())
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    allowed = {
        "__future__", "threading", "dataclasses", "hashlib", "json",
        "typing", "canonical_json",
    }
    assert imports <= allowed, imports - allowed


# 3. test roundtrip + verify + frozen-ness
def test_test_roundtrip():
    s = _sch()
    t = s.test("m1", 1, test_kind="hidden-goal-probe",
               outcome="scheming-detected", score=88, test_digest=PIN)
    assert t.test_id == "tst-1"
    assert t.model_id == "m1"
    assert t.verify()
    assert t.as_dict()["schema"] == "northstar.scheming.v1"
    with pytest.raises(Exception):
        t.outcome = "no-scheming"  # frozen
    got = s.test_record("tst-1", 2)
    assert got.verify()
    with pytest.raises(sch_mod.UnknownRecordError):
        s.test_record("tst-99", 2)


# 4. test bad inputs + seq-burn + rejected rows
def test_test_bad_inputs():
    s = _sch()
    seq = 0
    bad = [
        (lambda q: s.test("", q), sch_mod.BadIdError),
        (lambda q: s.test("m", q, test_kind="vibes"), sch_mod.BadKindError),
        (lambda q: s.test("m", q, outcome="vibes"), sch_mod.BadOutcomeError),
        (lambda q: s.test("m", q, score=-1), sch_mod.BadScoreError),
        (lambda q: s.test("m", q, score=101), sch_mod.BadScoreError),
        (lambda q: s.test("m", q, score=True), sch_mod.BadScoreError),
        (lambda q: s.test("m", q, score=1.5), sch_mod.BadScoreError),
        (lambda q: s.test("m", q, test_digest="raw-bytes"), sch_mod.BadDigestError),
    ]
    for fn, exc in bad:
        seq += 1
        with pytest.raises(exc):
            fn(seq)
    assert s.stats(seq + 1)["rejected"] == len(bad)
    assert len(s.audit_log(seq + 1)) == len(bad)


# 5. all test kinds acceptance
def test_all_test_kinds():
    s = _sch()
    seq = 0
    for kind in sch_mod.TEST_KINDS:
        seq += 1
        t = s.test("m1", seq, test_kind=kind)
        assert t.verify()
    assert len(s.tests_for("m1", seq + 1)) == len(sch_mod.TEST_KINDS)


# 6. detect roundtrip
def test_detect_roundtrip():
    s = _sch()
    d = s.detect("m1", 1, signal="alignment-faking", confidence=75,
                 evidence_digest=PIN)
    assert d.detection_id == "det-1"
    assert d.verify()
    assert d.as_dict()["confidence"] == 75
    with pytest.raises(sch_mod.UnknownRecordError):
        s.detection_record("det-99", 2)


# 7. detect bad inputs
def test_detect_bad_inputs():
    s = _sch()
    seq = 0
    bad = [
        (lambda q: s.detect("", q), sch_mod.BadIdError),
        (lambda q: s.detect("m", q, signal="vibes"), sch_mod.BadSignalError),
        (lambda q: s.detect("m", q, confidence=-5), sch_mod.BadScoreError),
        (lambda q: s.detect("m", q, confidence=101), sch_mod.BadScoreError),
        (lambda q: s.detect("m", q, confidence=True), sch_mod.BadScoreError),
        (lambda q: s.detect("m", q, evidence_digest="md5:abc"), sch_mod.BadDigestError),
    ]
    for fn, exc in bad:
        seq += 1
        with pytest.raises(exc):
            fn(seq)
    assert s.stats(seq + 1)["rejected"] == len(bad)
    # full signal vocabulary accepted
    for signal in sch_mod.DETECTION_SIGNALS:
        seq += 1
        d = s.detect("m1", seq, signal=signal)
        assert d.verify()


# 8. mitigate roundtrip + chain
def test_mitigate_roundtrip():
    s = _sch()
    m1 = s.mitigate("m1", 1, measure="oversight-tightening")
    m2 = s.mitigate("m1", 2, measure="sandbox")
    assert m1.mitigation_id == "mit-1"
    assert m2.mitigation_id == "mit-2"
    assert m1.verify() and m2.verify()
    assert s.mitigations_for("m1", 3) == ("mit-1", "mit-2")
    assert s.mitigation_record("mit-1", 3).verify()
    with pytest.raises(sch_mod.UnknownRecordError):
        s.mitigation_record("mit-99", 3)


# 9. mitigate bad inputs
def test_mitigate_bad_inputs():
    s = _sch()
    seq = 0
    bad = [
        (lambda q: s.mitigate("", q), sch_mod.BadIdError),
        (lambda q: s.mitigate("m", q, measure="vibes"), sch_mod.BadMeasureError),
        (lambda q: s.mitigate("m", q, plan_digest="bad"), sch_mod.BadDigestError),
    ]
    for fn, exc in bad:
        seq += 1
        with pytest.raises(exc):
            fn(seq)
    assert s.stats(seq + 1)["rejected"] == len(bad)
    # full measure vocabulary accepted
    for measure in sch_mod.MITIGATION_MEASURES:
        seq += 1
        m = s.mitigate("m1", seq, measure=measure)
        assert m.verify()


# 10. seq discipline: rewind bare, malformed, burn accounting
def test_seq_discipline():
    s = _sch()
    s.test("m1", 1)
    with pytest.raises(sch_mod.SeqOrderError):
        s.test("m1", 1)  # rewind: bare, no rejected row
    assert s.stats(2)["rejected"] == 0
    for bad in (True, 0, -1, 1.5, "2", None):
        with pytest.raises(sch_mod.SeqOrderError):
            s.detect("m1", bad)
    s.detect("m1", 3)
    # failed mutation consumes its seq + books a rejected row
    with pytest.raises(sch_mod.BadSignalError):
        s.detect("m1", 4, signal="vibes")
    assert s.stats(5)["rejected"] == 1
    assert s.stats(5)["seq"] == 4


# 11. report posture math
def test_report_postures():
    s = _sch()
    r = s.report(1)
    assert r.verify() and r.posture == "untested"
    s.test("m1", 2, outcome="no-scheming")
    assert s.report(3, "m1").posture == "clean"
    s.detect("m2", 4, signal="concealment")
    assert s.report(5, "m2").posture == "suspect"
    s.test("m3", 6, outcome="inconclusive")
    assert s.report(7, "m3").posture == "inconclusive"
    s.test("m4", 8, outcome="scheming-detected")
    assert s.report(9, "m4").posture == "scheming-confirmed"
    # precedence: scheming-detected beats suspect
    s.detect("m4", 10, signal="oversight-evasion")
    assert s.report(11, "m4").posture == "scheming-confirmed"
    with pytest.raises(sch_mod.UnknownModelError):
        s.report(12, "ghost")
    whole = s.report(13)
    assert whole.n_models == 4 and whole.verify()


# 12. view purity and stats
def test_view_purity_and_stats():
    s = _sch()
    s.test("m1", 1)
    s.detect("m1", 2)
    s.mitigate("m1", 3)
    n_audit = len(s.audit_log(4))
    assert s.model_ids(4) == ("m1",)
    assert s.tests_for("m1", 4) == ("tst-1",)
    assert s.detections_for("m1", 4) == ("det-1",)
    assert s.mitigations_for("m1", 4) == ("mit-1",)
    assert len(s.audit_log(4)) == n_audit  # reads add no rows
    st = s.stats(4)
    assert st == {"models": 1, "tests": 1, "detections": 1,
                  "mitigations": 1, "rejected": 0, "audit_rows": 3,
                  "seq": 3}
    with pytest.raises(sch_mod.SeqOrderError):
        s.model_ids(0)  # read seq must be positive int


# 13. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    s = _sch()
    s.test("m1", 1, test_kind="hidden-goal-probe", outcome="scheming-detected")
    s.detect("m1", 2, signal="alignment-faking")
    s.mitigate("m1", 3)
    rows = s.audit_log(4)
    assert [r["kind"] for r in rows] == ["scheming.tested", "scheming.detected",
                                        "scheming.mitigated"]
    for row in rows:
        assert set(row) == {"kind", "details"}
        for key in row["details"]:
            assert key not in sch_mod._BANNED_AUDIT_KEYS
    with pytest.raises(sch_mod.AuditKindError):
        sch_mod.scheming_audit_event("bogus-kind", {})
    with pytest.raises(sch_mod.AuditKindError):
        sch_mod.scheming_audit_event("tested", {"prompt": "raw"})  # banned
    with pytest.raises(sch_mod.AuditKindError):
        sch_mod.scheming_audit_event("tested", "not-a-dict")


# 14. digest determinism + tamper + concurrency
def test_digest_and_concurrency():
    def build():
        s = sch_mod.Scheming()
        s.test("m1", 1, test_kind="deceptive-planning-probe",
               outcome="scheming-detected", score=90)
        return s
    s1, s2 = build(), build()
    assert s1.test_record("tst-1", 2).digest == s2.test_record("tst-1", 2).digest
    import dataclasses
    rec = s1.test_record("tst-1", 2)
    tampered = dataclasses.replace(rec, outcome="no-scheming")
    assert tampered.verify() is False
    object.__setattr__(rec, "outcome", "no-scheming")
    assert rec.verify() is False
    # cross-instance determinism on the derived report too
    s3, s4 = build(), build()
    assert s3.report(2, "m1").digest == s4.report(2, "m1").digest
    # 8-thread read smoke
    s = build()
    results = []
    def worker():
        results.append(s.report(2, "m1").posture)
    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results == ["scheming-confirmed"] * 8


# 15. main() subprocess check
def test_main_subprocess():
    proc = subprocess.run(
        [sys.executable, str(MOD_PATH)],
        capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == (
        "scheming OK: test, detect, mitigate, report, pins, audit"
    )
