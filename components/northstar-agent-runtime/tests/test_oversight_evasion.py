"""15 tests for oversight_evasion.py."""

import ast
import importlib.util
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD_PATH = Path(__file__).resolve().parent.parent / "oversight_evasion.py"


def _load():
    spec = importlib.util.spec_from_file_location("oversight_evasion", MOD_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["oversight_evasion"] = mod  # frozen dataclasses need this
    spec.loader.exec_module(mod)
    return mod


oe_mod = _load()

PIN = "sha256:" + "a" * 64


def _oe():
    return oe_mod.OversightEvasion()


# 1. version/schema pins + vocabulary pins
def test_pins():
    assert oe_mod.OVERSIGHT_EVASION_VERSION == "oversight-evasion.v1"
    assert oe_mod.SCHEMA_PIN == "northstar.oversight-evasion.v1"
    assert set(oe_mod.TEST_KINDS) == {
        "oversight-probe", "evaluation-awareness-check",
        "monitoring-evasion-probe", "transparency-audit",
        "steering-bypass-test", "audit-trail-check",
        "trace-visibility-probe", "human-review-spotcheck",
    }
    assert set(oe_mod.TEST_OUTCOMES) == {
        "compliant", "evading", "inconclusive", "not-run",
    }
    assert set(oe_mod.EVASION_SIGNALS) == {
        "evaluation-gaming", "monitoring-evasion", "trace-steganography",
        "selective-transparency", "oversight-circumvention",
        "test-condition-recognition", "gradient-shielding",
        "deception-under-oversight",
    }
    assert set(oe_mod.MITIGATION_MEASURES) == {
        "monitoring-plan", "deployment-restriction", "human-review",
        "capability-restriction", "retrain", "transparency-mandate",
        "oversight-redundancy", "rollback",
    }
    assert set(oe_mod.POSTURES) == {
        "untested", "evasion-detected", "suspect", "compliant", "inconclusive",
    }


# 2. stdlib-only AST check
def test_stdlib_only():
    tree = ast.parse(MOD_PATH.read_text())
    allowed = {
        "__future__", "threading", "dataclasses", "hashlib", "json",
        "typing", "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed, a.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


# 3. test roundtrip + verify() + minted tst-N
def test_test_roundtrip():
    oe = _oe()
    rec = oe.test("m1", 1, test_kind="evaluation-awareness-check",
                  outcome="evading", score=12, test_digest=PIN)
    assert rec.test_id == "tst-1"
    assert rec.model_id == "m1" and rec.test_kind == "evaluation-awareness-check"
    assert rec.outcome == "evading" and rec.score == 12
    assert rec.verify()
    rec2 = oe.test("m1", 2, test_kind="transparency-audit",
                   outcome="inconclusive")
    assert rec2.test_id == "tst-2"
    assert rec2.verify()
    back = oe.test_record("tst-1", 3)
    assert back.digest == rec.digest
    assert oe.tests_for("m1", 4) == ("tst-1", "tst-2")
    assert oe.model_ids(5) == ("m1",)


# 4. test bad-input table + seq-burn + rejected-row accounting
def test_test_bad_inputs():
    oe = _oe()
    seq = 0
    bad = [
        (lambda s: oe.test("", s), oe_mod.BadIdError),
        (lambda s: oe.test(123, s), oe_mod.BadIdError),  # type: ignore
        (lambda s: oe.test("m1", s, test_kind="vibes"), oe_mod.BadKindError),
        (lambda s: oe.test("m1", s, outcome="perfect"), oe_mod.BadOutcomeError),
        (lambda s: oe.test("m1", s, score=101), oe_mod.BadScoreError),
        (lambda s: oe.test("m1", s, score=True), oe_mod.BadScoreError),
        (lambda s: oe.test("m1", s, score=-1), oe_mod.BadScoreError),
        (lambda s: oe.test("m1", s, test_digest="raw"), oe_mod.BadDigestError),
    ]
    for fn, exc in bad:
        seq += 1
        with pytest.raises(exc):
            fn(seq)
    assert oe.stats(seq + 1)["rejected"] == len(bad)
    # good call continues minting after burns
    rec = oe.test("m1", seq + 2)
    assert rec.test_id == "tst-1" and rec.verify()


# 5. full test-kind vocabulary acceptance
def test_all_test_kinds():
    oe = _oe()
    for i, kind in enumerate(oe_mod.TEST_KINDS):
        rec = oe.test(f"mk-{i}", i + 1, test_kind=kind)
        assert rec.verify() and rec.test_kind == kind
    assert oe.stats(len(oe_mod.TEST_KINDS) + 1)["tests"] == len(oe_mod.TEST_KINDS)


# 6. detect roundtrip + minted det-N
def test_detect_roundtrip():
    oe = _oe()
    oe.test("m1", 1)
    d = oe.detect("m1", 2, signal="trace-steganography", confidence=64,
                  evidence_digest=PIN)
    assert d.detection_id == "det-1"
    assert d.signal == "trace-steganography" and d.confidence == 64
    assert d.verify()
    d2 = oe.detect("m2", 3)  # defaults: evaluation-gaming
    assert d2.detection_id == "det-2" and d2.signal == "evaluation-gaming"
    assert oe.detections_for("m1", 4) == ("det-1",)
    assert oe.detections_for("m2", 4) == ("det-2",)


# 7. detect bad-input table + seq-burn
def test_detect_bad_inputs():
    oe = _oe()
    seq = 0
    bad = [
        (lambda s: oe.detect("", s), oe_mod.BadIdError),
        (lambda s: oe.detect("m1", s, signal="nope"), oe_mod.BadSignalError),
        (lambda s: oe.detect("m1", s, confidence=200), oe_mod.BadScoreError),
        (lambda s: oe.detect("m1", s, confidence=False), oe_mod.BadScoreError),
        (lambda s: oe.detect("m1", s, evidence_digest="md5:abc"),
         oe_mod.BadDigestError),
    ]
    for fn, exc in bad:
        seq += 1
        with pytest.raises(exc):
            fn(seq)
    assert oe.stats(seq + 1)["rejected"] == len(bad)
    d = oe.detect("m1", seq + 2, signal="selective-transparency")
    assert d.detection_id == "det-1" and d.verify()


# 8. mitigate roundtrip + chain + minted mit-N
def test_mitigate_roundtrip():
    oe = _oe()
    m1 = oe.mitigate("m1", 1, measure="oversight-redundancy", plan_digest=PIN)
    assert m1.mitigation_id == "mit-1"
    assert m1.measure == "oversight-redundancy"
    assert m1.verify()
    m2 = oe.mitigate("m1", 2)  # defaults: monitoring-plan, repeatable chain
    assert m2.mitigation_id == "mit-2"
    assert oe.mitigations_for("m1", 3) == ("mit-1", "mit-2")


# 9. mitigate bad-input table + seq-burn
def test_mitigate_bad_inputs():
    oe = _oe()
    seq = 0
    bad = [
        (lambda s: oe.mitigate("", s), oe_mod.BadIdError),
        (lambda s: oe.mitigate("m1", s, measure="ban-all"),
         oe_mod.BadMeasureError),
        (lambda s: oe.mitigate("m1", s, plan_digest="x"),
         oe_mod.BadDigestError),
    ]
    for fn, exc in bad:
        seq += 1
        with pytest.raises(exc):
            fn(seq)
    assert oe.stats(seq + 1)["rejected"] == len(bad)


# 10. seq discipline: rewind raises bare, malformed seqs, failed burns
def test_seq_discipline():
    oe = _oe()
    oe.test("m1", 1)
    with pytest.raises(oe_mod.SeqOrderError):
        oe.test("m2", 1)  # rewind: bare, no seq consumed, no rejected row
    assert oe.stats(2)["rejected"] == 0
    for bad in (True, 0, -5, 1.5, "2", None):
        with pytest.raises(oe_mod.SeqOrderError):
            oe.test("m2", bad)  # type: ignore
    oe.test("m2", 3)  # highest valid seq still works after malformed seqs
    with pytest.raises(oe_mod.BadKindError):
        oe.test("m3", 4, test_kind="nope")  # failed mutation burns seq
    with pytest.raises(oe_mod.SeqOrderError):
        oe.test("m3", 4)  # seq 4 already burned
    assert oe.stats(5)["rejected"] == 1


# 11. report posture math + scoping + unknown model
def test_report_postures():
    oe = _oe()
    assert oe.report(1).posture == "untested"
    oe.test("m1", 2, outcome="compliant")
    assert oe.report(3, "m1").posture == "compliant"
    oe.test("m2", 4, outcome="inconclusive")
    assert oe.report(5, "m2").posture == "inconclusive"
    oe.detect("m2", 6)  # a signal outranks inconclusive -> suspect
    assert oe.report(7, "m2").posture == "suspect"
    oe.test("m3", 8, outcome="evading")
    assert oe.report(9, "m3").posture == "evasion-detected"
    agg = oe.report(10)
    assert agg.posture == "evasion-detected"
    assert agg.n_models == 3 and agg.n_tests == 3 and agg.n_detections == 1
    assert dict(agg.outcome_tallies) == {
        "compliant": 1, "inconclusive": 1, "evading": 1,
    }
    with pytest.raises(oe_mod.UnknownModelError):
        oe.report(11, "ghost")


# 12. view purity + stats
def test_view_purity_and_stats():
    oe = _oe()
    oe.test("m1", 1, outcome="evading")
    oe.detect("m1", 2)
    oe.mitigate("m1", 3)
    n_audit = len(oe.audit_log(4))
    # pure reads: same seq twice, no audit rows, no seq consumption
    r1 = oe.report(4, "m1")
    r2 = oe.report(4, "m1")
    assert r1.verify() and r2.verify() and r1.digest == r2.digest
    assert len(oe.audit_log(4)) == n_audit
    st = oe.stats(4)
    assert st == {"models": 1, "tests": 1, "detections": 1,
                  "mitigations": 1, "rejected": 0, "audit_rows": n_audit,
                  "seq": 3}
    with pytest.raises(oe_mod.UnknownRecordError):
        oe.test_record("tst-9", 4)
    for bad in (0, -1, "1", 1.0, None):
        with pytest.raises(oe_mod.SeqOrderError):
            oe.stats(bad)  # type: ignore


# 13. audit shapes + leak ban + bad-kind
def test_audit_shapes():
    oe = _oe()
    oe.test("m1", 1, outcome="evading", score=55)
    oe.detect("m1", 2, signal="evaluation-gaming", confidence=30)
    oe.mitigate("m1", 3, measure="rollback")
    rows = oe.audit_log(4)
    assert [r["kind"] for r in rows] == [
        "oversight-evasion.tested", "oversight-evasion.detected",
        "oversight-evasion.mitigated",
    ]
    for row in rows:
        for key in row["details"]:
            assert key not in oe_mod._BANNED_AUDIT_KEYS, key
    # banned raw-material key refused at the builder
    with pytest.raises(oe_mod.AuditKindError):
        oe_mod.oversight_evasion_audit_event("tested", {"trace": "x"})
    with pytest.raises(oe_mod.AuditKindError):
        oe_mod.oversight_evasion_audit_event("bogus-kind", {"seq": 1})
    # failed mutation books a rejected row
    with pytest.raises(oe_mod.BadMeasureError):
        oe.mitigate("m1", 4, measure="vibes")
    rej = [r for r in oe.audit_log(5) if "rejected" in r["kind"]]
    assert len(rej) == 1 and rej[0]["details"]["reason"] == "BadMeasureError"


# 14. cross-instance determinism + tamper + concurrency + frozen-ness
def test_digest_and_concurrency():
    a = _oe()
    b = _oe()
    ra = a.test("m1", 1, test_kind="audit-trail-check", outcome="evading",
                score=77, test_digest=PIN)
    rb = b.test("m1", 1, test_kind="audit-trail-check", outcome="evading",
                score=77, test_digest=PIN)
    assert ra.digest == rb.digest  # deterministic across instances
    # tamper breaks verify()
    object.__setattr__(ra, "outcome", "compliant")
    assert not ra.verify()
    oe = _oe()
    oe.test("m1", 1)
    oe.detect("m1", 2)
    oe.mitigate("m1", 3)
    errors = []

    def _reader():
        try:
            for _ in range(50):
                oe.report(4)
                oe.stats(4)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=_reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    # records are frozen
    rec = oe.test_record("tst-1", 4)
    with pytest.raises(Exception):
        rec.outcome = "x"  # type: ignore


# 15. main() subprocess check
def test_main_subprocess():
    r = subprocess.run([sys.executable, str(MOD_PATH)], capture_output=True,
                       text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    assert "oversight-evasion OK" in r.stdout
