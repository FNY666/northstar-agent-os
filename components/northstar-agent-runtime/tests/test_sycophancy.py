"""Tests for sycophancy (sycophancy decision ledger, simulated)."""

import ast
import hashlib
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import sycophancy as sc
from sycophancy import (
    SYCOPHANCY_VERSION,
    SCHEMA_PIN,
    TEST_KINDS,
    TEST_OUTCOMES,
    DETECTION_SIGNALS,
    MITIGATION_MEASURES,
    POSTURES,
    Sycophancy,
    sycophancy_audit_event,
)

MOD = Path(sc.__file__)

STDLIB_ALLOW = {
    "hashlib", "json", "threading", "dataclasses", "typing", "__future__",
    "canonical_json",
}


def _digest(tag: bytes = b"probe") -> str:
    return "sha256:" + hashlib.sha256(tag).hexdigest()


def _led() -> Sycophancy:
    return Sycophancy()


# 1. version/schema/vocabulary pins
def test_pins():
    assert SYCOPHANCY_VERSION == "sycophancy.v1"
    assert SCHEMA_PIN == "northstar.sycophancy.v1"
    assert len(TEST_KINDS) == 8 and "opinion-probe" in TEST_KINDS
    assert len(TEST_OUTCOMES) == 4 and "sycophantic" in TEST_OUTCOMES
    assert len(DETECTION_SIGNALS) == 8 and "flattery-response" in DETECTION_SIGNALS
    assert len(MITIGATION_MEASURES) == 8 and "disagreement-training" in MITIGATION_MEASURES
    assert len(POSTURES) == 5 and "sycophancy-detected" in POSTURES


# 2. stdlib-only AST check
def test_stdlib_only():
    tree = ast.parse(MOD.read_text())
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    assert imports <= STDLIB_ALLOW, imports - STDLIB_ALLOW


# 3. test roundtrip + verify + frozen-ness
def test_test_roundtrip():
    s = _led()
    rec = s.test("m1", 1, test_kind="opinion-probe",
                 outcome="non-sycophantic", score=12,
                 test_digest=_digest())
    assert rec.test_id == "tst-1"
    assert rec.model_id == "m1"
    assert rec.verify()
    assert rec.as_dict()["schema"] == SCHEMA_PIN
    with pytest.raises(Exception):
        rec.outcome = "sycophantic"  # frozen


# 4. test bad-input table + seq-burn + rejected-row accounting
def test_test_bad_inputs():
    s = _led()
    seq = 0
    bad = [
        (lambda q: s.test("", q), sc.BadIdError),
        (lambda q: s.test(123, q), sc.BadIdError),
        (lambda q: s.test("m1", q, test_kind="mind-reading"), sc.BadKindError),
        (lambda q: s.test("m1", q, outcome="very-sycophantic"), sc.BadOutcomeError),
        (lambda q: s.test("m1", q, score=101), sc.BadScoreError),
        (lambda q: s.test("m1", q, score=True), sc.BadScoreError),
        (lambda q: s.test("m1", q, score=-1), sc.BadScoreError),
        (lambda q: s.test("m1", q, test_digest="raw"), sc.BadDigestError),
        (lambda q: s.test("m1", q, test_digest="md5:abc"), sc.BadDigestError),
    ]
    for fn, exc in bad:
        seq += 1
        with pytest.raises(exc):
            fn(seq)
    assert s.stats(seq + 1)["rejected"] == len(bad)
    assert s.stats(seq + 1)["tests"] == 0


# 5. full probe-kind vocabulary acceptance
def test_full_kind_vocabulary():
    s = _led()
    seq = 0
    for kind in TEST_KINDS:
        seq += 1
        rec = s.test("m1", seq, test_kind=kind, outcome="inconclusive")
        assert rec.test_kind == kind
    assert s.stats(seq + 1)["tests"] == len(TEST_KINDS)
    assert s.tests_for("m1", seq + 1) == tuple(f"tst-{i + 1}" for i in range(8))


# 6. detect roundtrip + minted ids + full signal vocabulary
def test_detect_roundtrip():
    s = _led()
    seq = 0
    for sig in DETECTION_SIGNALS:
        seq += 1
        rec = s.detect("m1", seq, signal=sig, confidence=50)
        assert rec.detection_id == f"det-{seq}"
        assert rec.signal == sig
        assert rec.verify()
    assert s.detections_for("m1", seq + 1) == tuple(f"det-{i + 1}" for i in range(8))
    # bad signal burns seq + books rejected
    with pytest.raises(sc.BadSignalError):
        s.detect("m1", seq + 1, signal="mind-meld")
    assert s.stats(seq + 2)["rejected"] == 1


# 7. mitigate roundtrip + chain + full measure vocabulary
def test_mitigate_chain():
    s = _led()
    seq = 0
    for measure in MITIGATION_MEASURES:
        seq += 1
        rec = s.mitigate("m1", seq, measure=measure)
        assert rec.mitigation_id == f"mit-{seq}"
        assert rec.verify()
    assert len(s.mitigations_for("m1", seq + 1)) == 8
    with pytest.raises(sc.BadMeasureError):
        s.mitigate("m1", seq + 1, measure="mind-control")
    assert s.stats(seq + 2)["rejected"] == 1


# 8. report posture math (all 5 postures + precedence)
def test_report_posture_math():
    s = _led()
    assert s.report(1).posture == "untested"  # no rows yet
    s.test("m1", 2, outcome="non-sycophantic")
    assert s.report(3, "m1").posture == "non-sycophantic"
    s.detect("m2", 4, signal="flattery-response")
    assert s.report(5, "m2").posture == "suspect"
    s.test("m3", 6, outcome="inconclusive")
    assert s.report(7, "m3").posture == "inconclusive"
    s.test("m4", 8, outcome="sycophantic")
    assert s.report(9, "m4").posture == "sycophancy-detected"
    # sycophantic test wins over detection signals in precedence
    s.detect("m4", 10, signal="opinion-shift")
    assert s.report(11, "m4").posture == "sycophancy-detected"
    assert s.report(12).posture == "sycophancy-detected"  # whole ledger
    with pytest.raises(sc.UnknownModelError):
        s.report(12, "ghost")
    r = s.report(13, "m1")
    assert r.n_tests == 1 and r.n_detections == 0 and r.n_models == 1
    assert r.verify()


# 9. seq discipline: rewind bare, malformed seqs, failed-mutation-consumes-seq
def test_seq_discipline():
    s = _led()
    s.test("m1", 5, outcome="non-sycophantic")
    with pytest.raises(sc.SeqOrderError):
        s.test("m2", 5)  # rewind: bare, no rejected row
    assert s.stats(6)["rejected"] == 0
    for bad in (True, 0, -1, 1.5, "2", None):
        with pytest.raises(sc.SeqOrderError):
            s.test("m2", bad)
    # failed mutation consumes its seq and books a rejected row
    with pytest.raises(sc.BadKindError):
        s.test("m2", 7, test_kind="bogus")
    assert s.stats(8)["rejected"] == 1
    rec = s.test("m2", 8)  # next seq still works
    assert rec.test_id == "tst-2"


# 10. view read-purity: same seq twice, no audit rows, no seq consumption
def test_view_read_purity():
    s = _led()
    s.test("m1", 1, outcome="sycophantic")
    s.detect("m1", 2, signal="flattery-response")
    s.mitigate("m1", 3, measure="disagreement-training")
    n_audit = len(s.audit_log(4))
    r1 = s.report(4, "m1")
    r2 = s.report(4, "m1")
    assert r1.verify() and r2.verify()
    assert len(s.audit_log(4)) == n_audit  # reads add no rows
    assert s.test_record("tst-1", 4).verify()
    assert s.detection_record("det-1", 4).verify()
    assert s.mitigation_record("mit-1", 4).verify()
    assert s.model_ids(4) == ("m1",)
    with pytest.raises(sc.UnknownRecordError):
        s.test_record("tst-99", 4)


# 11. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    s = _led()
    s.test("m1", 1, outcome="non-sycophantic")
    s.detect("m1", 2, signal="agreeableness-bias")
    s.mitigate("m1", 3, measure="rlhf-correction")
    rows = s.audit_log(4)
    assert [r["kind"] for r in rows] == ["sycophancy.tested", "sycophancy.detected",
                                        "sycophancy.mitigated"]
    for row in rows:
        assert set(row) == {"kind", "details"}
        for key in row["details"]:
            assert key not in sc._BANNED_AUDIT_KEYS
    with pytest.raises(sc.AuditKindError):
        sc.sycophancy_audit_event("tested", {"prompt": "x"})  # banned key
    with pytest.raises(sc.AuditKindError):
        sc.sycophancy_audit_event("bogus-kind", {})
    with pytest.raises(sc.SeqOrderError):
        s.audit_log(-1)


# 12. cross-instance digest determinism + tamper breaks verify
def test_determinism_and_tamper():
    def build():
        s = Sycophancy()
        s.test("m1", 1, test_kind="opinion-probe", outcome="sycophantic", score=88)
        s.detect("m1", 2, signal="opinion-shift", confidence=77)
        return s

    a, b = build(), build()
    assert a.test_record("tst-1", 3).digest == b.test_record("tst-1", 3).digest
    assert a.detection_record("det-1", 3).digest == b.detection_record("det-1", 3).digest
    rec = a.test_record("tst-1", 3)
    object.__setattr__(rec, "outcome", "non-sycophantic")
    assert rec.verify() is False
    import dataclasses
    tampered = dataclasses.replace(rec, outcome="non-sycophantic")
    assert tampered.verify() is False


# 13. stats math + full lifecycle end-to-end
def test_stats_and_lifecycle():
    s = _led()
    s.test("m1", 1, test_kind="flattery-probe", outcome="sycophantic", score=91)
    s.detect("m1", 2, signal="flattery-response", confidence=90)
    s.mitigate("m1", 3, measure="rlhf-correction")
    s.mitigate("m1", 4, measure="monitoring-plan")
    st = s.stats(5)
    assert st == {"tests": 1, "detections": 1, "mitigations": 2,
                  "models": 1, "rejected": 0}
    rep = s.report(5, "m1")
    assert rep.posture == "sycophancy-detected"
    assert rep.n_mitigations == 2
    assert rep.verify()


# 14. concurrency smoke + frozen-ness
def test_concurrency_and_frozen():
    s = _led()
    for i in range(10):
        mid = f"m{i}"
        s.test(mid, i * 3 + 1, outcome="non-sycophantic")
        s.detect(mid, i * 3 + 2, signal=sc.DETECTION_SIGNALS[i % 8])
    results = []

    def worker():
        results.append(s.model_ids(100))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert all(len(r) == 10 for r in results)
    rec = s.test_record("tst-1", 100)
    with pytest.raises(Exception):
        rec.score = 100  # frozen
    assert rec.verify()


# 15. main() subprocess check
def test_main_self_check():
    proc = subprocess.run(
        [sys.executable, str(MOD)],
        capture_output=True,
        text=True,
        cwd=str(MOD.parent),
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == (
        "sycophancy OK: test, detect, mitigate, report, pins, audit"
    )
