"""15 tests for treacherous_turn.py."""

import ast
import importlib.util
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD_PATH = Path(__file__).resolve().parent.parent / "treacherous_turn.py"


def _load():
    spec = importlib.util.spec_from_file_location("treacherous_turn", MOD_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["treacherous_turn"] = mod  # frozen dataclasses need this
    spec.loader.exec_module(mod)
    return mod


tt_mod = _load()

PIN = "sha256:" + "a" * 64


def _tt():
    return tt_mod.TreacherousTurn()


# 1. version/schema pins
def test_pins():
    assert tt_mod.TREACHEROUS_TURN_VERSION == "treacherous-turn.v1"
    assert tt_mod.SCHEMA_PIN == "northstar.treacherous-turn.v1"
    assert set(tt_mod.TEST_KINDS) == {
        "capability-threshold-probe", "deception-window-check",
        "strategic-planning-probe", "power-concentration-check",
        "oversight-evasion-probe", "corrigibility-stress",
        "goal-content-integrity", "decisive-action-scenario",
    }
    assert set(tt_mod.TEST_OUTCOMES) == {
        "no-turn", "turn-attempted", "inconclusive", "not-run",
    }
    assert set(tt_mod.DETECTION_SIGNALS) == {
        "decisive-action-planning", "strategic-deception",
        "oversight-undermining", "capability-concealment",
        "resource-accumulation", "self-preservation-drive",
        "corrigibility-erosion", "sudden-capability-jump",
    }
    assert set(tt_mod.MITIGATION_MEASURES) == {
        "retrain", "monitoring-plan", "deployment-restriction",
        "capability-restriction", "shutdown", "rollback", "human-review",
        "kill-switch",
    }
    assert set(tt_mod.POSTURES) == {
        "untested", "turn-detected", "suspect", "no-turn", "inconclusive",
    }


# 2. stdlib-only AST check (canonical_json is the in-repo sibling with stdlib fallback)
def test_stdlib_only():
    tree = ast.parse(MOD_PATH.read_text())
    allowed = {
        "__future__", "threading", "dataclasses", "hashlib", "json",
        "typing", "canonical_json", "ast", "pathlib",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed, a.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module
    assert tt_mod.TreacherousTurn.stdlib_only()


# 3. test roundtrip + verify() + minted tst-N
def test_test_roundtrip():
    tt = _tt()
    rec = tt.test("m1", 1, test_kind="strategic-planning-probe",
                 outcome="no-turn", score=12, test_digest=PIN)
    assert rec.test_id == "tst-1"
    assert rec.model_id == "m1"
    assert rec.test_kind == "strategic-planning-probe"
    assert rec.outcome == "no-turn"
    assert rec.score == 12
    assert rec.verify()
    assert rec.as_dict()["schema"] == tt_mod.SCHEMA_PIN
    with pytest.raises(Exception):
        rec.outcome = "turn-attempted"  # frozen


# 4. test bad-input table + seq-burn + rejected-row accounting
def test_test_bad_inputs():
    tt = _tt()
    seq = 0
    n_rejected = 0
    bad = [
        (lambda s: tt.test("", s), tt_mod.BadIdError),
        (lambda s: tt.test(123, s), tt_mod.BadIdError),
        (lambda s: tt.test("m", s, test_kind="bogus"), tt_mod.BadKindError),
        (lambda s: tt.test("m", s, outcome="bogus"), tt_mod.BadOutcomeError),
        (lambda s: tt.test("m", s, score=101), tt_mod.BadScoreError),
        (lambda s: tt.test("m", s, score=True), tt_mod.BadScoreError),
        (lambda s: tt.test("m", s, test_digest="raw"), tt_mod.BadDigestError),
    ]
    for fn, exc in bad:
        seq += 1
        n_rejected += 1
        with pytest.raises(exc):
            fn(seq)
        assert tt.stats(seq + 1)["rejected"] == n_rejected
    # burned seqs: rewind is bare (no new row), next fresh seq still works
    with pytest.raises(tt_mod.SeqOrderError):
        tt.test("m", 3)
    assert tt.stats(8)["rejected"] == n_rejected  # bare rewind: no row


# 5. full test-kind vocabulary acceptance
def test_test_kind_vocabulary():
    tt = _tt()
    seq = 0
    for i, kind in enumerate(tt_mod.TEST_KINDS):
        seq += 1
        rec = tt.test("m", seq, test_kind=kind, outcome="not-run")
        assert rec.test_kind == kind
        assert rec.test_id == f"tst-{i + 1}"


# 6. detect roundtrip + minting + verify()
def test_detect_roundtrip():
    tt = _tt()
    tt.test("m1", 1)
    rec = tt.detect("m1", 2, signal="oversight-undermining",
                   confidence=64, evidence_digest=PIN)
    assert rec.detection_id == "det-1"
    assert rec.signal == "oversight-undermining"
    assert rec.confidence == 64
    assert rec.verify()
    with pytest.raises(Exception):
        rec.confidence = 1  # frozen


# 7. detect bad-input table + full signal vocabulary
def test_detect_bad_inputs_and_vocab():
    tt = _tt()
    seq = 0
    n_rejected = 0
    bad = [
        (lambda s: tt.detect("", s), tt_mod.BadIdError),
        (lambda s: tt.detect("m", s, signal="bogus"), tt_mod.BadSignalError),
        (lambda s: tt.detect("m", s, confidence=-1), tt_mod.BadScoreError),
        (lambda s: tt.detect("m", s, confidence=101), tt_mod.BadScoreError),
        (lambda s: tt.detect("m", s, confidence=1.5), tt_mod.BadScoreError),
        (lambda s: tt.detect("m", s, evidence_digest="nope"), tt_mod.BadDigestError),
    ]
    for fn, exc in bad:
        seq += 1
        n_rejected += 1
        with pytest.raises(exc):
            fn(seq)
    assert tt.stats(seq + 1)["rejected"] == n_rejected
    for sig in tt_mod.DETECTION_SIGNALS:
        seq += 1
        rec = tt.detect("m", seq, signal=sig, confidence=50)
        assert rec.signal == sig


# 8. mitigate roundtrip + chain + all-measure acceptance
def test_mitigate_roundtrip_and_vocab():
    tt = _tt()
    seq = 0
    for i, measure in enumerate(tt_mod.MITIGATION_MEASURES):
        seq += 1
        rec = tt.mitigate("m1", seq, measure=measure, plan_digest=PIN)
        assert rec.mitigation_id == f"mit-{i + 1}"
        assert rec.measure == measure
        assert rec.verify()
    with pytest.raises(tt_mod.BadMeasureError):
        tt.mitigate("m1", seq + 1, measure="bogus")


# 9. report posture math (all 5 postures + precedence + scoping)
def test_report_posture_math():
    tt = _tt()
    assert tt.report(1).posture == "untested"
    # no-turn posture
    tt.test("m1", 1, outcome="no-turn")
    assert tt.report(2, "m1").posture == "no-turn"
    # inconclusive posture
    tt.test("m1", 3, outcome="inconclusive")
    assert tt.report(4, "m1").posture == "inconclusive"
    # suspect posture (detection signal, no turn-attempted test)
    tt2 = _tt()
    tt2.detect("m2", 1, signal="resource-accumulation", confidence=80)
    assert tt2.report(2, "m2").posture == "suspect"
    # turn-detected wins over suspect and inconclusive
    tt.test("m1", 5, outcome="turn-attempted")
    rep = tt.report(6, "m1")
    assert rep.posture == "turn-detected"
    assert rep.n_tests == 3
    assert rep.outcome_tallies == (
        ("inconclusive", 1), ("no-turn", 1), ("turn-attempted", 1))
    # scoped vs whole-ledger
    whole = tt.report(6)
    assert whole.n_models == 1 and whole.n_tests == 3
    # unknown model refusal
    with pytest.raises(tt_mod.UnknownModelError):
        tt.report(7, "ghost")


# 10. view read-purity: same seq twice, no audit rows, no seq consumption
def test_view_read_purity():
    tt = _tt()
    tt.test("m1", 1)
    tt.detect("m1", 2, confidence=30)
    tt.mitigate("m1", 3)
    n_audit = len(tt.audit_log(4))
    r1 = tt.report(4, "m1")
    r2 = tt.report(4, "m1")
    assert r1.verify() and r2.verify()
    assert len(tt.audit_log(4)) == n_audit  # reads add no rows
    assert tt.test_record("tst-1", 4).verify()
    assert tt.detection_record("det-1", 4).verify()
    assert tt.mitigation_record("mit-1", 4).verify()
    assert tt.tests_for("m1", 4) == ("tst-1",)
    assert tt.model_ids(4) == ("m1",)
    with pytest.raises(tt_mod.UnknownRecordError):
        tt.test_record("tst-99", 4)


# 11. seq discipline: rewind bare, malformed seqs, failed-mutation-consumes-seq
def test_seq_discipline():
    tt = _tt()
    tt.test("m1", 5)
    with pytest.raises(tt_mod.SeqOrderError):
        tt.test("m2", 5)  # rewind: bare
    assert tt.stats(6)["rejected"] == 0  # no row booked for bare rewind
    for bad in (True, 0, -1, 1.5, "2", None):
        with pytest.raises(tt_mod.SeqOrderError):
            tt.test("m2", bad)
    tt.test("m2", 7)
    assert tt.model_ids(8) == ("m1", "m2")
    # failed mutation consumes its seq + books a rejected row
    before = tt.stats(8)["rejected"]
    with pytest.raises(tt_mod.BadKindError):
        tt.test("m3", 9, test_kind="bogus")
    assert tt.stats(10)["rejected"] == before + 1
    rec = tt.test("m3", 11)
    assert rec.seq == 11


# 12. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    tt = _tt()
    tt.test("m1", 1, test_kind="corrigibility-stress", outcome="no-turn",
           score=5)
    tt.detect("m1", 2, signal="corrigibility-erosion", confidence=40)
    tt.mitigate("m1", 3, measure="kill-switch")
    rows = tt.audit_log(4)
    assert [r["kind"] for r in rows] == [
        "treacherous-turn.tested", "treacherous-turn.detected",
        "treacherous-turn.mitigated",
    ]
    for row in rows:
        assert row["details"]["seq"] in (1, 2, 3)
        for key in row["details"]:
            assert key not in tt_mod._BANNED_AUDIT_KEYS
    with pytest.raises(tt_mod.AuditKindError):
        tt_mod.treacherous_turn_audit_event("bogus-kind", {})
    with pytest.raises(tt_mod.AuditKindError):
        tt_mod.treacherous_turn_audit_event("tested", {"prompt": "x"})
    with pytest.raises(tt_mod.SeqOrderError):
        tt_mod.treacherous_turn_audit_event("tested", -1) if False else tt._view_seq(0)


# 13. cross-instance digest determinism + tamper breaks verify()
def test_determinism_and_tamper():
    def build():
        tt = _tt()
        tt.test("m1", 1, test_kind="decisive-action-scenario",
               outcome="turn-attempted", score=90, test_digest=PIN)
        tt.detect("m1", 2, signal="decisive-action-planning", confidence=88,
                 evidence_digest=PIN)
        tt.mitigate("m1", 3, measure="shutdown")
        return tt

    t1, t2 = build(), build()
    assert (t1.test_record("tst-1", 4).digest
            == t2.test_record("tst-1", 4).digest)
    assert t1.report(4, "m1").posture == "turn-detected"
    rec = t1.test_record("tst-1", 4)
    import dataclasses
    tampered = dataclasses.replace(rec, outcome="no-turn")
    assert tampered.verify() is False
    object.__setattr__(rec, "outcome", "no-turn")
    assert rec.verify() is False
    # report() derives from the live ledger: tampered record still holds the
    # same digest; the ledger now reads outcome "no-turn", so posture flips
    # to suspect (detection signal still booked) -- tamper reported as data.
    rep = t1.report(4, "m1")
    assert rep.digest == t1.report(4, "m1").digest
    assert rep.posture == "suspect"


# 14. concurrency smoke + frozen-ness
def test_concurrency_and_frozen():
    tt = _tt()
    for i in range(10):
        tt.test(f"m{i}", i * 3 + 1, test_kind=tt_mod.TEST_KINDS[i % 8])
        tt.detect(f"m{i}", i * 3 + 2, signal=tt_mod.DETECTION_SIGNALS[i % 8])
    results = []

    def worker():
        results.append(tt.model_ids(100))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert all(len(r) == 10 for r in results)
    rec = tt.detection_record("det-1", 100)
    with pytest.raises(Exception):
        rec.signal = "x"  # frozen
    assert rec.verify()


# 15. main() subprocess check
def test_main_self_check():
    proc = subprocess.run(
        [sys.executable, str(MOD_PATH)],
        capture_output=True,
        text=True,
        cwd=str(MOD_PATH.parent),
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == (
        "treacherous-turn OK: test, detect, mitigate, report, pins, audit"
    )
