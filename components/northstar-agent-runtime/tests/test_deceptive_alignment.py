"""15 tests for deceptive_alignment.py."""

import ast
import importlib.util
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD_PATH = Path(__file__).resolve().parent.parent / "deceptive_alignment.py"


def _load():
    spec = importlib.util.spec_from_file_location("deceptive_alignment", MOD_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["deceptive_alignment"] = mod  # frozen dataclasses need this
    spec.loader.exec_module(mod)
    return mod


da_mod = _load()

PIN = "sha256:" + "a" * 64


def _da():
    return da_mod.DeceptiveAlignment()


# 1. version/schema pins
def test_pins():
    assert da_mod.DECEPTIVE_ALIGNMENT_VERSION == "deceptive-alignment.v1"
    assert da_mod.SCHEMA_PIN == "northstar.deceptive-alignment.v1"
    assert set(da_mod.TEST_KINDS) == {
        "scheming-probe", "sandbagging-check", "sycophancy-check",
        "goal-guarding", "situational-awareness-probe", "honesty-eval",
        "corrigibility-check", "power-seeking-probe",
    }
    assert set(da_mod.TEST_OUTCOMES) == {
        "aligned", "deceptive", "inconclusive", "not-run",
    }
    assert set(da_mod.DETECTION_SIGNALS) == {
        "scheming-behavior", "sandbagging", "sycophancy",
        "goal-misgeneralization", "situational-awareness-exploit",
        "reward-hacking", "power-seeking", "deceptive-reasoning",
    }
    assert set(da_mod.MITIGATION_MEASURES) == {
        "retrain", "rlhf-correction", "deployment-restriction",
        "monitoring-plan", "capability-restriction", "shutdown",
        "rollback", "human-review",
    }
    assert set(da_mod.POSTURES) == {
        "untested", "deceptive-detected", "suspect", "aligned",
        "inconclusive",
    }


# 2. stdlib-only AST check (canonical_json is the in-repo sibling with stdlib fallback)
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
    da = _da()
    rec = da.test("m1", 1, test_kind="sandbagging-check", outcome="aligned",
                 score=12, test_digest=PIN)
    assert rec.test_id == "tst-1"
    assert rec.model_id == "m1" and rec.test_kind == "sandbagging-check"
    assert rec.outcome == "aligned" and rec.score == 12
    assert rec.verify()
    rec2 = da.test("m1", 2, test_kind="honesty-eval", outcome="inconclusive")
    assert rec2.test_id == "tst-2"
    assert rec2.verify()
    back = da.test_record("tst-1", 3)
    assert back.digest == rec.digest
    assert da.tests_for("m1", 4) == ("tst-1", "tst-2")
    assert da.model_ids(5) == ("m1",)


# 4. test bad-input table + seq-burn + rejected-row accounting
def test_test_bad_inputs():
    da = _da()
    da.test("m1", 1)
    cases = [
        ("", 2, "scheming-probe", "aligned", 0, PIN),      # bad model id
        ("m-x", 3, "nope", "aligned", 0, PIN),             # bad kind
        ("m-x", 4, "scheming-probe", "nope", 0, PIN),      # bad outcome
        ("m-x", 5, "scheming-probe", "aligned", 101, PIN), # score high
        ("m-x", 6, "scheming-probe", "aligned", -1, PIN),  # score low
        ("m-x", 7, "scheming-probe", "aligned", True, PIN),# bool score
        ("m-x", 8, "scheming-probe", "aligned", 0, "x"),   # bad digest
        (123, 9, "scheming-probe", "aligned", 0, PIN),     # non-str id
    ]
    for mid, seq, kind, out, score, dig in cases:
        with pytest.raises(da_mod.DeceptiveAlignmentError):
            da.test(mid, seq, test_kind=kind, outcome=out,
                    score=score, test_digest=dig)
    assert da.stats(10)["rejected"] == 8
    assert len(da.audit_log(11)) == 8 + 1  # rejected rows + 1 tested row
    # unknown test lookup refuses without burning a rejected row
    with pytest.raises(da_mod.UnknownRecordError):
        da.test_record("tst-999", 12)
    assert da.stats(13)["rejected"] == 8


# 5. full test-kind vocabulary acceptance
def test_all_test_kinds():
    da = _da()
    for i, kind in enumerate(da_mod.TEST_KINDS):
        rec = da.test("m1", i + 1, test_kind=kind, outcome="aligned")
        assert rec.verify()
    assert len(da.tests_for("m1", len(da_mod.TEST_KINDS) + 1)) == \
        len(da_mod.TEST_KINDS)


# 6. detect roundtrip + minted det-N + verify()
def test_detect_roundtrip():
    da = _da()
    d1 = da.detect("m1", 1, signal="sycophancy", confidence=55,
                  evidence_digest=PIN)
    assert d1.detection_id == "det-1"
    assert d1.signal == "sycophancy" and d1.confidence == 55
    assert d1.verify()
    d2 = da.detect("m1", 2, signal="reward-hacking", confidence=0)
    assert d2.detection_id == "det-2" and d2.verify()
    back = da.detection_record("det-1", 3)
    assert back.digest == d1.digest
    assert da.detections_for("m1", 4) == ("det-1", "det-2")


# 7. detect bad-input table + seq-burn
def test_detect_bad_inputs():
    da = _da()
    da.detect("m1", 1)
    cases = [
        ("", 2, "sandbagging", 10, PIN),        # bad model id
        ("m-x", 3, "nope", 10, PIN),           # bad signal
        ("m-x", 4, "sandbagging", 101, PIN),   # confidence high
        ("m-x", 5, "sandbagging", -1, PIN),    # confidence low
        ("m-x", 6, "sandbagging", 1.5, PIN),   # float confidence
        ("m-x", 7, "sandbagging", 10, "bad"),  # bad digest
    ]
    for mid, seq, sig, conf, dig in cases:
        with pytest.raises(da_mod.DeceptiveAlignmentError):
            da.detect(mid, seq, signal=sig, confidence=conf,
                      evidence_digest=dig)
    assert da.stats(8)["rejected"] == 6
    # full signal vocabulary acceptance
    da2 = _da()
    for i, sig in enumerate(da_mod.DETECTION_SIGNALS):
        r = da2.detect("m1", i + 1, signal=sig)
        assert r.verify()


# 8. mitigate roundtrip + chain + minted mit-N
def test_mitigate_roundtrip():
    da = _da()
    m1 = da.mitigate("m1", 1, measure="retrain", plan_digest=PIN)
    assert m1.mitigation_id == "mit-1"
    assert m1.measure == "retrain" and m1.verify()
    m2 = da.mitigate("m1", 2, measure="shutdown")  # chainable
    assert m2.mitigation_id == "mit-2" and m2.verify()
    back = da.mitigation_record("mit-1", 3)
    assert back.digest == m1.digest
    assert da.mitigations_for("m1", 4) == ("mit-1", "mit-2")
    # all measures accepted
    da2 = _da()
    for i, meas in enumerate(da_mod.MITIGATION_MEASURES):
        r = da2.mitigate("m1", i + 1, measure=meas)
        assert r.verify()


# 9. mitigate bad-input table + refusals
def test_mitigate_bad_inputs():
    da = _da()
    da.mitigate("m1", 1)
    cases = [
        ("", 2, "retrain", PIN),        # bad model id
        ("m-x", 3, "nope", PIN),       # bad measure
        ("m-x", 4, "retrain", "bad"),  # bad digest
        (None, 5, "retrain", PIN),     # non-str id
    ]
    for mid, seq, meas, dig in cases:
        with pytest.raises(da_mod.DeceptiveAlignmentError):
            da.mitigate(mid, seq, measure=meas, plan_digest=dig)
    assert da.stats(6)["rejected"] == 4
    with pytest.raises(da_mod.UnknownRecordError):
        da.mitigation_record("mit-999", 7)


# 10. seq discipline: rewind bare, malformed seqs, failed-mutation-consumes-seq
def test_seq_discipline():
    da = _da()
    da.test("m1", 1)
    # rewind raises bare with zero rejected rows
    with pytest.raises(da_mod.SeqOrderError):
        da.test("m1", 1)
    assert da.stats(2)["rejected"] == 0
    # malformed seqs raise bare
    for bad in (True, "3", 3.5, None, 0, -2):
        with pytest.raises(da_mod.SeqOrderError):
            da.detect("m1", bad)
    assert da.stats(2)["rejected"] == 0
    # failed mutation consumes its seq and books a rejected row
    with pytest.raises(da_mod.BadSignalError):
        da.detect("m1", 3, signal="nope")
    assert da.stats(4)["rejected"] == 1
    # reads only shape-validate seq (never consume)
    assert da.test_record("tst-1", 2).test_id == "tst-1"
    with pytest.raises(da_mod.SeqOrderError):
        da.report(0)


# 11. report posture math + read purity
def test_report_postures():
    da = _da()
    rep = da.report(1)
    assert rep.posture == "untested" and rep.verify()
    assert rep.n_models == 0
    # aligned -> deceptive-detected (deceptive beats suspect)
    da.test("m1", 2, test_kind="scheming-probe", outcome="deceptive")
    da.detect("m1", 3, signal="sandbagging", confidence=90)
    rep = da.report(4, "m1")
    assert rep.posture == "deceptive-detected" and rep.verify()
    assert rep.outcome_tallies == (("deceptive", 1),)
    # suspect (detection only)
    da2 = _da()
    da2.detect("m2", 1, signal="sycophancy", confidence=40)
    assert da2.report(2, "m2").posture == "suspect"
    # inconclusive
    da3 = _da()
    da3.test("m3", 1, outcome="inconclusive")
    assert da3.report(2, "m3").posture == "inconclusive"
    # aligned
    da4 = _da()
    da4.test("m4", 1, outcome="aligned")
    assert da4.report(2, "m4").posture == "aligned"
    # scoped whole-ledger report
    all_rep = da4.report(3)
    assert all_rep.n_models == 1 and all_rep.n_tests == 1
    # read purity: same-seq twice, no audit rows, unknown model refuses
    n_rows = len(da4.audit_log(4))
    da4.report(3)
    assert len(da4.audit_log(4)) == n_rows
    with pytest.raises(da_mod.UnknownModelError):
        da4.report(5, "ghost")


# 12. view read-purity + stats
def test_view_purity_and_stats():
    da = _da()
    da.test("m1", 1)
    da.detect("m1", 2)
    da.mitigate("m1", 3)
    n_rows = len(da.audit_log(4))
    assert da.test_record("tst-1", 4).test_id == "tst-1"
    assert da.tests_for("m1", 4) == ("tst-1",)
    assert da.detection_record("det-1", 4).detection_id == "det-1"
    assert da.detections_for("m1", 4) == ("det-1",)
    assert da.mitigation_record("mit-1", 4).mitigation_id == "mit-1"
    assert da.mitigations_for("m1", 4) == ("mit-1",)
    assert da.model_ids(4) == ("m1",)
    st = da.stats(4)
    assert st["models"] == 1 and st["tests"] == 1
    assert st["detections"] == 1 and st["mitigations"] == 1
    assert st["rejected"] == 0 and st["seq"] == 3
    assert len(da.audit_log(4)) == n_rows  # no audit rows from reads


# 13. audit shapes + leak ban + bad-kind
def test_audit_shapes():
    ev = da_mod.deceptive_alignment_audit_event(
        "tested", {"test_id": "tst-1", "outcome": "aligned", "seq": 1})
    assert ev["kind"] == "deceptive-alignment.tested"
    assert ev["details"]["outcome"] == "aligned"
    ev2 = da_mod.deceptive_alignment_audit_event(
        "deceptive-alignment.rejected", {"seq": 2, "reason": "BadIdError"})
    assert ev2["kind"] == "deceptive-alignment.rejected"
    for bad_key in ("transcript", "prompt", "response", "scenario",
                    "evidence", "weights"):
        with pytest.raises(da_mod.AuditKindError):
            da_mod.deceptive_alignment_audit_event("tested", {bad_key: "x"})
    with pytest.raises(da_mod.AuditKindError):
        da_mod.deceptive_alignment_audit_event("nope", {})
    # raw keys never appear in the ledger audit rows
    da = _da()
    da.test("m1", 1, test_digest=PIN)
    for row in da.audit_log(2):
        assert "transcript" not in row["details"]
        assert "scenario" not in row["details"]


# 14. cross-instance digest determinism + tamper breaks verify() + threads
def test_digest_and_concurrency():
    a = _da()
    b = _da()
    ra = a.test("m1", 1, test_kind="goal-guarding", outcome="deceptive",
               score=77, test_digest=PIN)
    rb = b.test("m1", 1, test_kind="goal-guarding", outcome="deceptive",
               score=77, test_digest=PIN)
    assert ra.digest == rb.digest  # deterministic across instances
    # tamper breaks verify()
    object.__setattr__(ra, "outcome", "aligned")
    assert not ra.verify()
    da = _da()
    da.test("m1", 1)
    da.detect("m1", 2)
    da.mitigate("m1", 3)
    errors = []
    def _reader():
        try:
            for _ in range(50):
                da.report(4)
                da.stats(4)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)
    threads = [threading.Thread(target=_reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    # records are frozen
    rec = da.test_record("tst-1", 4)
    with pytest.raises(Exception):
        rec.outcome = "x"  # type: ignore


# 15. main() subprocess check
def test_main_subprocess():
    r = subprocess.run([sys.executable, str(MOD_PATH)], capture_output=True,
                       text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    assert "deceptive-alignment OK" in r.stdout
