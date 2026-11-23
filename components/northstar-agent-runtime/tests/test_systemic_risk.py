"""15 tests for systemic_risk.py."""

import ast
import importlib.util
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD_PATH = Path(__file__).resolve().parent.parent / "systemic_risk.py"


def _load():
    spec = importlib.util.spec_from_file_location("systemic_risk", MOD_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["systemic_risk"] = mod  # frozen dataclasses need this
    spec.loader.exec_module(mod)
    return mod


sr_mod = _load()

PIN = "sha256:" + "a" * 64


def _sr():
    return sr_mod.SystemicRisk()


# 1. version/schema pins
def test_pins():
    assert sr_mod.SYSTEMIC_RISK_VERSION == "systemic-risk.v1"
    assert sr_mod.SCHEMA_PIN == "northstar.systemic-risk.v1"
    assert set(sr_mod.FLOPS_CLASSES) == {"below-1e24", "1e24-to-1e25", "above-1e25"}
    assert set(sr_mod.RISK_VECTORS) >= {
        "cbrn-uplift", "cyber-offense-uplift", "autonomous-replication",
        "loss-of-control", "large-scale-persuasion", "critical-infrastructure",
        "discrimination-at-scale", "power-concentration",
    }
    assert set(sr_mod.ASSESS_VERDICTS) == {"systemic", "elevated", "limited", "minimal"}
    assert set(sr_mod.MITIGATION_MEASURES) == {
        "red-team-eval", "capability-restriction", "staged-deployment",
        "monitoring-plan", "incident-reporting", "security-hardening",
        "access-controls", "rollback-plan",
    }
    assert set(sr_mod.RETIRE_REASONS) == {
        "manual", "model-withdrawn", "superseded", "decommissioned",
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


# 3. register roundtrip + verify()
def test_register_roundtrip():
    sr = _sr()
    rec = sr.register_model("m1", 1, flops_class="above-1e25",
                            provider="lab", model_digest=PIN)
    assert rec.model_id == "m1"
    assert rec.flops_class == "above-1e25"
    assert rec.verify()
    back = sr.model_record("m1", 2)
    assert back.digest == rec.digest
    assert sr.model_ids(3) == ("m1",)


# 4. duplicate + bad-input table + seq-burn + rejected-row accounting
def test_register_bad_inputs():
    sr = _sr()
    sr.register_model("m1", 1)
    with pytest.raises(sr_mod.DuplicateModelError):
        sr.register_model("m1", 2)
    cases = [
        ("", 3, "below-1e24", "", PIN),               # bad id
        ("m-x", 4, "huge", "", PIN),                  # bad flops class
        ("m-x", 5, "below-1e24", "", "not-a-pin"),     # bad digest
        ("m-x", 6, "below-1e24", "x" * 129, PIN),     # provider too long
        ("x" * 129, 7, "below-1e24", "", PIN),        # id too long
        (123, 8, "below-1e24", "", PIN),              # non-str id
        ("m-x", 9, None, "", PIN),                    # non-str flops class
    ]
    for mid, seq, fc, prov, dig in cases:
        with pytest.raises(sr_mod.SystemicRiskError):
            sr.register_model(mid, seq, flops_class=fc, provider=prov,
                              model_digest=dig)
    assert sr.stats(10)["rejected"] == 8  # 1 duplicate + 7 bad inputs
    assert len(sr.audit_log(11)) == 8 + 1  # rejected rows + 1 register row


# 5. assess roundtrip + minted ids + verify()
def test_assess_roundtrip():
    sr = _sr()
    sr.register_model("m1", 1)
    a1 = sr.assess("m1", 2, risk_vector="cbrn-uplift", verdict="systemic",
                   score=95, assessment_digest=PIN)
    assert a1.assessment_id == "asmt-1"
    assert a1.verdict == "systemic" and a1.score == 95
    assert a1.verify()
    a2 = sr.assess("m1", 3, risk_vector="loss-of-control", verdict="minimal")
    assert a2.assessment_id == "asmt-2"
    assert a2.verify()
    assert sr.assessments_for("m1", 4) == ("asmt-1", "asmt-2")
    back = sr.assessment_record("asmt-1", 5)
    assert back.digest == a1.digest


# 6. assess bad-input table (unknown model, bad vocab, bad score, bad digest)
def test_assess_bad_inputs():
    sr = _sr()
    sr.register_model("m1", 1)
    with pytest.raises(sr_mod.UnknownModelError):
        sr.assess("nope", 2)
    cases = [
        ("m1", 3, "aliens", "systemic", 50, PIN),      # bad vector
        ("m1", 4, "loss-of-control", "doom", 50, PIN), # bad verdict
        ("m1", 5, "loss-of-control", "elevated", -1, PIN),   # score too low
        ("m1", 6, "loss-of-control", "elevated", 101, PIN), # score too high
        ("m1", 7, "loss-of-control", "elevated", True, PIN),# bool score
        ("m1", 8, "loss-of-control", "elevated", 1.5, PIN), # float score
        ("m1", 9, "loss-of-control", "elevated", 50, "bad-pin"),  # bad digest
        ("m1", 10, "loss-of-control", "elevated", 50, 123),       # non-str digest
        ("m1", 11, 7, "elevated", 50, PIN),            # non-str vector
        ("", 12, "loss-of-control", "elevated", 50, PIN),  # bad id
    ]
    for mid, seq, vec, verd, sc, dig in cases:
        with pytest.raises(sr_mod.SystemicRiskError):
            sr.assess(mid, seq, risk_vector=vec, verdict=verd, score=sc,
                      assessment_digest=dig)
    assert sr.stats(13)["rejected"] == 11  # 1 unknown + 10 bad inputs


# 7. full vocabulary acceptance (all 4 verdicts, all 8 vectors)
def test_assess_full_vocabulary():
    sr = _sr()
    sr.register_model("m1", 1)
    for i, (vec, verd) in enumerate(
            zip(sr_mod.RISK_VECTORS, sr_mod.ASSESS_VERDICTS * 2)):
        rec = sr.assess("m1", 2 + i, risk_vector=vec, verdict=verd, score=i)
        assert rec.verify()
    assert sr.stats(10)["assessments"] == 8


# 8. mitigate roundtrip + all-8 measures + minted ids
def test_mitigate_roundtrip():
    sr = _sr()
    sr.register_model("m1", 1)
    for i, meas in enumerate(sr_mod.MITIGATION_MEASURES):
        rec = sr.mitigate("m1", 2 + i, measure=meas, plan_digest=PIN)
        assert rec.verify()
        assert rec.mitigation_id == f"mit-{i + 1}"
    assert sr.mitigations_for("m1", 10) == tuple(f"mit-{i}" for i in range(1, 9))


# 9. mitigate refusals (unknown model, bad measure, retired model)
def test_mitigate_refusals():
    sr = _sr()
    sr.register_model("m1", 1)
    with pytest.raises(sr_mod.UnknownModelError):
        sr.mitigate("nope", 2)
    with pytest.raises(sr_mod.BadMeasureError):
        sr.mitigate("m1", 3, measure="nope")
    sr.retire("m1", 4)
    with pytest.raises(sr_mod.RetiredModelError):
        sr.mitigate("m1", 5)
    with pytest.raises(sr_mod.RetiredModelError):
        sr.assess("m1", 6)
    assert sr.is_retired("m1", 7) is True


# 10. retire terminality (re-retire, re-register refused, id never recycled)
def test_retire_terminality():
    sr = _sr()
    sr.register_model("m1", 1)
    r = sr.retire("m1", 2, reason="model-withdrawn")
    assert r.verify() and r.reason == "model-withdrawn"
    with pytest.raises(sr_mod.RetiredModelError):
        sr.retire("m1", 3)
    with pytest.raises(sr_mod.RetiredModelError):
        sr.register_model("m1", 4)  # retired check precedes duplicate check
    assert sr.retired_ids(5) == ("m1",)
    with pytest.raises(sr_mod.UnknownModelError):
        sr.retire("unknown", 6, reason="nope")  # unknown hits first
    sr.register_model("m2", 7)
    with pytest.raises(sr_mod.BadReasonError):
        sr.retire("m2", 8, reason="nope")
    assert sr.is_retired("m2", 9) is False
    # reads still work on retired models
    assert sr.model_record("m1", 10).model_id == "m1"


# 11. seq discipline (rewind bare, malformed seqs, failed-mutation-consumes-seq)
def test_seq_discipline():
    sr = _sr()
    with pytest.raises(sr_mod.SeqOrderError):
        sr.register_model("m1", 0)   # must be a positive claimant
    sr.register_model("m1", 1)
    with pytest.raises(sr_mod.SeqOrderError):  # rewind: raises bare
        sr.register_model("m2", 1)
    with pytest.raises(sr_mod.SeqOrderError):  # rewind on assess
        sr.assess("m1", 1)
    for bad in (True, "2", 2.0, None):
        with pytest.raises(sr_mod.SeqOrderError):
            sr.register_model("mx", bad)
    n_rejected_before = sr.stats(2)["rejected"]
    with pytest.raises(sr_mod.BadVectorError):  # failed mutation burns seq
        sr.assess("m1", 3, risk_vector="nope")
    assert sr.stats(4)["rejected"] == n_rejected_before + 1
    with pytest.raises(sr_mod.SeqOrderError):  # burned seq 3 is consumed
        sr.assess("m1", 3)
    sr.assess("m1", 5, risk_vector="loss-of-control")  # seq 5 still free
    assert sr.stats(6)["assessments"] == 1


# 12. report semantics (postures, scoping, read purity)
def test_report_semantics():
    sr = _sr()
    rep0 = sr.report(1)
    assert rep0.posture == "not-assessed" and rep0.n_models == 0
    assert rep0.verify()
    sr.register_model("m1", 2)
    sr.register_model("m2", 3)
    rep1 = sr.report(4)
    assert rep1.posture == "not-assessed" and rep1.n_models == 2
    sr.assess("m1", 5, verdict="limited", score=30)
    rep2 = sr.report(6)
    assert rep2.posture == "limited"
    assert rep2.verdict_tallies == (("limited", 1),)
    sr.assess("m2", 7, verdict="systemic", score=90)
    rep3 = sr.report(8)
    assert rep3.posture == "systemic-confirmed"
    assert rep3.n_assessments == 2
    sr.mitigate("m2", 9)
    rep4 = sr.report(10)
    assert rep4.n_mitigations == 1
    # scoped report
    scoped = sr.report(11, model_id="m1")
    assert scoped.posture == "limited" and scoped.n_models == 1
    assert scoped.n_assessments == 1
    with pytest.raises(sr_mod.UnknownModelError):
        sr.report(12, model_id="nope")
    # read purity: same-seq reads twice, no audit rows, no seq consumption
    audit_before = len(sr.audit_log(13))
    a = sr.report(14)
    b = sr.report(14)
    assert a.digest == b.digest
    assert len(sr.audit_log(15)) == audit_before
    assert sr.stats(16)["seq"] == 9  # last mutation seq, reads claim nothing
    # minimal-only posture
    sr.register_model("m3", 17)
    sr.assess("m3", 18, verdict="minimal")
    assert sr.report(19, model_id="m3").posture == "minimal"
    # elevated beats limited
    sr.register_model("m4", 20)
    sr.assess("m4", 21, verdict="limited")
    sr.assess("m4", 22, verdict="elevated")
    assert sr.report(23, model_id="m4").posture == "elevated"


# 13. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    sr = _sr()
    sr.register_model("m1", 1, flops_class="above-1e25")
    sr.assess("m1", 2, verdict="elevated", score=70)
    sr.mitigate("m1", 3)
    log = sr.audit_log(4)
    kinds = [row["kind"] for row in log]
    assert kinds == ["systemic-risk.registered", "systemic-risk.assessed",
                     "systemic-risk.mitigated"]
    import json as _json
    blob = _json.dumps(log)
    for banned in ("weights", "checkpoint", "training", "secret", "raw"):
        assert banned not in blob
    # leak ban at builder level
    with pytest.raises(sr_mod.AuditKindError):
        sr_mod.systemic_risk_audit_event("assessed", {"weights": "x"})
    with pytest.raises(sr_mod.AuditKindError):
        sr_mod.systemic_risk_audit_event("assessed", {"model": "x"})
    # bad kind
    with pytest.raises(sr_mod.AuditKindError):
        sr_mod.systemic_risk_audit_event("nope", {})
    # pinned vocabulary values stay emittable as declared data
    row = sr_mod.systemic_risk_audit_event(
        "assessed", {"verdict": "systemic", "measure": "red-team-eval"})
    assert row["details"]["verdict"] == "systemic"


# 14. cross-instance digest determinism + tamper breaks verify()
def test_digest_determinism_and_tamper():
    sr1, sr2 = _sr(), _sr()
    r1 = sr1.register_model("m1", 1, flops_class="above-1e25", provider="lab",
                            model_digest=PIN)
    r2 = sr2.register_model("m1", 1, flops_class="above-1e25", provider="lab",
                            model_digest=PIN)
    assert r1.digest == r2.digest
    a1 = sr1.assess("m1", 2, verdict="systemic", score=95)
    a2 = sr2.assess("m1", 2, verdict="systemic", score=95)
    assert a1.digest == a2.digest
    m1 = sr1.mitigate("m1", 3)
    m2 = sr2.mitigate("m1", 3)
    assert m1.digest == m2.digest
    # tamper breaks verify()
    object.__setattr__(r1, "flops_class", "below-1e24")
    assert r1.verify() is False
    assert r2.verify() is True
    # frozen-ness
    import dataclasses
    assert dataclasses.is_dataclass(r1)
    with pytest.raises(Exception):  # frozen dataclasses refuse attribute sets
        r1.provider = "evil-lab"


# 15. main() subprocess check + thread safety smoke
def test_main_and_concurrency():
    proc = subprocess.run([sys.executable, str(MOD_PATH)], capture_output=True,
                          text=True, timeout=30)
    assert proc.returncode == 0, proc.stderr
    assert "systemic-risk OK: register, assess, mitigate, report, pins, audit" in proc.stdout
    sr = _sr()
    sr.register_model("m1", 1)

    def reader():
        for _ in range(50):
            sr.model_record("m1", 2)
            sr.report(3)
            sr.stats(4)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
