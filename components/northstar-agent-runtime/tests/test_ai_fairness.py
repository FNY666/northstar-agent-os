"""15 tests for ai_fairness (assess/mitigate/verify, simulated ledger)."""

import ast
import hashlib
import importlib.util
import subprocess
import sys
import threading
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
RUNTIME = HERE.parent
MODULE = RUNTIME / "ai_fairness.py"


def load_module():
    spec = importlib.util.spec_from_file_location("ai_fairness", str(MODULE))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["ai_fairness"] = mod
    spec.loader.exec_module(mod)
    return mod


af = load_module()

_GOOD_DIGEST = "sha256:" + hashlib.sha256(b"material").hexdigest()


# 1. pins
def test_version_and_schema_pins():
    assert af.AI_FAIRNESS_VERSION == "ai-fairness.v1"
    assert af.AI_FAIRNESS_SCHEMA == "northstar.ai-fairness.v1"
    assert af.AUDIT_SCHEMA == "audit.ndjson/1"
    assert len(af.DIMENSIONS) == 8
    assert len(af.VERDICTS) == 5
    assert len(af.STRATEGIES) == 8
    assert len(af.REASONS) == 4
    assert set(af.KINDS) == {"assessed", "mitigated", "retired", "rejected"}


# 2. stdlib-only AST check
def test_stdlib_only():
    tree = ast.parse(MODULE.read_text(encoding="utf-8"))
    seen = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            seen.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                seen.add(node.module.split(".")[0])
    assert seen <= af._STDLIB_IMPORTS | {"canonical_json"}
    assert af.stdlib_only() is True


# 3. assess roundtrip + minting + verify() + frozen-ness
def test_assess_roundtrip_minting_frozen():
    ledger = af.AIFairness()
    rec = ledger.assess("sys-1", "disparate-impact", "unfair", 1,
                        assessment_digest=_GOOD_DIGEST)
    assert rec.assessment_id == "asr-1"
    assert rec.system_id == "sys-1"
    assert rec.verify("asr-1", "sys-1", "disparate-impact", "unfair",
                      _GOOD_DIGEST)
    with pytest.raises(Exception):
        rec.system_id = "tampered"  # frozen
    rec2 = ledger.assess("sys-1", "calibration", "fair", 2)
    assert rec2.assessment_id == "asr-2"


# 4. assess bad-input table + seq-burn + rejected-row accounting
def test_assess_bad_inputs_burn_and_accounting():
    ledger = af.AIFairness()
    seq = [0]

    def nxt():
        seq[0] += 1
        return seq[0]

    bad_calls = [
        lambda: ledger.assess("", "disparate-impact", "fair", nxt()),
        lambda: ledger.assess("sys 1", "disparate-impact", "fair", nxt()),
        lambda: ledger.assess("s" * 257, "disparate-impact", "fair", nxt()),
        lambda: ledger.assess("sys-1", "bad-dim", "fair", nxt()),
        lambda: ledger.assess("sys-1", 123, "fair", nxt()),
        lambda: ledger.assess("sys-1", "disparate-impact", "bad-verdict",
                              nxt()),
        lambda: ledger.assess("sys-1", "disparate-impact", True, nxt()),
        lambda: ledger.assess("sys-1", "disparate-impact", "fair", nxt(),
                              assessment_digest="not-a-pin"),
    ]
    for i, call in enumerate(bad_calls):
        with pytest.raises(af.AIFairnessError):
            call()
        rejected = [r for r in ledger.audit_log(nxt()) if r["kind"] == "rejected"]
        assert len(rejected) == i + 1, f"bad call {i}"
    # seq rewinds raise bare, no row
    rows_before = len(ledger.audit_log(nxt()))
    with pytest.raises(af.SeqOrderError):
        ledger.assess("sys-1", "disparate-impact", "fair", 1)
    assert len(ledger.audit_log(nxt())) == rows_before
    # malformed seqs
    for bad in (True, "1", 1.5, None):
        with pytest.raises(af.SeqOrderError):
            ledger.assess("sys-1", "disparate-impact", "fair", bad)


# 5. full 8-dimension vocabulary
def test_full_dimension_vocabulary():
    ledger = af.AIFairness()
    seq = [0]
    for i, dim in enumerate(af.DIMENSIONS):
        seq[0] += 1
        rec = ledger.assess(f"sys-{i}", dim, "fair", seq[0])
        assert rec.dimension == dim
        assert rec.verify(rec.assessment_id, f"sys-{i}", dim, "fair", "")


# 6. full 5-verdict vocabulary
def test_full_verdict_vocabulary():
    ledger = af.AIFairness()
    seq = [0]
    for verdict in af.VERDICTS:
        seq[0] += 1
        rec = ledger.assess("sys-1", "equalized-odds", verdict, seq[0])
        assert rec.verdict == verdict


# 7. mitigate roundtrip + minted ids + verify roundtrip
def test_mitigate_roundtrip_and_verify():
    ledger = af.AIFairness()
    a = ledger.assess("sys-1", "disparate-impact", "unfair", 1)
    m = ledger.mitigate(a.assessment_id, 2, strategy="reweight",
                        mitigation_digest=_GOOD_DIGEST)
    assert m.mitigation_id == "mit-1"
    assert m.verify("mit-1", "asr-1", "sys-1", "reweight", _GOOD_DIGEST)
    m2 = ledger.mitigate(a.assessment_id, 3)  # chainable, default strategy
    assert m2.mitigation_id == "mit-2"
    assert ledger.mitigations_for(a.assessment_id, 4) == ("mit-1", "mit-2")
    assert ledger.verify("mit-1", 5).verdict == "verified"
    assert ledger.verify("asr-1", 6).verdict == "verified"


# 8. mitigate refusals + bad strategy + seq-burn
def test_mitigate_refusals_and_burn():
    ledger = af.AIFairness()
    ledger.assess("sys-1", "disparate-impact", "unfair", 1)
    with pytest.raises(af.UnknownAssessmentError):
        ledger.mitigate("asr-999", 2)
    with pytest.raises(af.BadStrategyError):
        ledger.mitigate("asr-1", 3, strategy="handwave")
    with pytest.raises(af.BadDigestError):
        ledger.mitigate("asr-1", 4, mitigation_digest="bogus")
    assert len([r for r in ledger.audit_log(5)
                if r["kind"] == "rejected"]) == 3
    # retire blocks mitigate
    ledger.retire("sys-1", 6)
    with pytest.raises(af.RetiredSystemError):
        ledger.mitigate("asr-1", 7)


# 9. full 8-strategy vocabulary
def test_full_strategy_vocabulary():
    ledger = af.AIFairness()
    seq = [0]
    for i, strategy in enumerate(af.STRATEGIES):
        seq[0] += 1
        a = ledger.assess(f"sys-{i}", "statistical-parity", "marginal",
                          seq[0])
        seq[0] += 1
        m = ledger.mitigate(a.assessment_id, seq[0], strategy=strategy)
        assert m.strategy == strategy
        assert m.verify(m.mitigation_id, a.assessment_id, f"sys-{i}",
                        strategy, "")


# 10. verify semantics (unknown refusal, tamper-as-data)
def test_verify_unknown_and_tamper_as_data():
    ledger = af.AIFairness()
    a = ledger.assess("sys-1", "disparate-impact", "fair", 1)
    with pytest.raises(af.UnknownRecordError):
        ledger.verify("nope-1", 2)
    before = len(ledger.audit_log(3))
    ledger.verify("asr-1", 4)  # pure read: no new audit rows
    assert len(ledger.audit_log(5)) == before
    object.__setattr__(a, "verdict", "unfair")  # tamper the frozen record
    rep = ledger.verify("asr-1", 4)
    assert rep.verdict == "tampered"
    assert rep.verify("asr-1", "tampered")
    assert ledger.verify("asr-1", 5).verdict == "tampered"  # stays


# 11. read purity (same-seq twice, no audit rows, no seq consumption)
def test_read_purity():
    ledger = af.AIFairness()
    a = ledger.assess("sys-1", "disparate-impact", "fair", 1)
    ledger.mitigate(a.assessment_id, 2)
    before = len(ledger.audit_log(3))
    r1 = ledger.verify("asr-1", 4)
    r2 = ledger.verify("asr-1", 4)  # same seq twice: pure read
    assert r1.digest == r2.digest
    assert len(ledger.audit_log(5)) == before
    assert ledger.stats(6)["assessments"] == 1
    # views don't write either
    ledger.assessment_record("asr-1", 7)
    ledger.mitigation_record("mit-1", 8)
    ledger.assessments_for("sys-1", 9)
    ledger.mitigations_for("asr-1", 10)
    ledger.system_ids(11)
    assert len(ledger.audit_log(12)) == before


# 12. retire terminality + id non-recycling + bad reason + post-retire reads
def test_retire_terminality():
    ledger = af.AIFairness()
    ledger.assess("sys-1", "disparate-impact", "fair", 1)
    rec = ledger.retire("sys-1", 2, reason="decommissioned")
    assert rec.reason == "decommissioned"
    assert rec.verify("sys-1", "decommissioned")
    assert ledger.retired_ids(3) == ("sys-1",)
    with pytest.raises(af.DoubleRetireError):
        ledger.retire("sys-1", 4)
    with pytest.raises(af.UnknownSystemError):
        ledger.retire("sys-9", 5)
    with pytest.raises(af.BadReasonError):
        ledger.retire("sys-1", 6, reason="vendetta")
    with pytest.raises(af.RetiredSystemError):
        ledger.assess("sys-1", "calibration", "fair", 7)
    # reads still work post-retire
    assert ledger.assessment_record("asr-1", 8).system_id == "sys-1"
    assert ledger.verify("asr-1", 9).verdict == "verified"


# 13. seq discipline (rewind bare, malformed, failed-mutation-consumes-seq)
def test_seq_discipline():
    ledger = af.AIFairness()
    ledger.assess("sys-1", "disparate-impact", "fair", 1)
    before = len(ledger.audit_log(2))
    with pytest.raises(af.SeqOrderError):
        ledger.assess("sys-1", "disparate-impact", "fair", 1)  # rewind
    with pytest.raises(af.SeqOrderError):
        ledger.assess("sys-1", "disparate-impact", "fair", 0)  # rewind
    assert len(ledger.audit_log(3)) == before, "rewinds never burn: no rows"
    for bad_seq in (True, -1, "x", 2.0):
        with pytest.raises(af.SeqOrderError):
            ledger.assess("sys-1", "disparate-impact", "fair", bad_seq)
    assert len(ledger.audit_log(4)) == before, "malformed seqs never burn"
    # failed mutation consumes its seq and books a rejected row
    with pytest.raises(af.BadDimensionError):
        ledger.assess("sys-1", "bad-dim", "fair", 4)
    rejected = [r for r in ledger.audit_log(5) if r["kind"] == "rejected"]
    assert len(rejected) == 1
    assert rejected[0]["seq"] == 4
    # seq 4 was consumed: next live seq must exceed it
    with pytest.raises(af.SeqOrderError):
        ledger.assess("sys-1", "disparate-impact", "fair", 4)
    rec = ledger.assess("sys-1", "disparate-impact", "fair", 5)
    assert rec.assessment_id == "asr-2"


# 14. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    ev = af.ai_fairness_audit_event(
        "assessed", {"system_id": "s", "assessment_id": "asr-1",
                     "dimension": "disparate-impact", "verdict": "fair",
                     "assessment_digest": ""}, 1)
    assert ev["schema"] == "audit.ndjson/1"
    assert ev["module"] == "ai-fairness.v1"
    assert ev["kind"] == "assessed"
    assert ev["seq"] == 1
    with pytest.raises(af.AuditKindError):
        af.ai_fairness_audit_event("exploited", {}, 1)
    for banned in ("group", "protected_group", "outcome_rates", "score",
                   "prompt", "response", "label"):
        with pytest.raises(af.AuditKindError):
            af.ai_fairness_audit_event("assessed", {banned: "x"}, 1)
    # module-level emit carries no raw material either
    ledger = af.AIFairness()
    ledger.assess("sys-1", "disparate-impact", "fair", 1,
                  assessment_digest=_GOOD_DIGEST)
    for row in ledger.audit_log(2):
        assert not af._BANNED_DETAIL_KEYS.intersection(row["detail"].keys())


# 15. cross-instance digest determinism + thread smoke + main() subprocess
def test_determinism_threads_and_main():
    a1 = af.AIFairness()
    a2 = af.AIFairness()
    r1 = a1.assess("sys-1", "calibration", "fair", 1,
                   assessment_digest=_GOOD_DIGEST)
    r2 = a2.assess("sys-1", "calibration", "fair", 1,
                   assessment_digest=_GOOD_DIGEST)
    assert r1.digest == r2.digest  # deterministic across instances

    ledger = af.AIFairness()
    ledger.assess("sys-1", "disparate-impact", "fair", 1)
    errors = []

    def reader():
        try:
            for i in range(50):
                ledger.verify("asr-1", 2)
                ledger.stats(3)
                ledger.audit_log(4)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors

    proc = subprocess.run([sys.executable, str(MODULE)],
                          capture_output=True, text=True, cwd=str(RUNTIME))
    assert proc.returncode == 0
    assert "ai-fairness OK" in proc.stdout
