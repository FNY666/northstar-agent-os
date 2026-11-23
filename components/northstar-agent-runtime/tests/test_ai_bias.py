"""Tests for ai_bias.py: AI-bias detection/mitigation decision ledger."""

from __future__ import annotations

import ast
import json
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import ai_bias


HERE = Path(__file__).resolve().parent
RUNTIME_ROOT = HERE.parent
MODULE_PATH = RUNTIME_ROOT / "ai_bias.py"


def _fresh():
    return ai_bias.AIBias()


# 1 -------------------------------------------------------------------------
def test_pins_and_vocabularies():
    assert ai_bias.AI_BIAS_VERSION == "ai-bias.v1"
    assert ai_bias.SCHEMA_PIN == "northstar.ai-bias.v1"
    assert len(ai_bias.BIAS_KINDS) == 8
    assert len(ai_bias.DETECT_VERDICTS) == 4
    assert len(ai_bias.MITIGATION_STRATEGIES) == 8
    assert ai_bias.VERIFY_VERDICTS == ("verified", "tampered")
    assert len(ai_bias.EVALUATE_POSTURES) == 5
    assert len(ai_bias.RETIRE_REASONS) == 4
    assert set(ai_bias.AUDIT_KINDS) == {
        "detected",
        "mitigated",
        "retired",
        "rejected",
    }


# 2 -------------------------------------------------------------------------
def test_stdlib_only_ast_and_selfcheck():
    src = MODULE_PATH.read_text(encoding="utf-8")
    tree = ast.parse(src)
    allowed = {
        "__future__",
        "ast",
        "dataclasses",
        "hashlib",
        "json",
        "pathlib",
        "threading",
        "typing",
        "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                assert node.module.split(".")[0] in allowed, node.module
    assert ai_bias.stdlib_only() is True


# 3 -------------------------------------------------------------------------
def test_detect_roundtrip_verify_frozen():
    ledger = _fresh()
    rec = ledger.detect(
        "sys-1", 1, bias_kind="algorithmic-bias", verdict="bias-detected"
    )
    assert rec.detection_id == "det-1"
    assert rec.system_id == "sys-1"
    assert rec.bias_kind == "algorithmic-bias"
    assert rec.verdict == "bias-detected"
    assert rec.digest.startswith("sha256:")
    assert rec.verify() is True
    with pytest.raises(Exception):
        rec.verdict = "no-bias"  # frozen dataclass
    # record is returned from the pure-read view too
    assert ledger.detection_record("det-1", 0) is rec
    # digest pin reproducibility: same inputs -> same digest
    other = _fresh()
    rec2 = other.detect(
        "sys-1", 1, bias_kind="algorithmic-bias", verdict="bias-detected"
    )
    assert rec2.digest == rec.digest


# 4 -------------------------------------------------------------------------
def test_detect_bad_input_table_seq_burn_and_rejected_rows():
    ledger = _fresh()
    # each failed mutation consumes its seq and books a rejected row
    with pytest.raises(ai_bias.BadBiasKindError):
        ledger.detect("sys-1", 1, bias_kind="bogus-kind")
    with pytest.raises(ai_bias.BadVerdictError):
        ledger.detect("sys-1", 2, verdict="bogus-verdict")
    with pytest.raises(ai_bias.BadDigestError):
        ledger.detect("sys-1", 3, detection_digest="not-a-pin")
    with pytest.raises(ai_bias.BadSystemError):
        ledger.detect("", 4)
    with pytest.raises(ai_bias.BadSystemError):
        ledger.detect(None, 5)
    rows = ledger.audit_log(0)
    rejected = [r for r in rows if r["kind"] == "rejected"]
    assert len(rejected) == 5
    assert [r["seq"] for r in rejected] == [1, 2, 3, 4, 5]
    assert all(
        r["schema"] == "audit.ndjson/1" and r["module"] == "ai-bias"
        for r in rejected
    )
    # rewind raises bare with zero rows consumed
    before = len(ledger.audit_log(0))
    with pytest.raises(ai_bias.SeqOrderError):
        ledger.detect("sys-1", 5)  # seq must strictly increase; 5 already used
    assert len(ledger.audit_log(0)) == before


# 5 -------------------------------------------------------------------------
def test_full_bias_kind_vocabulary():
    ledger = _fresh()
    seq = 0
    for i, kind in enumerate(ai_bias.BIAS_KINDS):
        seq += 1
        rec = ledger.detect("sys-k", seq, bias_kind=kind, verdict="no-bias")
        assert rec.bias_kind == kind
        assert rec.verify()
    assert ledger.stats(0)["n_detections"] == len(ai_bias.BIAS_KINDS)


# 6 -------------------------------------------------------------------------
def test_mitigate_roundtrip_unknown_detection_refusal():
    ledger = _fresh()
    det = ledger.detect("sys-1", 1, bias_kind="sampling-bias",
                        verdict="bias-detected")
    mit = ledger.mitigate(
        det.detection_id, 2, strategy="resampling",
        mitigation_digest="sha256:abc",
    )
    assert mit.mitigation_id == "mit-1"
    assert mit.detection_id == det.detection_id
    assert mit.strategy == "resampling"
    assert mit.verify() is True
    assert ledger.mitigations_for(det.detection_id, 0) == [mit]
    # chainable: second mitigation on the same detection
    mit2 = ledger.mitigate(det.detection_id, 3, strategy="retraining")
    assert mit2.mitigation_id == "mit-2"
    # unknown detection refuses, consuming its seq
    before = len(ledger.audit_log(0))
    with pytest.raises(ai_bias.UnknownDetectionError):
        ledger.mitigate("det-999", 4)
    rows = ledger.audit_log(0)
    assert len(rows) == before + 1
    assert rows[-1]["kind"] == "rejected"


# 7 -------------------------------------------------------------------------
def test_mitigate_bad_input_table_and_retired_refusal():
    ledger = _fresh()
    det = ledger.detect("sys-1", 1, verdict="bias-detected")
    with pytest.raises(ai_bias.BadStrategyError):
        ledger.mitigate(det.detection_id, 2, strategy="bogus")
    with pytest.raises(ai_bias.BadDigestError):
        ledger.mitigate(det.detection_id, 3, mitigation_digest="raw-bytes")
    with pytest.raises(ai_bias.BadSystemError):
        ledger.mitigate("", 4)
    ledger.retire("sys-1", 5)
    with pytest.raises(ai_bias.RetiredSystemError):
        ledger.mitigate(det.detection_id, 6)
    # pure reads still work after retirement
    assert ledger.detection_record(det.detection_id, 0).verdict == "bias-detected"
    rep = ledger.evaluate("sys-1", 0)
    assert rep.posture == "bias-open"
    rows = ledger.audit_log(0)
    rejected = [r for r in rows if r["kind"] == "rejected"]
    assert [r["seq"] for r in rejected] == [2, 3, 4, 6]


# 8 -------------------------------------------------------------------------
def test_full_mitigation_strategy_vocabulary():
    ledger = _fresh()
    det = ledger.detect("sys-1", 1, verdict="bias-detected")
    seq = 1
    for i, strategy in enumerate(ai_bias.MITIGATION_STRATEGIES):
        seq += 1
        mit = ledger.mitigate(det.detection_id, seq, strategy=strategy)
        assert mit.strategy == strategy
        assert mit.verify()
    assert ledger.stats(0)["n_mitigations"] == len(ai_bias.MITIGATION_STRATEGIES)


# 9 -------------------------------------------------------------------------
def test_verify_semantics_tamper_as_data_unknown_read_purity():
    ledger = _fresh()
    det = ledger.detect("sys-1", 1, verdict="suspected")
    mit = ledger.mitigate(det.detection_id, 2, strategy="reweighting")
    before = len(ledger.audit_log(0))
    rep = ledger.verify(det.detection_id, 5)
    assert rep.verdict == "verified"
    assert rep.integrity_ok is True
    assert rep.verify() is True
    assert len(ledger.audit_log(0)) == before  # pure read: no audit row
    # tamper is reported as data, never raised
    object.__setattr__(det, "verdict", "no-bias")
    rep2 = ledger.verify(det.detection_id, 6)
    assert rep2.verdict == "tampered"
    assert rep2.integrity_ok is False
    rep3 = ledger.verify(mit.mitigation_id, 7)
    assert rep3.verdict == "verified"
    with pytest.raises(ai_bias.UnknownRecordError):
        ledger.verify("det-999", 8)
    with pytest.raises(ai_bias.SeqOrderError):
        ledger.verify(det.detection_id, -1)


# 10 ------------------------------------------------------------------------
def test_evaluate_posture_math_all_five_postures_and_precedence():
    # unevaluated is unreachable by construction: every system has >=1
    # detection once known. Test the four reachable postures.
    ledger = _fresh()
    d1 = ledger.detect("open", 1, verdict="bias-detected")
    rep = ledger.evaluate("open", 0)
    assert rep.posture == "bias-open"
    assert rep.verify() is True
    # uncertain outranks everything but bias-open
    ledger.detect("open", 2, verdict="suspected")
    assert ledger.evaluate("open", 0).posture == "bias-open"
    ledger.mitigate(d1.detection_id, 3)
    assert ledger.evaluate("open", 0).posture == "uncertain"
    # mitigated: all bias-detected covered, no open
    ledger2 = _fresh()
    d = ledger2.detect("m", 1, verdict="bias-detected")
    ledger2.mitigate(d.detection_id, 2)
    assert ledger2.evaluate("m", 0).posture == "mitigated"
    # clean: all no-bias
    ledger3 = _fresh()
    ledger3.detect("c", 1, verdict="no-bias")
    ledger3.detect("c", 2, verdict="no-bias")
    rep3 = ledger3.evaluate("c", 0)
    assert rep3.posture == "clean"
    assert rep3.n_no_bias == 2
    # inconclusive -> uncertain
    ledger4 = _fresh()
    ledger4.detect("u", 1, verdict="inconclusive")
    assert ledger4.evaluate("u", 0).posture == "uncertain"
    with pytest.raises(ai_bias.UnknownSystemError):
        ledger.evaluate("nope", 0)


# 11 ------------------------------------------------------------------------
def test_evaluate_read_purity_tallies_and_unknown_refusal():
    ledger = _fresh()
    det = ledger.detect("sys-1", 1, verdict="bias-detected")
    before = len(ledger.audit_log(0))
    rep = ledger.evaluate("sys-1", 0)
    assert rep.n_detections == 1
    assert rep.n_bias_detected == 1
    assert rep.n_mitigated == 0
    assert len(ledger.audit_log(0)) == before  # pure read
    # tamper flips integrity_ok as data
    object.__setattr__(det, "bias_kind", "measurement-bias")
    rep2 = ledger.evaluate("sys-1", 0)
    assert rep2.integrity_ok is False
    assert rep2.posture == "bias-open"
    with pytest.raises(ai_bias.UnknownSystemError):
        ledger.evaluate("ghost", 0)


# 12 ------------------------------------------------------------------------
def test_retire_terminality_id_non_recycling_bad_reason():
    ledger = _fresh()
    ledger.detect("sys-1", 1)
    rec = ledger.retire("sys-1", 2, reason="decommissioned")
    assert rec.reason == "decommissioned"
    assert rec.verify() is True
    assert ledger.retired_ids(0) == ("sys-1",)
    # post-retire mutations refused; ids never recycled
    with pytest.raises(ai_bias.RetiredSystemError):
        ledger.detect("sys-1", 3)
    with pytest.raises(ai_bias.RetiredSystemError):
        ledger.retire("sys-1", 4)
    with pytest.raises(ai_bias.BadReasonError):
        ledger.retire("sys-1", 5, reason="bogus")
    with pytest.raises(ai_bias.UnknownSystemError):
        ledger.retire("ghost", 6)
    # post-retire reads still work
    assert ledger.detection_record("det-1", 0).system_id == "sys-1"
    assert ledger.evaluate("sys-1", 0).posture == "uncertain"
    assert ledger.retire is not None


# 13 ------------------------------------------------------------------------
def test_seq_discipline_rewind_bare_malformed_and_failed_burn():
    ledger = _fresh()
    # genesis rewind: seq 0 raises bare (no audit row)
    with pytest.raises(ai_bias.SeqOrderError):
        ledger.detect("sys-1", 0)
    assert ledger.audit_log(0) == []
    ledger.detect("sys-1", 1)
    # malformed seqs raise bare without burning
    for bad in (True, 1.5, "2", None):
        before = len(ledger.audit_log(0))
        with pytest.raises(ai_bias.SeqOrderError):
            ledger.detect("sys-2", bad)
        assert len(ledger.audit_log(0)) == before
    # failed mutation consumes its seq (claim-then-burn)
    with pytest.raises(ai_bias.BadVerdictError):
        ledger.detect("sys-2", 2, verdict="bogus")
    assert [r["kind"] for r in ledger.audit_log(0)] == ["detected", "rejected"]
    # successful mutation takes the next seq
    rec = ledger.detect("sys-2", 3)
    assert rec.detection_id == "det-2"


# 14 ------------------------------------------------------------------------
def test_audit_shapes_leak_ban_and_bad_kind():
    ledger = _fresh()
    det = ledger.detect("sys-1", 1, bias_kind="annotation-bias",
                       verdict="bias-detected")
    ledger.mitigate(det.detection_id, 2, strategy="data-augmentation")
    ledger.retire("sys-1", 3)
    rows = ledger.audit_log(0)
    kinds = [r["kind"] for r in rows]
    assert kinds == ["detected", "mitigated", "retired"]
    for r in rows:
        assert r["schema"] == "audit.ndjson/1"
        assert r["module"] == "ai-bias"
        assert r["version"] == "ai-bias.v1"
        # pinned vocabulary values remain emittable as declared data
    details = rows[0]["details"]
    assert details["bias_kind"] == "annotation-bias"
    assert details["verdict"] == "bias-detected"
    # raw material keys are banned at the audit builder level
    for banned in ("dataset", "labels", "predictions", "demographics",
                   "user_data", "weights", "transcript"):
        with pytest.raises(ai_bias.AIBiasError):
            ai_bias.ai_bias_audit_event("detected", 9, **{banned: "raw"})
    # unknown audit kind refuses
    with pytest.raises(ai_bias.AuditKindError):
        ai_bias.ai_bias_audit_event("bogus-kind", 9)
    with pytest.raises(ai_bias.SeqOrderError):
        ai_bias.ai_bias_audit_event("detected", "nine")


# 15 ------------------------------------------------------------------------
def test_cross_instance_determinism_thread_smoke_and_main():
    ledger = _fresh()
    d1 = ledger.detect("sys-1", 1, verdict="bias-detected")
    m1 = ledger.mitigate(d1.detection_id, 2, strategy="no-action")
    ev = ledger.evaluate("sys-1", 0)
    other = _fresh()
    d2 = other.detect("sys-1", 1, verdict="bias-detected")
    m2 = other.mitigate(d2.detection_id, 2, strategy="no-action")
    ev2 = other.evaluate("sys-1", 0)
    assert d2.digest == d1.digest
    assert m2.digest == m1.digest
    assert ev2.digest == ev.digest
    assert ledger.stats(0)["n_systems"] == 1
    assert ledger.system_ids(0) == ("sys-1",)
    assert ledger.detection_ids(0) == ("det-1",)
    assert ledger.mitigation_ids(0) == ("mit-1",)
    # 8-thread read smoke over pure reads
    errors = []

    def reader():
        try:
            for _ in range(50):
                ledger.evaluate("sys-1", 0)
                ledger.verify("det-1", 0)
                ledger.stats(0)
                ledger.audit_log(0)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    # main() self-check runs clean as a subprocess
    proc = subprocess.run(
        [sys.executable, str(MODULE_PATH)],
        capture_output=True,
        text=True,
        cwd=str(RUNTIME_ROOT),
    )
    assert proc.returncode == 0, proc.stderr
    assert "ai-bias OK" in proc.stdout
