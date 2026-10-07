"""Tests for the ai-attack detection/defense decision ledger, Simulated."""

import ast
import dataclasses
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "ai_attack.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("ai_attack", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["ai_attack"] = module
    spec.loader.exec_module(module)
    return module


aa = _load()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert aa.AI_ATTACK_VERSION == "ai-attack.v1"
    assert aa.SCHEMA_PIN == "northstar.ai-attack.v1"
    assert aa.ATTACK_KINDS == (
        "prompt-injection",
        "jailbreak",
        "model-extraction",
        "data-poisoning",
        "backdoor-trigger",
        "adversarial-example",
        "inference-abuse",
        "supply-chain-attack",
    )
    assert aa.DETECT_VERDICTS == ("attack-detected", "suspected", "inconclusive", "no-attack")
    assert aa.DEFENSE_STRATEGIES == (
        "block-source",
        "isolate-system",
        "input-filtering",
        "rate-limiting",
        "rotate-credentials",
        "patch-deployment",
        "escalate-response",
        "no-action",
    )
    assert aa.VERIFY_VERDICTS == ("verified", "tampered")
    assert aa.POSTURES == ("unassessed", "under-attack", "contested", "defended", "clean")
    assert aa.RETIRE_REASONS == ("manual", "superseded", "decommissioned", "false-start")
    assert aa.AUDIT_KINDS == ("detected", "defended", "retired", "rejected")


# 2. stdlib-only AST check
def test_stdlib_only_ast():
    tree = ast.parse(MOD.read_text())
    allowed = {
        "hashlib", "json", "threading", "dataclasses", "typing",
        "__future__", "ast", "pathlib", "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                assert node.module.split(".")[0] in allowed
    assert aa.stdlib_only() is True


# 3. detect roundtrip + verify + frozen-ness
def test_detect_roundtrip_verify_frozen():
    ledger = aa.AIAttack()
    rec = ledger.detect("sys-1", 1, attack_kind="jailbreak",
                        verdict="attack-detected", severity=70,
                        detection_digest=PIN)
    assert rec.detection_id == "det-1"
    assert rec.system_id == "sys-1"
    assert rec.verify() is True
    assert dataclasses.is_dataclass(rec) and rec.__dataclass_params__.frozen
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.severity = 99  # type: ignore
    row = ledger.audit_log(1)[0]
    assert row["schema"] == "audit.ndjson/1"
    assert row["kind"] == "detected"
    assert "payload" not in row["details"]
    assert row["details"]["severity"] == 70


# 4. detect bad-input table + seq-burn + rejected-row accounting + bare rewind
def test_detect_bad_inputs_burn_seq():
    ledger = aa.AIAttack()
    bads = [
        ("", 1, "prompt-injection", "no-attack", 0, ""),
        ("sys-1", 2, "not-a-kind", "no-attack", 0, ""),
        ("sys-1", 3, "prompt-injection", "bogus-verdict", 0, ""),
        ("sys-1", 4, "prompt-injection", "no-attack", True, ""),
        ("sys-1", 5, "prompt-injection", "no-attack", 101, ""),
        ("sys-1", 6, "prompt-injection", "no-attack", 0, "not-a-digest"),
    ]
    for system_id, seq, kind, verdict, sev, digest in bads:
        with pytest.raises(aa.AIAttackError):
            ledger.detect(system_id, seq, attack_kind=kind,
                          verdict=verdict, severity=sev,
                          detection_digest=digest)
    assert ledger.stats(0)["n_audit_rows"] == 6
    assert all(r["kind"] == "rejected" for r in ledger.audit_log(0))
    assert ledger.stats(0)["seq"] == 6
    # rewind raises bare with zero extra rows
    with pytest.raises(aa.SeqOrderError):
        ledger.detect("sys-1", 3)
    assert ledger.stats(0)["n_audit_rows"] == 6


# 5. full 8-kind vocabulary acceptance
def test_full_attack_kind_vocabulary():
    ledger = aa.AIAttack()
    seq = 0
    for i, kind in enumerate(aa.ATTACK_KINDS):
        seq += 1
        rec = ledger.detect(f"sys-{i}", seq, attack_kind=kind,
                            verdict="no-attack", severity=0)
        assert rec.attack_kind == kind
        assert rec.verify() is True
    assert ledger.stats(0)["n_detections"] == 8
    assert ledger.stats(0)["n_systems"] == 8


# 6. full 4-verdict vocabulary + severity boundaries
def test_full_verdict_vocabulary_and_severity_bounds():
    ledger = aa.AIAttack()
    seq = 0
    for verdict in aa.DETECT_VERDICTS:
        seq += 1
        rec = ledger.detect(f"sys-{verdict}", seq, verdict=verdict)
        assert rec.verdict == verdict
    for sev in (0, 100):
        seq += 1
        ledger.detect("sys-bound", seq, severity=sev)
    for bad in (-1, 101, 1.5, "70", None):
        seq += 1
        with pytest.raises(aa.AIAttackError):
            ledger.detect("sys-bad", seq, severity=bad)
    assert ledger.stats(0)["n_detections"] == 6


# 7. defend roundtrip + minted ids + chainable
def test_defend_roundtrip_and_chain():
    ledger = aa.AIAttack()
    det = ledger.detect("sys-1", 1, verdict="attack-detected")
    dfn1 = ledger.defend(det.detection_id, 2, strategy="block-source")
    assert dfn1.defense_id == "def-1"
    assert dfn1.detection_id == det.detection_id
    assert dfn1.verify() is True
    dfn2 = ledger.defend(det.detection_id, 3, strategy="escalate-response",
                         defense_digest=PIN2)
    assert dfn2.defense_id == "def-2"
    assert len(ledger.defenses_for(det.detection_id, 3)) == 2
    assert ledger.defense_record("def-1", 3).strategy == "block-source"


# 8. defend refusal table + seq-burn
def test_defend_refusals_burn_seq():
    ledger = aa.AIAttack()
    det = ledger.detect("sys-1", 1, verdict="attack-detected")
    with pytest.raises(aa.UnknownDetectionError):
        ledger.defend("det-999", 2, strategy="block-source")
    with pytest.raises(aa.BadStrategyError):
        ledger.defend(det.detection_id, 3, strategy="bogus")
    with pytest.raises(aa.BadDigestError):
        ledger.defend(det.detection_id, 4, defense_digest="zzz")
    ledger.retire("sys-1", 5)
    with pytest.raises(aa.RetiredSystemError):
        ledger.defend(det.detection_id, 6, strategy="block-source")
    assert ledger.stats(0)["n_audit_rows"] == 6  # 1 detected + 1 retired + 4 rejected
    assert [r["kind"] for r in ledger.audit_log(0)].count("rejected") == 4


# 9. verify semantics + tamper-as-data + unknown + read purity
def test_verify_semantics_tamper_read_purity():
    ledger = aa.AIAttack()
    det = ledger.detect("sys-1", 1, verdict="attack-detected")
    dfn = ledger.defend(det.detection_id, 2, strategy="isolate-system")
    rep = ledger.verify(det.detection_id, 3)
    assert rep.verdict == "verified"
    assert rep.integrity_ok is True
    assert rep.verify() is True
    # tamper reported as data, never raised
    object.__setattr__(det, "severity", 1)
    rep2 = ledger.verify(det.detection_id, 4)
    assert rep2.verdict == "tampered"
    assert rep2.integrity_ok is False
    # defense record verify still fine
    rep3 = ledger.verify(dfn.defense_id, 4)
    assert rep3.verdict == "verified"
    with pytest.raises(aa.UnknownRecordError):
        ledger.verify("det-999", 5)
    # read purity: same seq twice, no audit rows, no seq consumption
    before = ledger.stats(0)["n_audit_rows"]
    ledger.verify(det.detection_id, 4)
    ledger.verify(det.detection_id, 4)
    assert ledger.stats(0)["n_audit_rows"] == before
    assert ledger.stats(0)["seq"] == 2


# 10. evaluate posture math: all 5 postures + precedence
def test_evaluate_posture_math_all_postures():
    ledger = aa.AIAttack()
    a = ledger.detect("s-attack", 1, verdict="attack-detected")
    b = ledger.detect("s-suspect", 2, verdict="suspected")
    c = ledger.detect("s-clean", 3, verdict="no-attack")
    d = ledger.detect("s-defend", 4, verdict="attack-detected")
    ledger.defend(d.detection_id, 5, strategy="block-source")
    e = ledger.detect("s-inconc", 6, verdict="inconclusive")
    assert ledger.evaluate("s-attack", 6).posture == "under-attack"
    assert ledger.evaluate("s-suspect", 6).posture == "contested"
    assert ledger.evaluate("s-inconc", 6).posture == "contested"
    assert ledger.evaluate("s-clean", 6).posture == "clean"
    assert ledger.evaluate("s-defend", 6).posture == "defended"
    ev = ledger.evaluate("s-defend", 6)
    assert ev.n_detections == 1 and ev.n_attack_detected == 1 and ev.n_defended == 1
    assert ev.integrity_ok is True
    assert ev.verify() is True
    # undefended attack-detected outranks suspected
    ledger.detect("s-mixed", 7, verdict="suspected")
    ledger.detect("s-mixed", 8, verdict="attack-detected")
    assert ledger.evaluate("s-mixed", 8).posture == "under-attack"


# 11. evaluate read purity + unknown refusal + tamper flips integrity
def test_evaluate_read_purity_and_integrity_flip():
    ledger = aa.AIAttack()
    det = ledger.detect("sys-1", 1, verdict="attack-detected")
    with pytest.raises(aa.UnknownSystemError):
        ledger.evaluate("sys-unknown", 2)
    before = ledger.stats(0)["n_audit_rows"]
    ledger.evaluate("sys-1", 2)
    ledger.evaluate("sys-1", 2)
    assert ledger.stats(0)["n_audit_rows"] == before
    object.__setattr__(det, "verdict", "no-attack")
    ev = ledger.evaluate("sys-1", 3)
    assert ev.integrity_ok is False
    assert ev.verify() is True


# 12. retire terminality + id non-recycling + post-retire reads
def test_retire_terminality():
    ledger = aa.AIAttack()
    ledger.detect("sys-1", 1, verdict="no-attack")
    ret = ledger.retire("sys-1", 2, reason="decommissioned")
    assert ret.verify() is True
    with pytest.raises(aa.RetiredSystemError):
        ledger.detect("sys-1", 3)
    with pytest.raises(aa.RetiredSystemError):
        ledger.retire("sys-1", 4)
    with pytest.raises(aa.BadReasonError):
        ledger.retire("sys-1", 5, reason="bogus")
    with pytest.raises(aa.UnknownSystemError):
        ledger.retire("sys-unknown", 6)
    # reads still work post-retire
    assert ledger.evaluate("sys-1", 7).posture == "clean"
    assert ledger.retired_ids(7) == ("sys-1",)
    assert ledger.stats(0)["seq"] == 6  # failed muts burned 3..6


# 13. seq discipline: rewind bare, malformed seqs, failed-mutation-consumes-seq
def test_seq_discipline():
    ledger = aa.AIAttack()
    with pytest.raises(aa.SeqOrderError):
        ledger.detect("sys-1", 0)
    assert ledger.stats(0)["n_audit_rows"] == 0
    ledger.detect("sys-1", 1)
    with pytest.raises(aa.SeqOrderError):
        ledger.detect("sys-1", 1)
    assert ledger.stats(0)["n_audit_rows"] == 1  # only the successful detect row
    for bad in (True, 1.5, "2", None):
        with pytest.raises(aa.SeqOrderError):
            ledger.detect("sys-2", bad)
    assert ledger.stats(0)["n_audit_rows"] == 1
    # failed mutation consumes seq + books rejected
    with pytest.raises(aa.BadAttackKindError):
        ledger.detect("sys-3", 2, attack_kind="bogus")
    assert ledger.stats(0)["seq"] == 2
    assert ledger.stats(0)["n_audit_rows"] == 2
    rec = ledger.detect("sys-3", 3)
    assert rec.detection_id == "det-2"


# 14. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    ledger = aa.AIAttack()
    det = ledger.detect("sys-1", 1, attack_kind="jailbreak",
                        verdict="attack-detected", severity=90,
                        detection_digest=PIN)
    ledger.defend(det.detection_id, 2, strategy="block-source")
    ledger.retire("sys-1", 3)
    kinds = [r["kind"] for r in ledger.audit_log(0)]
    assert kinds == ["detected", "defended", "retired"]
    for row in ledger.audit_log(0):
        assert row["schema"] == "audit.ndjson/1"
        assert row["module"] == "ai-attack"
        assert row["version"] == "ai-attack.v1"
    with pytest.raises(aa.AIAttackError):
        aa.ai_attack_audit_event("detected", 4, payload="raw-exploit")
    with pytest.raises(aa.AuditKindError):
        aa.ai_attack_audit_event("bogus-kind", 4)
    with pytest.raises(aa.SeqOrderError):
        aa.ai_attack_audit_event("detected", "x")
    # pinned vocab values and digest pins remain emittable
    row = aa.ai_attack_audit_event("detected", 4, attack_kind="jailbreak",
                                   detection_digest=PIN)
    assert row["details"]["attack_kind"] == "jailbreak"


# 15. cross-instance determinism + thread read smoke + main subprocess
def test_determinism_thread_smoke_main():
    l1 = aa.AIAttack()
    l2 = aa.AIAttack()
    d1 = l1.detect("sys-1", 1, attack_kind="prompt-injection",
                   verdict="attack-detected", severity=42,
                   detection_digest=PIN)
    d2 = l2.detect("sys-1", 1, attack_kind="prompt-injection",
                   verdict="attack-detected", severity=42,
                   detection_digest=PIN)
    assert d1.digest == d2.digest
    assert dataclasses.is_dataclass(d1) and d1.__dataclass_params__.frozen
    errors = []

    def reader():
        try:
            for _ in range(50):
                l1.evaluate("sys-1", 1)
                l1.detections_for("sys-1", 1)
                l1.stats(0)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    proc = subprocess.run([sys.executable, str(MOD)], capture_output=True,
                          text=True, check=False)
    assert proc.returncode == 0
    assert "ai-attack OK" in proc.stdout
