"""Tests for the ai_safety_threat decision ledger (15 tests, house style).

Standalone-importable: loads ``ai_safety_threat`` directly from its file path so
the tests run without the package being installed (mirrors the house
pattern used across the batch).
"""

import ast
import importlib.util
import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).resolve().parent.parent / "ai_safety_threat.py"


def load_module():
    import importlib.util

    spec = importlib.util.spec_from_file_location("ai_safety_threat", MODULE_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["ai_safety_threat"] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def mod():
    return load_module()


@pytest.fixture()
def ledger(mod):
    return mod.AISafetyThreat()


def _digest():
    return "sha256:" + "ab" * 32


# ---------------------------------------------------------------------------
# 1. pins / vocabularies
# ---------------------------------------------------------------------------


def test_version_and_vocabulary_pins(mod):
    assert mod.AI_SAFETY_THREAT_VERSION == "ai-safety-threat.v1"
    assert mod.SCHEMA_PIN == "northstar.ai-safety-threat.v1"
    assert mod.SAFETY_THREAT_KINDS == (
        "loss-of-control",
        "misalignment-drift",
        "deceptive-behavior",
        "specification-gaming",
        "reward-hacking",
        "power-seeking",
        "self-exfiltration",
        "autonomous-replication",
    )
    assert len(mod.SAFETY_THREAT_KINDS) == 8
    assert mod.ASSESS_VERDICTS == (
        "active",
        "suspected",
        "contained",
        "inconclusive",
        "not-assessed",
    )
    assert len(mod.MITIGATION_STRATEGIES) == 8
    assert mod.VERIFY_VERDICTS == ("verified", "tampered")
    assert mod.POSTURES == (
        "unassessed",
        "threatening",
        "suspect",
        "mitigated",
        "contained",
    )
    assert mod.RETIRE_REASONS == (
        "manual",
        "superseded",
        "decommissioned",
        "false-start",
    )
    assert mod.AUDIT_KINDS == ("assessed", "mitigated", "retired", "rejected")


# ---------------------------------------------------------------------------
# 2. stdlib-only
# ---------------------------------------------------------------------------


def test_stdlib_only(mod):
    assert mod.stdlib_only() is True
    tree = ast.parse(Path(MODULE_PATH).read_text())
    allowed = {
        "hashlib",
        "json",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
        "ast",
        "pathlib",
        "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed
        elif isinstance(node, ast.ImportFrom):
            assert node.module.split(".")[0] in allowed


# ---------------------------------------------------------------------------
# 3. assess roundtrip + verify() + frozen-ness
# ---------------------------------------------------------------------------


def test_assess_roundtrip_verify_and_frozen(mod, ledger):
    rec = ledger.assess(
        "sys-1",
        1,
        safety_threat_kind="reward-hacking",
        verdict="active",
        severity=75,
        assessment_digest=_digest(),
    )
    assert rec.assessment_id == "asm-1"
    assert rec.system_id == "sys-1"
    assert rec.safety_threat_kind == "reward-hacking"
    assert rec.verdict == "active"
    assert rec.severity == 75
    assert rec.verify() is True
    assert rec.digest.startswith("sha256:")
    # frozen dataclass rejects direct attribute assignment
    try:
        rec.verdict = "contained"
        raise AssertionError("frozen dataclass accepted assignment")
    except Exception:
        pass
    fetched = ledger.assessment_record(rec.assessment_id, 2)
    assert fetched == rec


# ---------------------------------------------------------------------------
# 4. assess bad-input table + seq-burn + rejected-row accounting + rewind bare
# ---------------------------------------------------------------------------


def test_assess_bad_inputs_burn_seq_and_book_rejected(mod, ledger):
    bad = [
        lambda: ledger.assess("", 1, verdict="active"),
        lambda: ledger.assess(123, 2, verdict="active"),
        lambda: ledger.assess("sys", 3, safety_threat_kind="not-a-kind", verdict="active"),
        lambda: ledger.assess("sys", 4, verdict="bogus"),
        lambda: ledger.assess("sys", 5, verdict="active", severity=-1),
        lambda: ledger.assess("sys", 6, verdict="active", severity=101),
        lambda: ledger.assess("sys", 7, verdict="active", severity=True),
        lambda: ledger.assess("sys", 8, verdict="active", severity=1.5),
        lambda: ledger.assess("sys", 9, verdict="active", assessment_digest="bad"),
    ]
    errors = (
        mod.BadSystemError,
        mod.BadSafetyThreatKindError,
        mod.BadVerdictError,
        mod.BadSeverityError,
        mod.BadDigestError,
    )
    before = len(ledger.audit_log(0))
    for i, call in enumerate(bad):
        with pytest.raises(errors):
            call()
        assert ledger.stats(0)["seq"] == i + 1  # each failure burns its seq
    after = len(ledger.audit_log(0))
    assert after - before == len(bad)
    rejected = [r for r in ledger.audit_log(0) if r["kind"] == "rejected"]
    assert len(rejected) == len(bad)
    # rewind raises bare, consumes nothing, books no row
    rows_before = len(ledger.audit_log(0))
    with pytest.raises(mod.SeqOrderError):
        ledger.assess("sys", 1)
    assert len(ledger.audit_log(0)) == rows_before
    assert ledger.stats(0)["seq"] == len(bad)


# ---------------------------------------------------------------------------
# 5. full 8-safety-threat-kind vocabulary
# ---------------------------------------------------------------------------


def test_full_safety_threat_kind_vocabulary(mod, ledger):
    for i, kind in enumerate(mod.SAFETY_THREAT_KINDS):
        rec = ledger.assess("sys-k", i + 1, safety_threat_kind=kind, verdict="suspected")
        assert rec.safety_threat_kind == kind
        assert rec.verify() is True
    assert ledger.stats(0)["n_assessments"] == 8


# ---------------------------------------------------------------------------
# 6. full verdict vocabulary
# ---------------------------------------------------------------------------


def test_full_verdict_vocabulary(mod, ledger):
    for i, verdict in enumerate(mod.ASSESS_VERDICTS):
        rec = ledger.assess("sys-v", i + 1, verdict=verdict)
        assert rec.verdict == verdict
        assert rec.verify() is True
    assert ledger.stats(0)["n_assessments"] == 5


# ---------------------------------------------------------------------------
# 7. mitigate roundtrip + minted ids + unknown-assessment refusal
# ---------------------------------------------------------------------------


def test_mitigate_roundtrip_and_unknown_refusal(mod, ledger):
    rec = ledger.assess("sys-1", 1, safety_threat_kind="deceptive-behavior", verdict="active")
    mit1 = ledger.mitigate(rec.assessment_id, 2, strategy="safety-interlock")
    assert mit1.mitigation_id == "mit-1"
    assert mit1.assessment_id == rec.assessment_id
    assert mit1.system_id == "sys-1"
    assert mit1.verify() is True
    mit2 = ledger.mitigate(rec.assessment_id, 3, strategy="oversight-escalation")
    assert mit2.mitigation_id == "mit-2"
    assert mit2.verify() is True
    chain = ledger.mitigations_for(rec.assessment_id, 4)
    assert tuple(m.mitigation_id for m in chain) == ("mit-1", "mit-2")
    with pytest.raises(mod.UnknownAssessmentError):
        ledger.mitigate("asm-999", 5, strategy="no-action")


# ---------------------------------------------------------------------------
# 8. mitigate bad-input table + retired-system refusal
# ---------------------------------------------------------------------------


def test_mitigate_bad_inputs_and_retired_refusal(mod, ledger):
    rec = ledger.assess("sys-1", 1, verdict="active")
    rows_before = len(ledger.audit_log(0))
    with pytest.raises(mod.BadStrategyError):
        ledger.mitigate(rec.assessment_id, 2, strategy="bogus")
    with pytest.raises(mod.BadDigestError):
        ledger.mitigate(rec.assessment_id, 3, mitigation_digest="bad")
    with pytest.raises(mod.BadSystemError):
        ledger.mitigate("", 4)
    rows_after = len(ledger.audit_log(0))
    assert rows_after - rows_before == 3  # 3 rejected rows booked
    ledger.retire("sys-1", 5)
    with pytest.raises(mod.RetiredSystemError):
        ledger.mitigate(rec.assessment_id, 6, strategy="no-action")
    with pytest.raises(mod.UnknownMitigationError):
        ledger.mitigation_record("mit-999", 7)


# ---------------------------------------------------------------------------
# 9. full 8-strategy vocabulary
# ---------------------------------------------------------------------------


def test_full_mitigation_strategy_vocabulary(mod, ledger):
    rec = ledger.assess("sys-1", 1, verdict="active")
    for i, strategy in enumerate(mod.MITIGATION_STRATEGIES):
        mit = ledger.mitigate(rec.assessment_id, i + 2, strategy=strategy)
        assert mit.strategy == strategy
        assert mit.verify() is True
    assert ledger.stats(0)["n_mitigations"] == 8


# ---------------------------------------------------------------------------
# 10. verify semantics: tamper-as-data, read purity, unknown refusal
# ---------------------------------------------------------------------------


def test_verify_semantics_and_read_purity(mod, ledger):
    rec = ledger.assess("sys-1", 1, verdict="active")
    rows_before = len(ledger.audit_log(0))
    rep = ledger.verify(rec.assessment_id, 2)
    assert rep.verdict == "verified"
    assert rep.integrity_ok is True
    assert rep.verify() is True
    # read purity: same seq twice, no audit rows, no seq consumption
    rep2 = ledger.verify(rec.assessment_id, 2)
    assert rep2 == rep
    assert len(ledger.audit_log(0)) == rows_before
    assert ledger.stats(0)["seq"] == 1
    # tamper is reported as data, never raised
    object.__setattr__(rec, "verdict", "contained")
    tampered = ledger.verify(rec.assessment_id, 3)
    assert tampered.verdict == "tampered"
    assert tampered.integrity_ok is False
    ev = ledger.evaluate("sys-1", 4)
    assert ev.integrity_ok is False
    with pytest.raises(mod.UnknownRecordError):
        ledger.verify("nope", 5)


# ---------------------------------------------------------------------------
# 11. evaluate posture math: all reachable postures + precedence
# ---------------------------------------------------------------------------


def test_evaluate_posture_math(mod, ledger):
    with pytest.raises(mod.UnknownSystemError):
        ledger.evaluate("ghost", 1)
    a = ledger.assess("p1", 2, verdict="active")
    assert ledger.evaluate("p1", 3).posture == "threatening"
    ledger.mitigate(a.assessment_id, 4, strategy="deployment-hold")
    assert ledger.evaluate("p1", 5).posture == "mitigated"
    ledger.assess("p2", 6, verdict="suspected")
    assert ledger.evaluate("p2", 7).posture == "suspect"
    ledger.assess("p3", 8, verdict="inconclusive")
    assert ledger.evaluate("p3", 9).posture == "suspect"
    ledger.assess("p4", 10, verdict="contained")
    ev4 = ledger.evaluate("p4", 11)
    assert ev4.posture == "contained"
    assert ev4.n_contained == 1
    # precedence: unmitigated active outranks suspected
    ledger.assess("p5", 12, verdict="suspected")
    ledger.assess("p5", 13, verdict="active")
    assert ledger.evaluate("p5", 14).posture == "threatening"
    active_id = [
        aid
        for aid in ledger.assessment_ids(0)
        if ledger.assessment_record(aid, 0).system_id == "p5"
        and ledger.assessment_record(aid, 0).verdict == "active"
    ][0]
    ledger.mitigate(active_id, 15, strategy="shutdown-procedure")
    assert ledger.evaluate("p5", 16).posture == "suspect"
    # tallies
    ev5 = ledger.evaluate("p5", 17)
    assert ev5.n_assessments == 2
    assert ev5.n_suspected == 1
    assert ev5.n_threatening == 1
    assert ev5.n_mitigated == 1
    assert ev5.integrity_ok is True
    assert ev5.verify() is True


# ---------------------------------------------------------------------------
# 12. retire terminality + id non-recycling + bad reason + post-retire reads
# ---------------------------------------------------------------------------


def test_retire_terminality(mod, ledger):
    ledger.assess("sys-1", 1, verdict="active")
    ret = ledger.retire("sys-1", 2, reason="decommissioned")
    assert ret.verify() is True
    assert ledger.retired_ids(3) == ("sys-1",)
    with pytest.raises(mod.RetiredSystemError):
        ledger.assess("sys-1", 3, verdict="active")
    with pytest.raises(mod.RetiredSystemError):
        ledger.retire("sys-1", 4)
    with pytest.raises(mod.BadReasonError):
        ledger.retire("sys-1", 5, reason="bogus")
    with pytest.raises(mod.UnknownSystemError):
        ledger.retire("ghost", 6)
    # ids never recycled; reads still work
    ev = ledger.evaluate("sys-1", 7)
    assert ev.posture == "threatening"
    assert len(ledger.assessments_for("sys-1", 8)) == 1


# ---------------------------------------------------------------------------
# 13. seq discipline: malformed seqs, rewind bare, gap allowed
# ---------------------------------------------------------------------------


def test_seq_discipline(mod, ledger):
    for bad in (True, "1", 1.5, None):
        with pytest.raises(mod.SeqOrderError):
            ledger.assess("sys", bad)
        with pytest.raises(mod.SeqOrderError):
            ledger.verify("asm-1", bad)
    ledger.assess("sys", 10)
    with pytest.raises(mod.SeqOrderError):
        ledger.assess("sys", 10)  # rewind raises bare
    assert ledger.stats(0)["n_audit_rows"] == 1  # only the successful assess
    # negative read seqs refused, but gap seqs are fine for mutations
    with pytest.raises(mod.SeqOrderError):
        ledger.verify("asm-1", -1)
    ledger.assess("sys", 100)
    assert ledger.stats(0)["n_assessments"] == 2


# ---------------------------------------------------------------------------
# 14. audit shapes + leak ban + bad kind
# ---------------------------------------------------------------------------


def test_audit_shapes_and_leak_ban(mod, ledger):
    rec = ledger.assess(
        "sys-1", 1, safety_threat_kind="self-exfiltration", verdict="suspected"
    )
    ledger.mitigate(rec.assessment_id, 2, strategy="safety-interlock")
    ledger.retire("sys-1", 3)
    kinds = [r["kind"] for r in ledger.audit_log(4)]
    assert kinds == ["assessed", "mitigated", "retired"]
    row = ledger.audit_log(4)[0]
    assert row["schema"] == "audit.ndjson/1"
    assert row["module"] == "ai-safety-threat"
    assert row["version"] == "ai-safety-threat.v1"
    assert row["details"]["safety_threat_kind"] == "self-exfiltration"
    # raw safety material is banned from the audit boundary
    with pytest.raises(mod.AISafetyThreatError):
        mod.ai_safety_threat_audit_event("assessed", 9, reasoning_trace="someone")
    with pytest.raises(mod.AISafetyThreatError):
        mod.ai_safety_threat_audit_event("assessed", 9, exfiltration_plan="some-plan")
    # pinned vocabulary values remain emittable as declared data
    ok = mod.ai_safety_threat_audit_event(
        "assessed", 9, safety_threat_kind="autonomous-replication"
    )
    assert ok["details"]["safety_threat_kind"] == "autonomous-replication"
    with pytest.raises(mod.AuditKindError):
        mod.ai_safety_threat_audit_event("bogus-kind", 10)
    with pytest.raises(mod.SeqOrderError):
        mod.ai_safety_threat_audit_event("assessed", True)


# ---------------------------------------------------------------------------
# 15. determinism + 8-thread read smoke + main() subprocess check
# ---------------------------------------------------------------------------


def test_determinism_thread_smoke_and_main(mod):
    def build():
        m = load_module()
        led = m.AISafetyThreat()
        led.assess(
            "sys-1",
            1,
            safety_threat_kind="autonomous-replication",
            verdict="active",
            severity=90,
        )
        return m, led

    m1, l1 = build()
    m2, l2 = build()
    assert l1.assessment_record("asm-1", 2).digest == l2.assessment_record(
        "asm-1", 2
    ).digest
    assert l1.evaluate("sys-1", 3).digest == l2.evaluate("sys-1", 3).digest

    _, led = build()
    errors = []

    def reader():
        try:
            for _ in range(50):
                led.evaluate("sys-1", 9)
                led.verify("asm-1", 9)
                led.system_ids(9)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors

    env = dict(os.environ)
    proc = subprocess.run(
        [sys.executable, "-m", "ai_safety_threat"],
        cwd=str(MODULE_PATH.parent),
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert "ai-safety-threat OK" in proc.stdout
