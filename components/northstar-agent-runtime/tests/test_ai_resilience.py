"""Tests for the ai-resilience assessment -> strengthening decision ledger, Simulated."""

import ast
import dataclasses
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "ai_resilience.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("ai_resilience", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["ai_resilience"] = module
    spec.loader.exec_module(module)
    return module


ar = _load()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert ar.AI_RESILIENCE_VERSION == "ai-resilience.v1"
    assert ar.SCHEMA_PIN == "northstar.ai-resilience.v1"
    assert ar.RESILIENCE_KINDS == (
        "fault-recovery",
        "graceful-degradation",
        "failover",
        "self-healing",
        "redundancy",
        "rollback",
        "contingency",
        "drift-resilience",
    )
    assert ar.ASSESS_VERDICTS == (
        "resilient",
        "at-risk",
        "brittle",
        "inconclusive",
        "not-assessed",
    )
    assert ar.STRENGTHEN_STRATEGIES == (
        "redundancy-add",
        "failover-drill",
        "graceful-degradation",
        "rollback-plan",
        "monitoring-escalation",
        "diversity-injection",
        "checkpointing",
        "no-action",
    )
    assert ar.VERIFY_VERDICTS == ("verified", "tampered")
    assert ar.POSTURES == (
        "unassessed",
        "brittle",
        "uncertain",
        "strengthened",
        "resilient",
    )
    assert ar.RETIRE_REASONS == ("manual", "superseded", "decommissioned", "false-start")
    assert ar.AUDIT_KINDS == ("assessed", "strengthened", "retired", "rejected")


# 2. stdlib-only AST check + stdlib_only()
def test_stdlib_only_ast():
    assert ar.stdlib_only() is True
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
    tree = ast.parse(MOD.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                assert node.module.split(".")[0] in allowed


# 3. assess roundtrip + verify() + frozen-ness
def test_assess_roundtrip_verify():
    led = ar.AIResilience()
    rec = led.assess("sys-1", 1, resilience_kind="failover", verdict="brittle",
                     severity=42, assessment_digest=PIN)
    assert rec.assessment_id == "asm-1"
    assert rec.system_id == "sys-1"
    assert rec.seq == 1
    assert rec.verify() is True
    assert led.assessment_record("asm-1", 2) == rec
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.verdict = "resilient"  # type: ignore[misc]
    assert led.verify("asm-1", 3).verdict == "verified"
    assert led.system_ids(3) == ["sys-1"]
    assert led.assessment_ids(3) == ["asm-1"]
    st = led.stats(3)
    assert st["n_assessments"] == 1 and st["n_systems"] == 1 and st["seq"] == 1


# 4. assess bad-input table + seq-burn + rejected-row accounting
def test_assess_bad_inputs():
    led = ar.AIResilience()
    with pytest.raises(ar.BadSystemError):
        led.assess("", 1)
    with pytest.raises(ar.BadSystemError):
        led.assess(None, 2)  # type: ignore[arg-type]
    with pytest.raises(ar.BadResilienceKindError):
        led.assess("sys-1", 3, resilience_kind="nope")
    with pytest.raises(ar.BadVerdictError):
        led.assess("sys-1", 4, verdict="nope")
    with pytest.raises(ar.BadSeverityError):
        led.assess("sys-1", 5, severity=-1)
    with pytest.raises(ar.BadSeverityError):
        led.assess("sys-1", 6, severity=101)
    with pytest.raises(ar.BadSeverityError):
        led.assess("sys-1", 7, severity=True)  # type: ignore[arg-type]
    with pytest.raises(ar.BadDigestError):
        led.assess("sys-1", 8, assessment_digest="junk")
    with pytest.raises(ar.BadDigestError):
        led.assess("sys-1", 9, assessment_digest="sha256:" + "zz" * 32)
    rec = led.assess("sys-1", 10)
    assert rec.assessment_id == "asm-1"
    led.retire("sys-1", 11)
    with pytest.raises(ar.RetiredSystemError):
        led.assess("sys-1", 12)
    audit = led.audit_log(12)
    assert len(audit) == 12  # 10 rejected + 1 assessed + 1 retired
    assert [r["kind"] for r in audit] == ["rejected"] * 9 + ["assessed", "retired", "rejected"]
    assert all(r["schema"] == "audit.ndjson/1" for r in audit)
    assert led.stats(12)["seq"] == 12
    with pytest.raises(ar.SeqOrderError):  # rewind raises bare, no new row
        led.assess("sys-1", 12)
    assert len(led.audit_log(12)) == 12


# 5. full resilience-kind vocabulary acceptance
def test_full_resilience_kind_vocabulary():
    led = ar.AIResilience()
    for i, kind in enumerate(ar.RESILIENCE_KINDS, start=1):
        rec = led.assess("sys-1", i, resilience_kind=kind, verdict="resilient")
        assert rec.assessment_id == f"asm-{i}"
        assert rec.verify() is True
    assert led.stats(8)["n_assessments"] == 8
    assert len(led.assessments_for("sys-1", 9)) == 8


# 6. full verdict vocabulary + severity boundaries
def test_full_verdict_vocabulary():
    led = ar.AIResilience()
    for i, verdict in enumerate(ar.ASSESS_VERDICTS, start=1):
        rec = led.assess("sys-1", i, verdict=verdict, severity=0 if i % 2 else 100)
        assert rec.verify() is True
    tallies = led.evaluate("sys-1", 6)
    assert tallies.n_resilient == 1
    assert tallies.n_at_risk == 1
    assert tallies.n_brittle == 1
    assert tallies.n_inconclusive == 1
    assert tallies.n_not_assessed == 1
    assert tallies.verify() is True


# 7. strengthen roundtrip + chainable + verify
def test_strengthen_roundtrip():
    led = ar.AIResilience()
    led.assess("sys-1", 1, verdict="brittle")
    st = led.strengthen("asm-1", 2, strategy="failover-drill", strengthening_digest=PIN2)
    assert st.strengthening_id == "str-1"
    assert st.assessment_id == "asm-1"
    assert st.verify() is True
    st2 = led.strengthen("asm-1", 3, strategy="checkpointing")
    assert st2.strengthening_id == "str-2"
    assert led.strengthening_record("str-1", 4) == st
    assert len(led.strengthenings_for("asm-1", 4)) == 2
    with pytest.raises(dataclasses.FrozenInstanceError):
        st.strategy = "no-action"  # type: ignore[misc]
    assert led.verify("str-1", 4).verdict == "verified"


# 8. strengthen refusal table + seq-burn
def test_strengthen_refusals():
    led = ar.AIResilience()
    led.assess("sys-1", 1, verdict="brittle")
    with pytest.raises(ar.UnknownAssessmentError):
        led.strengthen("asm-999", 2)
    with pytest.raises(ar.BadStrategyError):
        led.strengthen("asm-1", 3, strategy="nope")
    with pytest.raises(ar.BadDigestError):
        led.strengthen("asm-1", 4, strengthening_digest="junk")
    with pytest.raises(ar.BadSystemError):
        led.strengthen("", 5)
    led.retire("sys-1", 6)
    with pytest.raises(ar.RetiredSystemError):
        led.strengthen("asm-1", 7)
    audit = led.audit_log(7)
    assert [r["kind"] for r in audit].count("rejected") == 5
    assert led.stats(7)["seq"] == 7
    assert led.strengthening_ids(7) == []  # all strengthen attempts refused


# 9. full strategy vocabulary
def test_full_strategy_vocabulary():
    led = ar.AIResilience()
    led.assess("sys-1", 1, verdict="at-risk")
    for i, strategy in enumerate(ar.STRENGTHEN_STRATEGIES, start=2):
        st = led.strengthen("asm-1", i, strategy=strategy)
        assert st.strengthening_id == f"str-{i - 1}"
        assert st.verify() is True
    assert led.stats(9)["n_strengthenings"] == 8


# 10. verify semantics: unknown refusal + tamper-as-data + read purity
def test_verify_semantics():
    led = ar.AIResilience()
    led.assess("sys-1", 1, verdict="resilient")
    led.strengthen("asm-1", 2, strategy="redundancy-add")
    with pytest.raises(ar.UnknownRecordError):
        led.verify("nope-1", 3)
    r1 = led.verify("asm-1", 4)
    assert (r1.verdict, r1.integrity_ok) == ("verified", True)
    assert r1.verify() is True
    obj = led._assessments["asm-1"]
    object.__setattr__(obj, "verdict", "brittle")  # tamper bypasses frozen
    r2 = led.verify("asm-1", 5)
    assert (r2.verdict, r2.integrity_ok) == ("tampered", False)
    assert r1.verify() is True  # report from before tamper still self-consistent
    assert led.verify("str-1", 5).verdict == "verified"
    before = len(led.audit_log(5))
    led.verify("asm-1", 6)
    led.verify("str-1", 6)
    assert len(led.audit_log(6)) == before  # pure read: no rows, seq not consumed
    assert led.stats(6)["seq"] == 2


# 11. evaluate posture math: all postures + precedence + tallies + integrity
def test_evaluate_posture_math():
    led = ar.AIResilience()
    led.assess("sys-A", 1, verdict="brittle")                      # open brittle
    led.assess("sys-B", 2, verdict="brittle")                      # covered brittle
    led.strengthen("asm-2", 3, strategy="failover-drill")
    led.assess("sys-C", 4, verdict="inconclusive")                  # uncertain
    led.assess("sys-D", 5, verdict="not-assessed")                  # unassessed
    led.assess("sys-E", 6, verdict="resilient")
    led.assess("sys-E", 7, verdict="resilient")                     # resilient
    led.assess("sys-F", 8, verdict="at-risk")                      # open at-risk -> uncertain
    led.assess("sys-G", 9, verdict="brittle")                      # precedence: brittle beats inconclusive
    led.assess("sys-G", 10, verdict="inconclusive")
    led.assess("sys-H", 11, verdict="at-risk")                     # covered at-risk -> strengthened
    led.strengthen("asm-10", 12, strategy="checkpointing")
    assert led.evaluate("sys-A", 13).posture == "brittle"
    assert led.evaluate("sys-B", 13).posture == "strengthened"
    assert led.evaluate("sys-C", 13).posture == "uncertain"
    assert led.evaluate("sys-D", 13).posture == "unassessed"
    assert led.evaluate("sys-E", 13).posture == "resilient"
    assert led.evaluate("sys-F", 13).posture == "uncertain"
    assert led.evaluate("sys-G", 13).posture == "brittle"
    assert led.evaluate("sys-H", 13).posture == "strengthened"
    rep = led.evaluate("sys-B", 13)
    assert (rep.n_assessments, rep.n_brittle, rep.n_strengthened) == (1, 1, 1)
    assert rep.integrity_ok is True and rep.verify() is True
    with pytest.raises(ar.UnknownSystemError):
        led.evaluate("sys-ZZZ", 13)
    obj = led._assessments["asm-2"]
    object.__setattr__(obj, "severity", 99)                 # tamper -> flips integrity as data
    rep2 = led.evaluate("sys-B", 14)
    assert rep2.integrity_ok is False and rep2.posture == "strengthened"
    assert rep2.verify() is True


# 12. evaluate read purity: same-seq twice, no audit rows, seq not consumed
def test_evaluate_read_purity():
    led = ar.AIResilience()
    led.assess("sys-1", 1, verdict="resilient")
    before = len(led.audit_log(1))
    r1 = led.evaluate("sys-1", 2)
    r2 = led.evaluate("sys-1", 2)
    assert r1 == r2
    assert len(led.audit_log(2)) == before
    assert led.stats(2)["seq"] == 1  # read-seq never consumed
    with pytest.raises(ar.UnknownSystemError):
        led.evaluate("sys-nope", 2)
    for bad in (True, "2", 2.5, None):
        with pytest.raises(ar.SeqOrderError):
            led.evaluate("sys-1", bad)  # type: ignore[arg-type]


# 13. retire terminality + id non-recycling + bad reason + post-retire reads
def test_retire_terminality():
    led = ar.AIResilience()
    led.assess("sys-1", 1, verdict="brittle")
    with pytest.raises(ar.BadReasonError):
        led.retire("sys-1", 2, reason="nope")
    rr = led.retire("sys-1", 3, reason="decommissioned")
    assert rr.verify() is True
    assert led.retired_ids(3) == ["sys-1"]
    with pytest.raises(ar.RetiredSystemError):
        led.assess("sys-1", 4)                                      # post-retire mutation refused
    with pytest.raises(ar.RetiredSystemError):
        led.strengthen("asm-1", 5)
    with pytest.raises(ar.RetiredSystemError):
        led.retire("sys-1", 6)                                      # double retire refused
    assert led.assessment_record("asm-1", 7).verify() is True       # reads still work
    assert led.evaluate("sys-1", 7).posture == "brittle"
    assert led.verify("asm-1", 7).verdict == "verified"
    with pytest.raises(ar.UnknownSystemError):
        led.retire("sys-nope", 8)


# 14. seq discipline: rewind bare with zero rows, malformed seqs, failed-mutation-consumes-seq
def test_seq_discipline():
    led = ar.AIResilience()
    with pytest.raises(ar.SeqOrderError):
        led.assess("sys-1", 0)                                      # genesis rewind raises bare
    assert len(led.audit_log(0)) == 0
    for bad in (True, "1", 1.5, None):
        with pytest.raises(ar.SeqOrderError):
            led.assess("sys-1", bad)  # type: ignore[arg-type]
    assert len(led.audit_log(0)) == 0
    with pytest.raises(ar.BadResilienceKindError):
        led.assess("sys-1", 5, resilience_kind="nope")              # failed mutation burns seq
    assert led.stats(0)["seq"] == 5
    assert [r["kind"] for r in led.audit_log(0)] == ["rejected"]
    with pytest.raises(ar.SeqOrderError):
        led.assess("sys-1", 5)                                      # rewind after burn: bare
    assert len(led.audit_log(0)) == 1
    rec = led.assess("sys-1", 6)                                    # next live seq works
    assert rec.assessment_id == "asm-1"


# 15. audit shapes + leak ban + cross-instance determinism + threads + main()
def test_audit_shapes_and_integrity():
    led = ar.AIResilience()
    led.assess("sys-1", 1, resilience_kind="redundancy", verdict="brittle", severity=70)
    led.strengthen("asm-1", 2, strategy="redundancy-add")
    led.retire("sys-1", 3)
    with pytest.raises(ar.BadResilienceKindError):
        led.assess("sys-1", 4, resilience_kind="nope")
    audit = led.audit_log(4)
    assert [r["kind"] for r in audit] == ["assessed", "strengthened", "retired", "rejected"]
    for row in audit:
        assert row["schema"] == "audit.ndjson/1"
        assert row["module"] == "ai-resilience"
        assert row["version"] == "ai-resilience.v1"
        assert isinstance(row["seq"], int) and not isinstance(row["seq"], bool)
        assert isinstance(row["details"], dict)
    with pytest.raises(ar.AIResilienceError):
        ar.ai_resilience_audit_event("assessed", 9, weights="raw")   # banned key
    with pytest.raises(ar.AIResilienceError):
        ar.ai_resilience_audit_event("assessed", 9, fault_trace="raw")
    with pytest.raises(ar.AuditKindError):
        ar.ai_resilience_audit_event("bogus", 9)
    with pytest.raises(ar.SeqOrderError):
        ar.ai_resilience_audit_event("assessed", True)
    # pinned vocab values and digest pins remain emittable as declared data
    row = ar.ai_resilience_audit_event("assessed", 9, resilience_kind="failover",
                                       verdict="brittle", assessment_digest=PIN)
    assert row["details"]["verdict"] == "brittle"
    # cross-instance digest determinism
    a, b = ar.AIResilience(), ar.AIResilience()
    ra = a.assess("sys-1", 1, verdict="brittle")
    rb = b.assess("sys-1", 1, verdict="brittle")
    assert ra.digest == rb.digest
    object.__setattr__(rb, "severity", 99)
    assert rb.verify() is False
    # 8-thread read smoke
    errors = []
    def _read():
        try:
            for _ in range(50):
                a.evaluate("sys-1", 5)
                a.verify("asm-1", 5)
                a.assessments_for("sys-1", 5)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)
    threads = [threading.Thread(target=_read) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    # main() self-check via subprocess
    proc = subprocess.run([sys.executable, str(MOD)], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert "ai-resilience OK: assess, strengthen, verify, evaluate, pins, audit" in proc.stdout
