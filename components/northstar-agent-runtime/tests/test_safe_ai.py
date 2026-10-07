"""Tests for the safe-ai assurance decision ledger, Simulated."""

import ast
import dataclasses
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "safe_ai.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("safe_ai", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["safe_ai"] = module
    spec.loader.exec_module(module)
    return module


sa = _load()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert sa.SAFE_AI_VERSION == "safe-ai.v1"
    assert sa.SCHEMA_PIN == "northstar.safe-ai.v1"
    assert sa.DIMENSIONS == (
        "robustness",
        "oversight",
        "containment",
        "monitoring",
        "incident-response",
        "evaluation",
        "transparency",
        "secure-deployment",
    )
    assert sa.ASSESS_OUTCOMES == (
        "satisfactory",
        "deficient",
        "critical-gap",
        "inconclusive",
        "not-assessed",
    )
    assert sa.VERIFY_VERDICTS == (
        "substantiated",
        "refuted",
        "inconclusive",
        "not-checked",
    )
    assert sa.POSTURES == (
        "unassessed",
        "unsafe",
        "at-risk",
        "inconclusive",
        "safe",
    )
    assert sa.RETIRE_REASONS == ("manual", "superseded", "decommissioned", "false-start")


# 2. stdlib-only AST check
def test_stdlib_only():
    tree = ast.parse(MOD.read_text())
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
    assert sa.stdlib_only()


# 3. assess() roundtrip + verify() + frozen-ness
def test_assess_roundtrip():
    ledger = sa.SafeAI()
    rec = ledger.assess(
        "sys-1", 1, dimension="monitoring", outcome="satisfactory", assessment_digest=PIN
    )
    assert rec.assessment_id == "ass-1"
    assert rec.system_id == "sys-1"
    assert rec.dimension == "monitoring"
    assert rec.outcome == "satisfactory"
    assert rec.digest.startswith("sha256:")
    assert rec.verify()
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.outcome = "deficient"  # type: ignore
    fetched = ledger.assessment_record(rec.assessment_id, 2)
    assert fetched == rec
    rep = ledger.verify_assessment(rec.assessment_id, 3)
    assert rep.verdict == "verified"
    assert rep.integrity_ok
    assert rep.verify()


# 4. assess() bad-input table + seq-burn + rejected-row accounting
def test_assess_bad_inputs():
    ledger = sa.SafeAI()
    bads = [
        ("", 1, "robustness", "satisfactory", PIN),            # empty system id
        (123, 2, "robustness", "satisfactory", PIN),           # non-string id
        ("sys-1", 3, "bogus-dimension", "satisfactory", PIN),  # bad dimension
        ("sys-1", 4, "robustness", "bogus-outcome", PIN),      # bad outcome
        ("sys-1", 5, "robustness", "satisfactory", "nope"),    # bad digest
        (None, 6, "robustness", "satisfactory", PIN),          # None id
        ("sys-1", 7, None, "satisfactory", PIN),               # None dimension
        (True, 8, "robustness", "satisfactory", PIN),          # bool id
    ]
    for system_id, seq, dimension, outcome, digest in bads:
        with pytest.raises(sa.SafeAIError):
            ledger.assess(
                system_id, seq, dimension=dimension, outcome=outcome,
                assessment_digest=digest,
            )
    # claim-then-burn: each failed mutation consumed its seq
    assert ledger.stats(9)["seq"] == 8
    rejected = [r for r in ledger.audit_log(9) if r["kind"] == "rejected"]
    assert len(rejected) == 8
    # rewinds raise bare: no seq consumed, no rejected row
    with pytest.raises(sa.SeqOrderError):
        ledger.assess("sys-1", 8, dimension="robustness", outcome="satisfactory")
    assert ledger.stats(9)["seq"] == 8
    assert len([r for r in ledger.audit_log(9) if r["kind"] == "rejected"]) == 8


# 5. full 8-dimension vocabulary acceptance
def test_full_dimension_vocabulary():
    ledger = sa.SafeAI()
    seq = 0
    for dimension in sa.DIMENSIONS:
        seq += 1
        rec = ledger.assess(f"sys-{dimension}", seq, dimension=dimension, outcome="satisfactory")
        assert rec.dimension == dimension
        assert rec.verify()
    assert ledger.stats(seq + 1)["n_assessments"] == 8


# 6. verify() roundtrip + minted ids + unknown refusal
def test_verify_roundtrip():
    ledger = sa.SafeAI()
    rec = ledger.assess("sys-1", 1, dimension="evaluation", outcome="satisfactory")
    vrec = ledger.verify(rec.assessment_id, 2, verdict="substantiated", verification_digest=PIN)
    assert vrec.verification_id == "vfy-1"
    assert vrec.assessment_id == rec.assessment_id
    assert vrec.verdict == "substantiated"
    assert vrec.digest.startswith("sha256:")
    assert vrec.verify()
    with pytest.raises(dataclasses.FrozenInstanceError):
        vrec.verdict = "refuted"  # type: ignore
    fetched = ledger.verification_record(vrec.verification_id, 3)
    assert fetched == vrec
    assert ledger.verification_for(rec.assessment_id, 4) == vrec.verification_id
    # unknown assessment refusal
    with pytest.raises(sa.UnknownAssessmentError):
        ledger.verify("ass-999", 5, verdict="substantiated")


# 7. verify() bad-input table + double-verify refusal
def test_verify_bad_inputs():
    ledger = sa.SafeAI()
    rec = ledger.assess("sys-1", 1, dimension="oversight", outcome="satisfactory")
    ledger.verify(rec.assessment_id, 2, verdict="substantiated")
    with pytest.raises(sa.AlreadyVerifiedError):
        ledger.verify(rec.assessment_id, 3, verdict="refuted")  # one per assessment
    assert ledger.stats(4)["seq"] == 3  # double-verify consumed its seq
    rejected = [r for r in ledger.audit_log(4) if r["kind"] == "rejected"]
    assert len(rejected) == 1
    ledger2 = sa.SafeAI()
    rec2 = ledger2.assess("sys-1", 1, dimension="oversight", outcome="satisfactory")
    bads = [
        ("ass-999", 2, "substantiated", PIN),   # unknown assessment
        ("", 3, "substantiated", PIN),          # empty assessment id
        (None, 4, "substantiated", PIN),        # None assessment id
        (True, 5, "substantiated", PIN),        # bool assessment id
        (rec2.assessment_id, 6, "bogus", PIN), # bad verdict
        (rec2.assessment_id, 7, "substantiated", "nope"),  # bad digest
    ]
    for aid, seq, verdict, digest in bads:
        with pytest.raises(sa.SafeAIError):
            ledger2.verify(aid, seq, verdict=verdict, verification_digest=digest)
    assert ledger2.stats(8)["seq"] == 7
    rejected = [r for r in ledger2.audit_log(8) if r["kind"] == "rejected"]
    assert len(rejected) == 6


# 8. full 4-verdict vocabulary acceptance
def test_full_verdict_vocabulary():
    ledger = sa.SafeAI()
    seq = 0
    for verdict in sa.VERIFY_VERDICTS:
        seq += 1
        rec = ledger.assess(f"sys-{verdict}", seq, dimension="transparency", outcome="satisfactory")
        seq += 1
        vrec = ledger.verify(rec.assessment_id, seq, verdict=verdict)
        assert vrec.verdict == verdict
        assert vrec.verify()
    assert ledger.stats(seq + 1)["n_verifications"] == 4


# 9. evaluate() posture math (all 5 postures + precedence)
def test_evaluate_posture_math():
    ledger = sa.SafeAI()
    seq = 0
    # unassessed ledger: evaluate refuses unknown system
    with pytest.raises(sa.UnknownSystemError):
        ledger.evaluate("sys-0", 1)
    # safe: all satisfactory
    seq += 1
    ledger.assess("sys-safe", seq, dimension="robustness", outcome="satisfactory")
    rep = ledger.evaluate("sys-safe", seq + 1)
    assert rep.posture == "safe"
    assert rep.n_satisfactory == 1
    assert rep.integrity_ok
    assert rep.verify()
    # unsafe: any critical-gap outranks everything
    seq += 2
    ledger.assess("sys-unsafe", seq, dimension="containment", outcome="satisfactory")
    seq += 1
    ledger.assess("sys-unsafe", seq, dimension="monitoring", outcome="critical-gap")
    rep = ledger.evaluate("sys-unsafe", seq + 1)
    assert rep.posture == "unsafe"
    assert rep.n_critical_gap == 1
    # at-risk: deficient outranks inconclusive/satisfactory
    seq += 2
    ledger.assess("sys-risk", seq, dimension="evaluation", outcome="inconclusive")
    seq += 1
    ledger.assess("sys-risk", seq, dimension="oversight", outcome="deficient")
    rep = ledger.evaluate("sys-risk", seq + 1)
    assert rep.posture == "at-risk"
    # inconclusive: inconclusive outranks not-assessed/satisfactory
    seq += 2
    ledger.assess("sys-inc", seq, dimension="incident-response", outcome="inconclusive")
    rep = ledger.evaluate("sys-inc", seq + 1)
    assert rep.posture == "inconclusive"


# 10. evaluate() read purity + unknown refusal + tamper flips integrity
def test_evaluate_read_purity():
    ledger = sa.SafeAI()
    rec = ledger.assess("sys-1", 1, dimension="secure-deployment", outcome="satisfactory")
    before = ledger.stats(2)["n_audit_rows"]
    rep1 = ledger.evaluate("sys-1", 2)
    rep2 = ledger.evaluate("sys-1", 2)  # same seq twice: pure read
    assert rep1 == rep2
    assert ledger.stats(3)["seq"] == 1  # read did not consume
    assert ledger.stats(3)["n_audit_rows"] == before  # no audit rows
    with pytest.raises(sa.UnknownSystemError):
        ledger.evaluate("sys-nope", 4)
    # tamper flips integrity_ok as data (reported, never raised)
    object.__setattr__(rec, "outcome", "deficient")
    rep3 = ledger.evaluate("sys-1", 5)
    assert rep3.integrity_ok is False
    assert rep3.verify() is True  # report itself is honestly pinned


# 11. retire() terminality + id non-recycling + post-retire reads
def test_retire_terminality():
    ledger = sa.SafeAI()
    rec = ledger.assess("sys-1", 1, dimension="robustness", outcome="satisfactory")
    rrec = ledger.retire("sys-1", 2, reason="superseded")
    assert rrec.system_id == "sys-1"
    assert rrec.reason == "superseded"
    assert rrec.verify()
    assert ledger.retired_ids(3) == ("sys-1",)
    fetched = ledger.retire_record("sys-1", 4)
    assert fetched == rrec
    # post-retire mutations refused
    with pytest.raises(sa.RetiredSystemError):
        ledger.assess("sys-1", 5, dimension="oversight", outcome="satisfactory")
    with pytest.raises(sa.RetiredSystemError):
        ledger.verify(rec.assessment_id, 6, verdict="substantiated")
    with pytest.raises(sa.RetiredSystemError):
        ledger.retire("sys-1", 7)
    # post-retire reads still work
    assert ledger.evaluate("sys-1", 8).posture == "safe"
    assert ledger.verify_assessment(rec.assessment_id, 9).verdict == "verified"
    # bad reason burns seq
    ledger2 = sa.SafeAI()
    ledger2.assess("sys-2", 1, dimension="robustness", outcome="satisfactory")
    with pytest.raises(sa.BadReasonError):
        ledger2.retire("sys-2", 2, reason="bogus")
    assert ledger2.stats(3)["seq"] == 2
    # unknown system
    with pytest.raises(sa.UnknownSystemError):
        ledger2.retire("sys-nope", 3)


# 12. seq discipline (rewind bare, malformed seqs, failed-mutation-consumes-seq)
def test_seq_discipline():
    ledger = sa.SafeAI()
    for bad in (True, 1.5, "2", None, -1, 0):
        with pytest.raises(sa.SeqOrderError):
            ledger.assess("sys-1", bad, dimension="robustness", outcome="satisfactory")
    # failed mutations consume seq even when input validation fails first
    assert ledger.stats(1)["seq"] == 0  # reads at seq 1: malformed never claimed
    rec = ledger.assess("sys-1", 1, dimension="robustness", outcome="satisfactory")
    with pytest.raises(sa.SeqOrderError):
        ledger.assess("sys-2", 1, dimension="oversight", outcome="satisfactory")  # rewind bare
    assert ledger.stats(2)["seq"] == 1
    assert ledger.stats(2)["n_assessments"] == 1
    # pure reads accept non-negative ints but never consume
    rep = ledger.evaluate("sys-1", 0)
    assert rep.posture == "safe"
    with pytest.raises(sa.SeqOrderError):
        ledger.evaluate("sys-1", -1)
    assert rec.verify()


# 13. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    ledger = sa.SafeAI()
    rec = ledger.assess("sys-1", 1, dimension="monitoring", outcome="satisfactory")
    vrec = ledger.verify(rec.assessment_id, 2, verdict="substantiated")
    ledger.retire("sys-1", 3)
    rows = ledger.audit_log(4)
    kinds = [r["kind"] for r in rows]
    assert kinds == ["assessed", "verified", "retired"]
    for r in rows:
        assert r["schema"] == "audit.ndjson/1"
        assert r["module"] == "safe-ai"
        assert r["version"] == "safe-ai.v1"
    # banned keys never cross the audit boundary raw
    with pytest.raises(sa.SafeAIError):
        sa.safe_ai_audit_event("assessed", 9, incident="raw incident text")
    with pytest.raises(sa.SafeAIError):
        sa.safe_ai_audit_event("assessed", 9, vulnerability="CVE-2026-0001")
    # pinned vocabulary values remain emittable as declared data
    ok = sa.safe_ai_audit_event("assessed", 9, dimension="monitoring", outcome="satisfactory")
    assert ok["details"]["dimension"] == "monitoring"
    # bad kind
    with pytest.raises(sa.AuditKindError):
        sa.safe_ai_audit_event("bogus", 9)
    # bad seq
    with pytest.raises(sa.SeqOrderError):
        sa.safe_ai_audit_event("assessed", True)
    assert vrec.verify()


# 14. cross-instance digest determinism + tamper breaks verify() + thread smoke
def test_determinism_tamper_threads():
    a = sa.SafeAI()
    b = sa.SafeAI()
    ra = a.assess("sys-1", 1, dimension="evaluation", outcome="satisfactory", assessment_digest=PIN)
    rb = b.assess("sys-1", 1, dimension="evaluation", outcome="satisfactory", assessment_digest=PIN)
    assert ra.digest == rb.digest  # cross-instance determinism
    # tamper breaks verify() as data
    object.__setattr__(ra, "dimension", "containment")
    assert ra.verify() is False
    assert a.verify_assessment(ra.assessment_id, 2).verdict == "tampered"
    # 8-thread read smoke: all clean
    c = sa.SafeAI()
    c.assess("sys-1", 1, dimension="transparency", outcome="satisfactory")
    errors = []

    def reader():
        try:
            for _ in range(25):
                assert c.evaluate("sys-1", 2).posture == "safe"
                assert c.assessment_ids(3) == ("ass-1",)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    # frozen-ness of all record types
    vrec = c.verify("ass-1", 4, verdict="substantiated")
    for frozen_rec in (rb, vrec):
        with pytest.raises(dataclasses.FrozenInstanceError):
            frozen_rec.digest = "sha256:" + "ff" * 32  # type: ignore


# 15. main() subprocess check
def test_main_subprocess():
    proc = subprocess.run(
        [sys.executable, str(MOD)], capture_output=True, text=True, timeout=60
    )
    assert proc.returncode == 0, proc.stderr
    assert "safe-ai OK: assess, verify, evaluate, retire, pins, audit" in proc.stdout
