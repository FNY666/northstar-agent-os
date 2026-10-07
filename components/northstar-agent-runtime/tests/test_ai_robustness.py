"""Tests for the ai-robustness test-governance decision ledger, Simulated."""

import ast
import dataclasses
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "ai_robustness.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("ai_robustness", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["ai_robustness"] = module
    spec.loader.exec_module(module)
    return module


ar = _load()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert ar.AI_ROBUSTNESS_VERSION == "ai-robustness.v1"
    assert ar.SCHEMA_PIN == "northstar.ai-robustness.v1"
    assert ar.TEST_KINDS == (
        "adversarial",
        "distribution-shift",
        "perturbation",
        "stress",
        "calibration",
        "uncertainty",
        "fault-injection",
        "regeneration",
    )
    assert ar.TEST_OUTCOMES == ("robust", "degraded", "fragile", "inconclusive", "not-run")
    assert ar.VERIFY_VERDICTS == ("verified", "tampered")
    assert ar.POSTURES == (
        "untested",
        "fragile",
        "degraded",
        "contested",
        "unevaluated",
        "robust",
    )
    assert ar.RETIRE_REASONS == ("manual", "superseded", "decommissioned", "false-start")
    assert ar.AUDIT_KINDS == ("tested", "retired", "rejected")


# 2. stdlib-only AST check + stdlib_only()
def test_stdlib_only_ast():
    assert ar.stdlib_only() is True
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


# 3. test roundtrip + tst-N minting + verify() + frozen-ness
def test_test_roundtrip():
    ledger = ar.AIRobustness()
    rec = ledger.test(
        "sys-1", 1, test_kind="stress", outcome="degraded", test_digest=PIN,
    )
    assert rec.test_id == "tst-1"
    assert rec.system_id == "sys-1"
    assert rec.seq == 1
    assert rec.verify() is True
    rec2 = ledger.test("sys-2", 2)
    assert rec2.test_id == "tst-2"
    assert rec2.test_kind == "adversarial"
    assert rec2.outcome == "not-run"
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.outcome = "robust"  # type: ignore[misc]


# 4. test bad-input table + seq-burn + rejected-row accounting + rewind bare
def test_test_bad_inputs():
    ledger = ar.AIRobustness()
    bads = [
        ("", 1, "adversarial", "robust", PIN),        # empty system id
        (123, 2, "adversarial", "robust", PIN),       # non-string id
        ("sys-1", 3, "bogus-kind", "robust", PIN),    # bad test kind
        ("sys-1", 4, "adversarial", "bogus", PIN),    # bad outcome
        ("sys-1", 5, "adversarial", "robust", "nope"),  # bad digest
        ("sys-1", 6, "adversarial", "robust", "sha256:" + "zz" * 32),  # bad hex
        (None, 7, "adversarial", "robust", PIN),      # None id
        (True, 8, "adversarial", "robust", PIN),      # bool id
    ]
    for system_id, seq, kind, outcome, digest in bads:
        with pytest.raises(ar.AIRobustnessError):
            ledger.test(
                system_id, seq, test_kind=kind, outcome=outcome,
                test_digest=digest,
            )
    # claim-then-burn: each failed mutation consumed its seq
    assert ledger.stats(9)["seq"] == 8
    rejected = [r for r in ledger.audit_log(9) if r["kind"] == "rejected"]
    assert len(rejected) == 8
    # rewind raises bare with no new row
    with pytest.raises(ar.SeqOrderError):
        ledger.test("sys-1", 8)
    assert ledger.stats(9)["seq"] == 8
    assert len([r for r in ledger.audit_log(9) if r["kind"] == "rejected"]) == 8


# 5. full 8-test-kind vocabulary
def test_full_test_kind_vocabulary():
    ledger = ar.AIRobustness()
    for i, kind in enumerate(ar.TEST_KINDS, start=1):
        rec = ledger.test("sys-1", i, test_kind=kind, outcome="robust")
        assert rec.test_kind == kind
        assert rec.verify() is True
    assert ledger.stats(9)["n_tests"] == 8


# 6. full 5-outcome vocabulary
def test_full_outcome_vocabulary():
    ledger = ar.AIRobustness()
    for i, outcome in enumerate(ar.TEST_OUTCOMES, start=1):
        rec = ledger.test("sys-1", i, test_kind="adversarial", outcome=outcome)
        assert rec.outcome == outcome
    assert ledger.stats(6)["n_tests"] == 5


# 7. verify semantics + tamper-as-data + unknown refusal + read purity
def test_verify_semantics():
    ledger = ar.AIRobustness()
    rec = ledger.test("sys-1", 1, test_kind="perturbation", outcome="robust")
    rep = ledger.verify(rec.test_id, 1)
    assert rep.verdict == "verified"
    assert rep.integrity_ok is True
    assert rep.verify() is True
    # pure read: same-seq twice, no audit rows consumed
    before = len(ledger.audit_log(1))
    rep2 = ledger.verify(rec.test_id, 1)
    assert rep2.verdict == "verified"
    assert len(ledger.audit_log(1)) == before
    # tamper reported as data, never raised
    object.__setattr__(rec, "outcome", "fragile")
    rep3 = ledger.verify(rec.test_id, 1)
    assert rep3.verdict == "tampered"
    assert rep3.integrity_ok is False
    # unknown test id refused
    with pytest.raises(ar.UnknownRecordError):
        ledger.verify("tst-999", 1)


# 8. evaluate posture math (5 reachable postures + precedence)
def test_evaluate_posture_math():
    robust_ledger = ar.AIRobustness()
    robust_ledger.test("s", 1, outcome="robust")
    ev = robust_ledger.evaluate("s", 1)
    assert ev.posture == "robust"
    assert ev.n_tests == 1 and ev.n_robust == 1

    degraded_ledger = ar.AIRobustness()
    degraded_ledger.test("s", 1, outcome="robust")
    degraded_ledger.test("s", 2, outcome="degraded")
    ev = degraded_ledger.evaluate("s", 2)
    assert ev.posture == "degraded"
    assert ev.n_degraded == 1

    fragile_ledger = ar.AIRobustness()
    fragile_ledger.test("s", 1, outcome="robust")
    fragile_ledger.test("s", 2, outcome="degraded")
    fragile_ledger.test("s", 3, outcome="fragile")
    ev = fragile_ledger.evaluate("s", 3)
    assert ev.posture == "fragile"  # fragile outranks degraded
    assert ev.n_fragile == 1

    contested_ledger = ar.AIRobustness()
    contested_ledger.test("s", 1, outcome="inconclusive")
    ev = contested_ledger.evaluate("s", 1)
    assert ev.posture == "contested"

    unevaluated_ledger = ar.AIRobustness()
    unevaluated_ledger.test("s", 1, outcome="not-run")
    ev = unevaluated_ledger.evaluate("s", 1)
    assert ev.posture == "unevaluated"
    assert ev.n_not_run == 1
    assert ev.integrity_ok is True
    assert ev.verify() is True


# 9. evaluate read purity + unknown-system refusal + integrity-flip-as-data
def test_evaluate_purity_and_integrity():
    ledger = ar.AIRobustness()
    ledger.test("s", 1, test_kind="stress", outcome="robust", test_digest=PIN)
    ev1 = ledger.evaluate("s", 1)
    assert ev1.posture == "robust"
    before = len(ledger.audit_log(1))
    ev2 = ledger.evaluate("s", 1)
    assert ev2.posture == "robust"
    assert len(ledger.audit_log(1)) == before  # pure read, no rows
    with pytest.raises(ar.UnknownSystemError):
        ledger.evaluate("ghost", 1)
    # tamper flips integrity_ok as data, never raises
    rec = ledger.test_record("tst-1", 1)
    object.__setattr__(rec, "test_kind", "adversarial")
    ev3 = ledger.evaluate("s", 1)
    assert ev3.integrity_ok is False


# 10. retire terminality + id non-recycling + bad reason + post-retire reads
def test_retire_terminality():
    ledger = ar.AIRobustness()
    ledger.test("s", 1, outcome="robust")
    ret = ledger.retire("s", 2, reason="superseded")
    assert ret.verify() is True
    assert ledger.retired_ids(3) == ("s",)
    # double retire refused and burns seq
    with pytest.raises(ar.RetiredSystemError):
        ledger.retire("s", 3)
    # post-retire mutations refused
    with pytest.raises(ar.RetiredSystemError):
        ledger.test("s", 4, outcome="robust")
    # ids never recycled: a later test on a new id does not reuse tst-N
    rec = ledger.test("s2", 5, outcome="robust")
    assert rec.test_id == "tst-2"
    # post-retire reads still work
    ev = ledger.evaluate("s", 6)
    assert ev.posture == "robust"
    assert ledger.tests_for("s", 6)
    # bad reason on a live system burns seq
    ledger2 = ar.AIRobustness()
    ledger2.test("t", 1)
    with pytest.raises(ar.BadReasonError):
        ledger2.retire("t", 2, reason="bogus")
    assert ledger2.stats(3)["seq"] == 2


# 11. seq discipline: malformed seqs raise bare, rewinds raise bare
def test_seq_discipline():
    ledger = ar.AIRobustness()
    for bad_seq in (True, "1", 1.5, None):
        with pytest.raises(ar.SeqOrderError):
            ledger.test("s", bad_seq, outcome="robust")
    assert ledger.audit_log(1) == ()  # malformed seqs write nothing
    ledger.test("s", 1, outcome="robust")
    with pytest.raises(ar.SeqOrderError):
        ledger.test("s", 1, outcome="robust")  # rewind raises bare
    assert len(ledger.audit_log(1)) == 1  # no new row
    with pytest.raises(ar.SeqOrderError):
        ledger.evaluate("s", -1)  # negative read seq refused


# 12. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    ledger = ar.AIRobustness()
    rec = ledger.test("s", 1, test_kind="adversarial", outcome="robust")
    rows = ledger.audit_log(2)
    assert len(rows) == 1
    row = rows[0]
    assert row["schema"] == "audit.ndjson/1"
    assert row["module"] == "ai-robustness"
    assert row["version"] == "ai-robustness.v1"
    assert row["kind"] == "tested"
    assert row["seq"] == 1
    assert row["details"]["test_id"] == rec.test_id
    assert row["details"]["test_kind"] == "adversarial"
    assert not (set(row["details"]) & ar._BANNED_AUDIT_KEYS)
    ledger.retire("s", 2)
    kinds = [r["kind"] for r in ledger.audit_log(3)]
    assert kinds == ["tested", "retired"]
    # raw material keys banned at the builder level
    with pytest.raises(ar.AIRobustnessError):
        ar.ai_robustness_audit_event("tested", 3, transcript="raw-material")
    with pytest.raises(ar.AIRobustnessError):
        ar.ai_robustness_audit_event("tested", 3, weights="raw-material")
    # bad audit kind
    with pytest.raises(ar.AuditKindError):
        ar.ai_robustness_audit_event("bogus", 3)
    # pinned vocab values remain emittable as declared data
    ok = ar.ai_robustness_audit_event(
        "tested", 3, test_id="tst-1", test_kind="adversarial", outcome="robust"
    )
    assert ok["details"]["outcome"] == "robust"


# 13. views/stats + unknown lookups
def test_views_and_stats():
    ledger = ar.AIRobustness()
    ledger.test("s1", 1, test_kind="adversarial", outcome="robust")
    ledger.test("s2", 2, test_kind="stress", outcome="degraded")
    assert ledger.system_ids(3) == ("s1", "s2")
    assert ledger.test_ids(3) == ("tst-1", "tst-2")
    assert len(ledger.tests_for("s1", 3)) == 1
    assert ledger.tests_for("ghost", 3) == ()
    stats = ledger.stats(3)
    assert stats["n_systems"] == 2
    assert stats["n_tests"] == 2
    assert stats["n_retired"] == 0
    assert stats["n_audit_rows"] == 2
    with pytest.raises(ar.UnknownTestError):
        ledger.test_record("tst-999", 3)


# 14. cross-instance digest determinism + tamper + 8-thread read smoke
def test_determinism_and_thread_smoke():
    def build():
        ledger = ar.AIRobustness()
        ledger.test("s", 1, test_kind="stress", outcome="robust", test_digest=PIN)
        ledger.test("s", 2, test_kind="calibration", outcome="degraded", test_digest=PIN2)
        return ledger

    a, b = build(), build()
    for tid in ("tst-1", "tst-2"):
        assert a.test_record(tid, 1).digest == b.test_record(tid, 1).digest
    rec = a.test_record("tst-1", 1)
    object.__setattr__(rec, "outcome", "fragile")
    assert rec.verify() is False

    ledger = build()
    errors = []

    def reader():
        try:
            for _ in range(50):
                ledger.test_record("tst-1", 1)
                ledger.evaluate("s", 1)
                ledger.stats(1)
                ledger.audit_log(1)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors


# 15. main() subprocess self-check
def test_main_subprocess():
    proc = subprocess.run(
        [sys.executable, str(MOD)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0
    assert "ai-robustness OK: test, verify, evaluate, retire, pins, audit" in proc.stdout
