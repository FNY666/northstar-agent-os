"""Tests for the ai-adversarial test/defense decision ledger, Simulated."""

import ast
import dataclasses
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "ai_adversarial.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("ai_adversarial", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["ai_adversarial"] = module
    spec.loader.exec_module(module)
    return module


aa = _load()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert aa.AI_ADVERSARIAL_VERSION == "ai-adversarial.v1"
    assert aa.SCHEMA_PIN == "northstar.ai-adversarial.v1"
    assert aa.TEST_METHODS == (
        "gradient-based",
        "optimization-based",
        "perturbation-based",
        "generative-attack",
        "query-based",
        "transfer-based",
        "physical-world",
        "poisoning-injection",
    )
    assert aa.TEST_KINDS == (
        "evasion",
        "poisoning",
        "extraction",
        "backdoor",
        "inversion",
        "membership-inference",
        "model-stealing",
        "sponge",
    )
    assert aa.TEST_VERDICTS == ("vulnerable", "suspected", "robust", "inconclusive", "not-tested")
    assert aa.DEFENSE_STRATEGIES == (
        "adversarial-training",
        "input-sanitization",
        "randomized-smoothing",
        "certified-defense",
        "gradient-masking",
        "detection-filter",
        "ensemble-defense",
        "no-action",
    )
    assert aa.VERIFY_VERDICTS == ("verified", "tampered")
    assert aa.POSTURES == ("untested", "vulnerable", "contested", "defended", "robust")
    assert aa.RETIRE_REASONS == ("manual", "superseded", "decommissioned", "false-start")
    assert aa.AUDIT_KINDS == ("tested", "defended", "retired", "rejected")


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


# 3. test roundtrip + verify + frozen-ness
def test_test_roundtrip_verify_frozen():
    ledger = aa.AIAdversarial()
    rec = ledger.test(
        "sys-a", 1, test_method="gradient-based", test_kind="evasion",
        verdict="vulnerable", severity=80, test_digest=PIN,
    )
    assert rec.test_id == "tst-1"
    assert rec.system_id == "sys-a"
    assert rec.verify() is True
    assert dataclasses.is_dataclass(rec) and rec.__dataclass_params__.frozen
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.verdict = "robust"  # type: ignore
    # defaults
    rec2 = ledger.test("sys-b", 2)
    assert rec2.test_id == "tst-2"
    assert rec2.test_method == "gradient-based"
    assert rec2.test_kind == "evasion"
    assert rec2.verdict == "not-tested"
    assert rec2.verify() is True


# 4. bad inputs: fail-closed, seq burned, rejected row booked
def test_bad_inputs_fail_closed():
    ledger = aa.AIAdversarial()
    bad = [
        ({"test_method": "nope"}, aa.BadTestMethodError),
        ({"test_kind": "nope"}, aa.BadTestKindError),
        ({"verdict": "nope"}, aa.BadVerdictError),
        ({"severity": -1}, aa.BadSeverityError),
        ({"severity": 101}, aa.BadSeverityError),
        ({"severity": True}, aa.BadSeverityError),
        ({"severity": 1.5}, aa.BadSeverityError),
        ({"test_digest": "bad"}, aa.BadDigestError),
        ({"system_id": ""}, aa.BadSystemError),
        ({"system_id": 123}, aa.BadSystemError),
    ]
    seq = 1
    for kwargs, exc in bad:
        seq += 1
        kw = dict(kwargs)
        sid = kw.pop("system_id", "sys-a")
        with pytest.raises(exc):
            ledger.test(sid, seq, **kw)
        rejected = [r for r in ledger.audit_log(0) if r["kind"] == "rejected"]
        assert any(r["seq"] == seq for r in rejected)
    # rewind raises bare, no new audit row
    n = len(ledger.audit_log(0))
    with pytest.raises(aa.SeqOrderError):
        ledger.test("sys-a", 2)
    assert len(ledger.audit_log(0)) == n
    # malformed seq shapes
    for bad_seq in (True, 1.5, "3", None):
        with pytest.raises(aa.SeqOrderError):
            ledger.test("sys-a", bad_seq)


# 5. full test-method vocabulary
def test_full_method_vocabulary():
    ledger = aa.AIAdversarial()
    for i, method in enumerate(aa.TEST_METHODS, start=1):
        rec = ledger.test(f"sys-m{i}", i, test_method=method, verdict="robust")
        assert rec.test_method == method
        assert rec.verify() is True


# 6. full test-kind vocabulary + severity boundaries
def test_full_kind_vocabulary_and_severity_bounds():
    ledger = aa.AIAdversarial()
    for i, kind in enumerate(aa.TEST_KINDS, start=1):
        rec = ledger.test(f"sys-k{i}", i, test_kind=kind)
        assert rec.test_kind == kind
        assert rec.verify() is True
    lo = ledger.test("sys-lo", 100, severity=0)
    hi = ledger.test("sys-hi", 101, severity=100)
    assert lo.severity == 0 and hi.severity == 100
    assert lo.verify() and hi.verify()


# 7. defend roundtrip + chainable + refusal on unknown/retired
def test_defend_roundtrip_chain_and_refusals():
    ledger = aa.AIAdversarial()
    rec = ledger.test("sys-a", 1, verdict="vulnerable")
    d1 = ledger.defend(rec.test_id, 2, strategy="adversarial-training", defense_digest=PIN)
    assert d1.defense_id == "def-1"
    assert d1.verify() is True
    # chainable
    d2 = ledger.defend(rec.test_id, 3, strategy="randomized-smoothing")
    assert d2.defense_id == "def-2"
    assert d2.verify() is True
    # unknown test refusal
    with pytest.raises(aa.UnknownTestError):
        ledger.defend("tst-999", 4)
    # bad strategy refusal
    with pytest.raises(aa.BadStrategyError):
        ledger.defend(rec.test_id, 5, strategy="nope")
    # bad digest refusal
    with pytest.raises(aa.BadDigestError):
        ledger.defend(rec.test_id, 6, defense_digest="bad")
    # retired system refusal
    ledger.retire("sys-a", 7)
    with pytest.raises(aa.RetiredSystemError):
        ledger.defend(rec.test_id, 8)


# 8. verify semantics: pure read, tamper-as-data, unknown refusal
def test_verify_semantics():
    ledger = aa.AIAdversarial()
    rec = ledger.test("sys-a", 1, verdict="vulnerable")
    d1 = ledger.defend(rec.test_id, 2)
    before = len(ledger.audit_log(0))
    rep = ledger.verify(rec.test_id, 3)
    assert rep.verdict == "verified"
    assert rep.integrity_ok is True
    # pure read: no audit row, seq not consumed
    assert len(ledger.audit_log(0)) == before
    assert ledger.stats(0)["seq"] == 2
    rep2 = ledger.verify(d1.defense_id, 4)
    assert rep2.verdict == "verified"
    # tamper reported as data, never raised
    object.__setattr__(rec, "verdict", "robust")
    rep3 = ledger.verify(rec.test_id, 5)
    assert rep3.verdict == "tampered"
    assert rep3.integrity_ok is False
    # unknown record refusal
    with pytest.raises(aa.UnknownRecordError):
        ledger.verify("tst-999", 6)
    # malformed read seq
    with pytest.raises(aa.SeqOrderError):
        ledger.verify(rec.test_id, -1)


# 9. evaluate posture math + precedence + tallies
def test_evaluate_posture_math():
    ledger = aa.AIAdversarial()
    # untested -> vulnerable (unmitigated vulnerable)
    r1 = ledger.test("s1", 1, verdict="vulnerable")
    ev = ledger.evaluate("s1", 1)
    assert ev.posture == "vulnerable"
    # defended after defense booked
    ledger.defend(r1.test_id, 2)
    ev = ledger.evaluate("s1", 2)
    assert ev.posture == "defended"
    # contested via suspected
    ledger.test("s2", 3, verdict="suspected")
    ev = ledger.evaluate("s2", 3)
    assert ev.posture == "contested"
    # contested via inconclusive
    ledger.test("s3", 4, verdict="inconclusive")
    ev = ledger.evaluate("s3", 4)
    assert ev.posture == "contested"
    # robust only when all robust
    ledger.test("s4", 5, verdict="robust")
    ledger.test("s4", 6, verdict="robust")
    ev = ledger.evaluate("s4", 6)
    assert ev.posture == "robust"
    # vulnerable outranks suspected
    r5 = ledger.test("s5", 7, verdict="suspected")
    r6 = ledger.test("s5", 8, verdict="vulnerable")
    ev = ledger.evaluate("s5", 8)
    assert ev.posture == "vulnerable"
    ledger.defend(r6.test_id, 9)
    ev = ledger.evaluate("s5", 9)
    assert ev.posture == "contested"
    # tallies
    ev = ledger.evaluate("s5", 9)
    assert ev.n_tests == 2
    assert ev.n_vulnerable == 1
    assert ev.n_suspected == 1
    assert ev.n_defended == 1
    assert ev.integrity_ok is True
    assert ev.verify() is True
    # unknown system
    with pytest.raises(aa.UnknownSystemError):
        ledger.evaluate("nope", 10)


# 10. evaluate read purity + tamper flips integrity_ok
def test_evaluate_read_purity_and_tamper():
    ledger = aa.AIAdversarial()
    rec = ledger.test("sys-a", 1, verdict="robust")
    before = len(ledger.audit_log(0))
    ev1 = ledger.evaluate("sys-a", 1)
    ev2 = ledger.evaluate("sys-a", 99)
    assert ev1.posture == "robust"
    assert ev2.posture == "robust"
    assert ev1.digest != ev2.digest  # seq is part of the pin
    assert len(ledger.audit_log(0)) == before  # no audit rows
    assert ledger.stats(0)["seq"] == 1  # seq not consumed
    object.__setattr__(rec, "severity", 50)
    ev3 = ledger.evaluate("sys-a", 2)
    assert ev3.integrity_ok is False


# 11. retire terminality + id non-recycling + post-retire reads
def test_retire_terminality():
    ledger = aa.AIAdversarial()
    rec = ledger.test("sys-a", 1, verdict="robust")
    ret = ledger.retire("sys-a", 2, reason="decommissioned")
    assert ret.reason == "decommissioned"
    assert ret.verify() is True
    # double retire refuses
    with pytest.raises(aa.RetiredSystemError):
        ledger.retire("sys-a", 3)
    # post-retire mutations refuse
    with pytest.raises(aa.RetiredSystemError):
        ledger.test("sys-a", 4)
    with pytest.raises(aa.RetiredSystemError):
        ledger.defend(rec.test_id, 5)
    # ids never recycled; reads still work
    ev = ledger.evaluate("sys-a", 6)
    assert ev.posture == "robust"
    assert ledger.test_record(rec.test_id, 7) is rec
    # bad reason
    ledger.test("sys-b", 8)
    with pytest.raises(aa.BadReasonError):
        ledger.retire("sys-b", 9, reason="nope")
    # unknown system
    with pytest.raises(aa.UnknownSystemError):
        ledger.retire("ghost", 10)


# 12. seq discipline: rewinds bare, failed mutations consume seq
def test_seq_discipline():
    ledger = aa.AIAdversarial()
    # genesis rewind is bare (seq 0 claim then rewind to 0)
    with pytest.raises(aa.SeqOrderError):
        ledger.test("sys-a", 0)  # 0 <= 0 initial: raises bare, no row
    assert len(ledger.audit_log(0)) == 0
    ledger.test("sys-a", 1)
    # failed mutation consumes seq and books rejected
    with pytest.raises(aa.BadVerdictError):
        ledger.test("sys-a", 2, verdict="nope")
    assert ledger.stats(0)["seq"] == 2
    # gap seqs are allowed (strictly increasing only)
    ledger.test("sys-a", 100)
    assert ledger.stats(0)["seq"] == 100
    # negative read seq rejected
    with pytest.raises(aa.SeqOrderError):
        ledger.stats(-1)


# 13. audit shapes + leak ban + bad kind
def test_audit_shapes_and_leak_ban():
    ledger = aa.AIAdversarial()
    rec = ledger.test("sys-a", 1, verdict="vulnerable")
    ledger.defend(rec.test_id, 2, strategy="input-sanitization")
    ledger.retire("sys-a", 3)
    kinds = [r["kind"] for r in ledger.audit_log(0)]
    assert kinds == ["tested", "defended", "retired"]
    for row in ledger.audit_log(0):
        assert row["schema"] == "audit.ndjson/1"
        assert row["module"] == "ai-adversarial"
        assert row["version"] == "ai-adversarial.v1"
    # pinned vocab values remain emittable as declared data
    tested = ledger.audit_log(0)[0]
    assert tested["details"]["verdict"] == "vulnerable"
    # raw material keys banned
    with pytest.raises(aa.AIAdversarialError):
        aa.ai_adversarial_audit_event("tested", 9, perturbation="x")
    with pytest.raises(aa.AIAdversarialError):
        aa.ai_adversarial_audit_event("defended", 9, adversarial_examples="x")
    # bad kind
    with pytest.raises(aa.AuditKindError):
        aa.ai_adversarial_audit_event("nope", 9)


# 14. cross-instance determinism + views/stats + unknown lookups
def test_determinism_views_stats():
    l1, l2 = aa.AIAdversarial(), aa.AIAdversarial()
    r1 = l1.test("sys-a", 1, verdict="vulnerable", test_digest=PIN)
    r2 = l2.test("sys-a", 1, verdict="vulnerable", test_digest=PIN)
    assert r1.digest == r2.digest  # cross-instance determinism
    assert r1.verify() and r2.verify()
    # views
    assert l1.system_ids(0) == ("sys-a",)
    assert l1.test_ids(0) == ("tst-1",)
    assert l1.defense_ids(0) == ()
    assert l1.retired_ids(0) == ()
    assert len(l1.tests_for("sys-a", 0)) == 1
    assert l1.tests_for("unknown", 0) == ()
    d = l1.defend("tst-1", 2)
    assert len(l1.defenses_for("tst-1", 0)) == 1
    assert l1.defenses_for("tst-1", 0)[0] is d
    st = l1.stats(0)
    assert st["n_systems"] == 1 and st["n_tests"] == 1 and st["n_defenses"] == 1
    assert st["n_audit_rows"] == 2
    # unknown lookups
    with pytest.raises(aa.UnknownTestError):
        l1.test_record("tst-999", 3)
    with pytest.raises(aa.UnknownDefenseError):
        l1.defense_record("def-999", 3)


# 15. thread read smoke + main() subprocess self-check
def test_thread_smoke_and_main():
    ledger = aa.AIAdversarial()
    rec = ledger.test("sys-a", 1, verdict="robust")
    ledger.defend(rec.test_id, 2)
    errors = []

    def reader():
        try:
            for _ in range(50):
                ledger.evaluate("sys-a", 3)
                ledger.verify(rec.test_id, 4)
                ledger.stats(0)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert dataclasses.is_dataclass(rec) and rec.__dataclass_params__.frozen
    out = subprocess.run(
        [sys.executable, str(MOD)], capture_output=True, text=True, check=True
    )
    assert "ai-adversarial OK: test, defend, verify, evaluate, retire, pins, audit" in out.stdout
