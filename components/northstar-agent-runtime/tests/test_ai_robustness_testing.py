"""Tests for ai_robustness_testing.py - AI robustness test-execution-run decision ledger."""

import importlib.util
import sys
import threading
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

_MOD_PATH = Path(__file__).resolve().parent.parent / "ai_robustness_testing.py"


def _load():
    spec = importlib.util.spec_from_file_location(
        "ai_robustness_testing", str(_MOD_PATH)
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules["ai_robustness_testing"] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def mod():
    return _load()


@pytest.fixture()
def ledger(mod):
    return mod.AIRobustnessTesting()


# 1. pins / vocabularies -------------------------------------------------------


def test_pins_and_vocabularies(mod):
    assert mod.AI_ROBUSTNESS_TESTING_VERSION == "ai-robustness-testing.v1"
    assert mod.SCHEMA_PIN == "northstar.ai-robustness-testing.v1"
    assert mod.RUN_KINDS == (
        "adversarial-suite-run",
        "shift-suite-run",
        "corruption-suite-run",
        "backdoor-scan-run",
        "jailbreak-suite-run",
        "injection-suite-run",
        "poisoning-audit-run",
        "noise-tolerance-run",
    )
    assert mod.OUTCOMES == (
        "passed",
        "partial",
        "failed",
        "inconclusive",
        "not-run",
    )
    assert mod.VERIFY_VERDICTS == ("verified", "tampered")
    assert mod.POSTURES == (
        "untested",
        "failed",
        "contested",
        "partial",
        "robust",
    )
    assert mod.RETIRE_REASONS == (
        "manual",
        "superseded",
        "decommissioned",
        "false-start",
    )
    assert mod.AUDIT_KINDS == ("tested", "retired", "rejected")


# 2. stdlib-only AST self-check -------------------------------------------------


def test_stdlib_only(mod):
    assert mod.stdlib_only() is True


# 3. test roundtrip / run-N minting / verify() / frozen-ness --------------------


def test_test_roundtrip_and_frozen(mod, ledger):
    rec = ledger.test("sys-1", 1, run_kind="adversarial-suite-run", outcome="passed")
    assert rec.run_id == "run-1"
    assert rec.system_id == "sys-1"
    assert rec.run_kind == "adversarial-suite-run"
    assert rec.outcome == "passed"
    assert rec.digest.startswith("sha256:") and len(rec.digest) == 71
    assert rec.verify() is True
    with pytest.raises(FrozenInstanceError):
        rec.outcome = "failed"  # type: ignore
    rec2 = ledger.test("sys-1", 2)
    assert rec2.run_id == "run-2"
    assert rec2.run_kind == "adversarial-suite-run"  # default
    assert rec2.outcome == "not-run"  # default


# 4. bad-input table + seq-burn + rejected-row accounting + rewind bare ---------


def test_bad_input_table_and_seq_burn(mod, ledger):
    bad_calls = [
        dict(system_id="", seq=1),
        dict(system_id="sys-1", seq=2, run_kind="nope"),
        dict(system_id="sys-1", seq=3, outcome="nope"),
        dict(system_id="sys-1", seq=4, test_digest="bad-digest"),
        dict(system_id="  ", seq=5),
        dict(system_id=True, seq=6),
    ]
    for kwargs in bad_calls:
        with pytest.raises(mod.AIRobustnessTestingError):
            ledger.test(**kwargs)
    # all six burned their seqs: six rejected rows booked
    rejected = [r for r in ledger.audit_log(0) if r["kind"] == "rejected"]
    assert len(rejected) == 6
    # seq advanced to 6 despite the failures
    assert ledger.stats(0)["seq"] == 6
    # rewinds raise bare with no new row
    before = len(ledger.audit_log(0))
    with pytest.raises(mod.SeqOrderError):
        ledger.test("sys-1", 6)
    assert len(ledger.audit_log(0)) == before


# 5. full 8-kind run vocabulary -------------------------------------------------


def test_full_run_kind_vocabulary(mod, ledger):
    ids = []
    for i, kind in enumerate(mod.RUN_KINDS):
        rec = ledger.test("sys-v", i + 1, run_kind=kind, outcome="passed")
        assert rec.run_kind == kind
        ids.append(rec.run_id)
    assert ids == [f"run-{i + 1}" for i in range(8)]


# 6. full 5-outcome vocabulary + tallies ----------------------------------------


def test_full_outcome_vocabulary(mod, ledger):
    for i, outcome in enumerate(mod.OUTCOMES):
        rec = ledger.test("sys-o", i + 1, outcome=outcome)
        assert rec.outcome == outcome
    ev = ledger.evaluate("sys-o", 100)
    assert ev.n_runs == 5
    assert ev.n_passed == 1
    assert ev.n_partial == 1
    assert ev.n_failed == 1
    assert ev.n_inconclusive == 1
    assert ev.n_not_run == 1
    assert ev.integrity_ok is True


# 7. verify semantics + tamper-as-data + unknown refusal + read purity ---------


def test_verify_semantics(mod, ledger):
    rec = ledger.test("sys-1", 1, outcome="passed")
    rep = ledger.verify(rec.run_id, 2)
    assert rep.verdict == "verified"
    assert rep.integrity_ok is True
    assert rep.verify() is True
    # read purity: same seq twice, no audit row
    before = len(ledger.audit_log(0))
    rep2 = ledger.verify(rec.run_id, 2)
    assert rep2.verdict == "verified"
    assert len(ledger.audit_log(0)) == before
    # tamper reported as data, never raised
    object.__setattr__(rec, "outcome", "failed")
    rep3 = ledger.verify(rec.run_id, 3)
    assert rep3.verdict == "tampered"
    assert rep3.integrity_ok is False
    # unknown record refused
    with pytest.raises(mod.UnknownRecordError):
        ledger.verify("run-999", 4)


# 8. evaluate posture math (all postures + precedence) --------------------------


def test_evaluate_posture_math(mod):
    l = mod.AIRobustnessTesting()
    # untested via unknown-system refusal instead; empty can't happen post-register,
    # so check precedence ladders:
    s = 0
    l.test("s-failed", 1, outcome="passed")
    s += 1
    l.test("s-failed", 2, outcome="failed")
    s += 1
    assert l.evaluate("s-failed", 3).posture == "failed"  # failed outranks
    l.test("s-contested", 4, outcome="passed")
    l.test("s-contested", 5, outcome="inconclusive")
    assert l.evaluate("s-contested", 6).posture == "contested"
    l.test("s-partial", 7, outcome="passed")
    l.test("s-partial", 8, outcome="not-run")
    assert l.evaluate("s-partial", 9).posture == "partial"
    l.test("s-robust", 10, outcome="passed")
    l.test("s-robust", 11, outcome="passed")
    assert l.evaluate("s-robust", 12).posture == "robust"


# 9. evaluate read purity + tamper flips integrity_ok + unknown refusal ---------


def test_evaluate_read_purity_and_integrity(mod, ledger):
    rec = ledger.test("sys-1", 1, outcome="passed")
    ev1 = ledger.evaluate("sys-1", 2)
    assert ev1.integrity_ok is True
    before = len(ledger.audit_log(0))
    ev2 = ledger.evaluate("sys-1", 2)  # same seq twice is fine
    assert ev2.posture == "robust"
    assert len(ledger.audit_log(0)) == before
    object.__setattr__(rec, "outcome", "failed")
    ev3 = ledger.evaluate("sys-1", 3)
    assert ev3.integrity_ok is False
    assert ev3.posture == "failed"  # derived as data from tampered record
    with pytest.raises(mod.UnknownSystemError):
        ledger.evaluate("sys-zzz", 4)


# 10. retire terminality + id non-recycling + bad reason + post-retire reads -----


def test_retire_terminality(mod, ledger):
    ledger.test("sys-1", 1)
    ret = ledger.retire("sys-1", 2, reason="decommissioned")
    assert ret.system_id == "sys-1"
    assert ret.reason == "decommissioned"
    assert ret.verify() is True
    # mutations refused after retire
    with pytest.raises(mod.RetiredSystemError):
        ledger.test("sys-1", 3)
    # double retire refused
    with pytest.raises(mod.RetiredSystemError):
        ledger.retire("sys-1", 4)
    # ids never recycled: a fresh run on another system mints run-2
    rec = ledger.test("sys-2", 5)
    assert rec.run_id == "run-2"
    # post-retire reads still work
    ev = ledger.evaluate("sys-1", 6)
    assert ev.posture == "partial"  # one not-run run
    assert "sys-1" in ledger.retired_ids(0)
    # bad reason refused (burns seq)
    ledger.test("sys-3", 7)
    with pytest.raises(mod.BadReasonError):
        ledger.retire("sys-3", 8, reason="nope")
    # retire unknown system refused
    with pytest.raises(mod.UnknownSystemError):
        ledger.retire("sys-zzz", 9)


# 11. seq discipline (genesis rewind bare, malformed seqs, burn accounting) -----


def test_seq_discipline(mod, ledger):
    # malformed seqs raise bare with nothing burned
    for bad in (0, "x", 1.5, True, None):
        before = len(ledger.audit_log(0))
        with pytest.raises(mod.SeqOrderError):
            ledger.test("sys-1", bad)
        assert len(ledger.audit_log(0)) == before
    ledger.test("sys-1", 1)
    # genesis rewind bare (seq 1 already claimed): raises bare, no row
    before = len(ledger.audit_log(0))
    with pytest.raises(mod.SeqOrderError):
        ledger.test("sys-1", 1)
    assert len(ledger.audit_log(0)) == before
    # gap seqs are allowed (strictly increasing, not necessarily +1)
    rec = ledger.test("sys-1", 100)
    assert rec.run_id == "run-2"
    # failed mutation consumes seq: bad run_kind at 101 books rejected
    with pytest.raises(mod.BadRunKindError):
        ledger.test("sys-1", 101, run_kind="nope")
    assert ledger.stats(0)["seq"] == 101
    assert [r for r in ledger.audit_log(0) if r["kind"] == "rejected"]


# 12. audit shapes + leak ban + bad-kind ----------------------------------------


def test_audit_shapes_and_leak_ban(mod, ledger):
    ledger.test("sys-1", 1, run_kind="noise-tolerance-run", outcome="passed")
    ledger.retire("sys-1", 2)
    rows = ledger.audit_log(0)
    tested = [r for r in rows if r["kind"] == "tested"]
    assert len(tested) == 1
    row = tested[0]
    assert row["schema"] == "audit.ndjson/1"
    assert row["module"] == "ai-robustness-testing"
    assert row["version"] == "ai-robustness-testing.v1"
    assert row["details"]["run_id"] == "run-1"
    assert row["details"]["run_kind"] == "noise-tolerance-run"
    # banned raw-material keys cannot cross the audit boundary
    with pytest.raises(mod.AIRobustnessTestingError):
        mod.ai_robustness_testing_audit_event(
            "tested", 3, perturbed_inputs=["x"]
        )
    with pytest.raises(mod.AIRobustnessTestingError):
        mod.ai_robustness_testing_audit_event("tested", 3, weights="w")
    # pinned vocab values remain emittable
    ok = mod.ai_robustness_testing_audit_event(
        "tested", 3, run_kind="adversarial-suite-run", outcome="passed"
    )
    assert ok["kind"] == "tested"
    # bad audit kind refused
    with pytest.raises(mod.AuditKindError):
        mod.ai_robustness_testing_audit_event("nope", 3)


# 13. cross-instance digest determinism + views/stats/unknown lookups -----------


def test_cross_instance_determinism_and_views(mod):
    a = mod.AIRobustnessTesting()
    b = mod.AIRobustnessTesting()
    ra = a.test("sys-1", 1, run_kind="shift-suite-run", outcome="partial")
    rb = b.test("sys-1", 1, run_kind="shift-suite-run", outcome="partial")
    assert ra.digest == rb.digest
    assert a.evaluate("sys-1", 2).digest == b.evaluate("sys-1", 2).digest
    # views
    assert a.system_ids(0) == ("sys-1",)
    assert a.run_ids(0) == ("run-1",)
    assert a.runs_for("sys-1", 0)[0].run_id == "run-1"
    assert a.runs_for("sys-zzz", 0) == ()
    st = a.stats(0)
    assert st["n_systems"] == 1 and st["n_runs"] == 1 and st["n_retired"] == 0
    assert st["n_audit_rows"] == 1
    with pytest.raises(mod.UnknownRunError):
        a.run_record("run-999", 0)


# 14. thread read smoke + frozen-ness -------------------------------------------


def test_thread_read_smoke_and_frozen(mod, ledger):
    for i in range(4):
        ledger.test(f"sys-{i}", i + 1, outcome="passed")
    errors = []

    def reader():
        try:
            for _ in range(50):
                ledger.evaluate("sys-0", 0)
                ledger.stats(0)
                ledger.audit_log(0)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    rec = ledger.run_record("run-1", 0)
    with pytest.raises(FrozenInstanceError):
        rec.run_kind = "nope"  # type: ignore


# 15. main() subprocess self-check ----------------------------------------------


def test_main_self_check():
    import subprocess

    proc = subprocess.run(
        [sys.executable, str(_MOD_PATH)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0
    assert "ai-robustness-testing OK: test, verify, evaluate, retire, pins, audit" in proc.stdout
