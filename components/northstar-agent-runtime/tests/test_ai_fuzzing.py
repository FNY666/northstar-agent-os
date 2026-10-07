"""Tests for the ai-fuzzing campaign decision ledger, Simulated."""

import ast
import dataclasses
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "ai_fuzzing.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("ai_fuzzing", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["ai_fuzzing"] = module
    spec.loader.exec_module(module)
    return module


fz = _load()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert fz.AI_FUZZING_VERSION == "ai-fuzzing.v1"
    assert fz.SCHEMA_PIN == "northstar.ai-fuzzing.v1"
    assert fz.FUZZ_KINDS == (
        "mutation-fuzzing",
        "grammar-fuzzing",
        "coverage-guided",
        "differential-fuzzing",
        "generational-fuzzing",
        "property-fuzzing",
        "model-based",
        "swarm-fuzzing",
    )
    assert fz.FUZZ_OUTCOMES == ("crash-found", "hang-found", "anomaly-found", "clean", "not-run")
    assert fz.VERIFY_VERDICTS == ("verified", "tampered")
    assert fz.POSTURES == ("untested", "fragile", "unstable", "contested", "covered")
    assert fz.RETIRE_REASONS == ("manual", "superseded", "decommissioned", "false-start")
    assert fz.AUDIT_KINDS == ("fuzzed", "retired", "rejected")


# 2. stdlib-only AST check
def test_stdlib_only():
    assert fz.stdlib_only()
    tree = ast.parse(MOD.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in {
                    "hashlib", "json", "threading", "dataclasses", "typing",
                    "__future__", "ast", "pathlib", "canonical_json",
                }


# 3. fuzz roundtrip + fuz-N minting + frozen-ness
def test_fuzz_roundtrip_minting_frozen():
    ledger = fz.AIFuzzing()
    rec = ledger.fuzz("tgt-1", 1, fuzz_kind="coverage-guided", outcome="clean", coverage=30)
    assert rec.fuzz_id == "fuz-1"
    assert rec.verify()
    assert rec.fuzz_kind == "coverage-guided"
    assert rec.outcome == "clean"
    assert rec.coverage == 30
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.outcome = "crash-found"  # type: ignore
    rec2 = ledger.fuzz("tgt-1", 2)
    assert rec2.fuzz_id == "fuz-2"
    assert rec2.fuzz_kind == "mutation-fuzzing"  # default
    assert rec2.outcome == "not-run"  # default
    assert rec2.coverage == 0  # default


# 4. bad inputs burn seq and book rejected rows; rewinds raise bare
def test_bad_inputs_burn_seq_and_rejected_rows():
    ledger = fz.AIFuzzing()
    bad_cases = [
        ({"target_id": "tgt-1", "fuzz_kind": "nope"}, fz.BadFuzzKindError),
        ({"target_id": "tgt-1", "outcome": "nope"}, fz.BadOutcomeError),
        ({"target_id": "tgt-1", "coverage": -1}, fz.BadCoverageError),
        ({"target_id": "tgt-1", "coverage": 101}, fz.BadCoverageError),
        ({"target_id": "tgt-1", "coverage": True}, fz.BadCoverageError),
        ({"target_id": "tgt-1", "fuzz_digest": "garbage"}, fz.BadDigestError),
        ({"target_id": ""}, fz.BadTargetError),
    ]
    n = 0
    for kwargs, exc in bad_cases:
        n += 1
        with pytest.raises(exc):
            ledger.fuzz(kwargs.pop("target_id"), n, **kwargs)
    rows = ledger.audit_log(n + 100)
    rejected = [r for r in rows if r["kind"] == "rejected"]
    assert len(rejected) == len(bad_cases)
    assert ledger.stats(n + 101)["seq"] == n  # burned seqs claim forward
    with pytest.raises(fz.SeqOrderError):
        ledger.fuzz("tgt-1", n)  # rewind raises bare, no new row
    assert len(ledger.audit_log(n + 102)) == len(rows)  # zero new rows


# 5. full fuzz-kind vocabulary sweep
def test_full_fuzz_kind_vocabulary():
    ledger = fz.AIFuzzing()
    seq = 0
    for kind in fz.FUZZ_KINDS:
        seq += 1
        rec = ledger.fuzz("tgt-1", seq, fuzz_kind=kind)
        assert rec.fuzz_kind == kind
        assert rec.verify()


# 6. full outcome vocabulary sweep + coverage bounds
def test_full_outcome_vocabulary():
    ledger = fz.AIFuzzing()
    seq = 0
    for outcome in fz.FUZZ_OUTCOMES:
        seq += 1
        rec = ledger.fuzz("tgt-1", seq, outcome=outcome)
        assert rec.outcome == outcome
        assert rec.verify()
    ledger2 = fz.AIFuzzing()
    rec0 = ledger2.fuzz("t", 1, coverage=0)
    assert rec0.coverage == 0
    rec100 = ledger2.fuzz("t", 2, coverage=100)
    assert rec100.coverage == 100


# 7. verify semantics: verified/tampered as data, read purity, unknown refusal
def test_verify_semantics():
    ledger = fz.AIFuzzing()
    rec = ledger.fuzz("tgt-1", 1)
    n_rows = len(ledger.audit_log(100))
    rep = ledger.verify(rec.fuzz_id, 2)
    assert rep.verdict == "verified"
    assert rep.integrity_ok is True
    assert rep.verify()
    assert len(ledger.audit_log(101)) == n_rows  # pure read: no audit rows
    rep2 = ledger.verify(rec.fuzz_id, 2)  # same read seq twice is fine
    assert rep2.verdict == "verified"
    # tamper is reported as data, never raised
    object.__setattr__(rec, "outcome", "crash-found")
    rep3 = ledger.verify(rec.fuzz_id, 3)
    assert rep3.verdict == "tampered"
    assert rep3.integrity_ok is False
    with pytest.raises(fz.UnknownRecordError):
        ledger.verify("fuz-999", 4)
    with pytest.raises(fz.SeqOrderError):
        ledger.verify(rec.fuzz_id, -1)


# 8. evaluate posture math: all postures + precedence
def test_evaluate_posture_math():
    ledger = fz.AIFuzzing()
    seq = 0
    # covered: all clean/not-run
    for outcome in ("clean", "not-run"):
        seq += 1
        ledger.fuzz("a", seq, outcome=outcome)
    ev = ledger.evaluate("a", seq + 10)
    assert ev.posture == "covered"
    assert ev.n_fuzzes == 2 and ev.n_clean == 1 and ev.n_not_run == 1
    # contested: any anomaly-found
    seq += 1
    ledger.fuzz("b", seq, outcome="anomaly-found")
    assert ledger.evaluate("b", seq + 10).posture == "contested"
    # unstable: hang-found outranks anomaly-found
    seq += 1
    ledger.fuzz("c", seq, outcome="hang-found")
    seq += 1
    ledger.fuzz("c", seq, outcome="anomaly-found")
    assert ledger.evaluate("c", seq + 10).posture == "unstable"
    # fragile: crash-found outranks everything
    seq += 1
    ledger.fuzz("d", seq, outcome="crash-found")
    seq += 1
    ledger.fuzz("d", seq, outcome="hang-found")
    evd = ledger.evaluate("d", seq + 10)
    assert evd.posture == "fragile"
    assert evd.n_crash_found == 1 and evd.n_hang_found == 1
    assert evd.integrity_ok is True
    assert evd.verify()


# 9. evaluate read purity + unknown-target refusal
def test_evaluate_read_purity_and_unknown():
    ledger = fz.AIFuzzing()
    ledger.fuzz("tgt-1", 1, outcome="clean")
    n_rows = len(ledger.audit_log(100))
    ev1 = ledger.evaluate("tgt-1", 101)
    ev2 = ledger.evaluate("tgt-1", 101)  # same seq twice: pure read
    assert ev1.digest == ev2.digest
    assert len(ledger.audit_log(102)) == n_rows  # no audit rows, seq unclaimed
    assert ledger.stats(103)["seq"] == 1  # mutation seq untouched by reads
    with pytest.raises(fz.UnknownTargetError):
        ledger.evaluate("nope", 104)


# 10. retire terminality: bad reason, double-retire, id non-recycling, post-retire reads
def test_retire_terminality():
    ledger = fz.AIFuzzing()
    ledger.fuzz("tgt-1", 1, outcome="clean")
    with pytest.raises(fz.BadReasonError):
        ledger.retire("tgt-1", 2, reason="nope")
    with pytest.raises(fz.UnknownTargetError):
        ledger.retire("ghost", 3)
    ret = ledger.retire("tgt-1", 4, reason="superseded")
    assert ret.reason == "superseded"
    assert ret.verify()
    assert "tgt-1" in ledger.retired_ids(100)
    with pytest.raises(fz.RetiredTargetError):
        ledger.retire("tgt-1", 5)  # double-retire refused
    with pytest.raises(fz.RetiredTargetError):
        ledger.fuzz("tgt-1", 6)  # post-retire mutations refused
    # reads still work post-retire
    assert ledger.evaluate("tgt-1", 100).posture == "covered"
    assert len(ledger.fuzzes_for("tgt-1", 100)) == 1


# 11. seq discipline: genesis rewind bare, malformed seqs, failed-mutation-consumes-seq
def test_seq_discipline():
    ledger = fz.AIFuzzing()
    with pytest.raises(fz.SeqOrderError):
        ledger.fuzz("tgt-1", 0)  # seq must be > current seq (0 at genesis)
    rec = ledger.fuzz("tgt-1", 1)
    assert rec.fuzz_id == "fuz-1"
    for bad in (True, 1.5, "1", None):
        with pytest.raises(fz.SeqOrderError):
            ledger.fuzz("tgt-1", bad)
    with pytest.raises(fz.BadOutcomeError):
        ledger.fuzz("tgt-1", 2, outcome="bogus")  # burns seq 2
    rec2 = ledger.fuzz("tgt-1", 3)
    assert rec2.fuzz_id == "fuz-2"


# 12. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    ledger = fz.AIFuzzing()
    ledger.fuzz("tgt-1", 1, fuzz_kind="differential-fuzzing", outcome="clean", coverage=42)
    ledger.retire("tgt-1", 2)
    with pytest.raises(fz.BadOutcomeError):
        ledger.fuzz("tgt-1", 3, outcome="bogus")
    rows = ledger.audit_log(100)
    assert [r["kind"] for r in rows] == ["fuzzed", "retired", "rejected"]
    for r in rows:
        assert r["schema"] == "audit.ndjson/1"
        assert r["module"] == "ai-fuzzing"
        assert r["version"] == "ai-fuzzing.v1"
    fuzzed = rows[0]["details"]
    assert fuzzed["fuzz_kind"] == "differential-fuzzing"  # pinned vocab emittable
    assert fuzzed["coverage"] == 42  # declared scalar emittable
    for banned in ("crash_trace", "seed", "corpus", "stack_trace", "poc", "harness"):
        with pytest.raises(fz.AIFuzzingError):
            fz.ai_fuzzing_audit_event("fuzzed", 99, **{banned: "raw"})
    with pytest.raises(fz.AuditKindError):
        fz.ai_fuzzing_audit_event("bogus", 99)


# 13. cross-instance digest determinism + views/stats + unknown lookups
def test_cross_instance_digest_determinism_and_views():
    a = fz.AIFuzzing()
    b = fz.AIFuzzing()
    ra = a.fuzz("tgt", 1, fuzz_kind="grammar-fuzzing", outcome="clean", coverage=10)
    rb = b.fuzz("tgt", 1, fuzz_kind="grammar-fuzzing", outcome="clean", coverage=10)
    assert ra.digest == rb.digest  # deterministic across instances
    assert a.target_ids(10) == ("tgt",)
    assert a.fuzz_ids(10) == ("fuz-1",)
    assert len(a.fuzzes_for("tgt", 10)) == 1
    assert a.fuzz_record("fuz-1", 10).fuzz_id == "fuz-1"
    st = a.stats(10)
    assert st["n_targets"] == 1 and st["n_fuzzes"] == 1 and st["n_retired"] == 0
    with pytest.raises(fz.UnknownFuzzError):
        a.fuzz_record("fuz-999", 10)
    assert a.retired_ids(10) == ()


# 14. 8-thread read smoke + frozen-ness of all record types
def test_thread_safety_and_frozen():
    ledger = fz.AIFuzzing()
    ledger.fuzz("tgt-1", 1, outcome="clean")
    ledger.retire("tgt-1", 2)
    errors = []

    def reader():
        try:
            for _ in range(25):
                ledger.evaluate("tgt-1", 100)
                ledger.verify("fuz-1", 100)
                ledger.stats(100)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    for rec in (
        ledger.fuzz_record("fuz-1", 100),
        ledger.evaluate("tgt-1", 100),
    ):
        with pytest.raises(dataclasses.FrozenInstanceError):
            rec.posture = "x"  # type: ignore


# 15. main() subprocess self-check
def test_main_self_check():
    out = subprocess.run(
        [sys.executable, str(MOD)],
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    ).stdout
    assert "ai-fuzzing OK: fuzz, verify, evaluate, retire, pins, audit" in out
