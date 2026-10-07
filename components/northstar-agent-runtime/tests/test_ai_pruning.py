"""Tests for ai_pruning.py - AI pruning-operation decision ledger."""

import importlib.util
import sys
import threading
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

_MOD_PATH = Path(__file__).resolve().parent.parent / "ai_pruning.py"


def _load():
    spec = importlib.util.spec_from_file_location("ai_pruning", str(_MOD_PATH))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["ai_pruning"] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def mod():
    return _load()


@pytest.fixture()
def ledger(mod):
    return mod.AIPruning()


# 1. pins / vocabularies -------------------------------------------------------


def test_pins_and_vocabularies(mod):
    assert mod.AI_PRUNING_VERSION == "ai-pruning.v1"
    assert mod.SCHEMA_PIN == "northstar.ai-pruning.v1"
    assert mod.PRUNING_KINDS == (
        "weight-pruning",
        "neuron-pruning",
        "channel-pruning",
        "structured-pruning",
        "unstructured-pruning",
        "layer-pruning",
        "attention-head-pruning",
        "token-pruning",
    )
    assert mod.VERDICTS == (
        "pruned",
        "partial",
        "failed",
        "inconclusive",
        "not-pruned",
    )
    assert mod.VERIFY_VERDICTS == ("verified", "tampered")
    assert mod.POSTURES == (
        "unpruned",
        "failed",
        "contested",
        "partially-pruned",
        "pruned",
    )
    assert set(mod.AUDIT_KINDS) == {"pruned", "retired", "rejected"}


# 2. stdlib-only ----------------------------------------------------------------


def test_stdlib_only(mod):
    assert mod.stdlib_only()


# 3. prune roundtrip / defaults / minting / frozen-ness ------------------------


def test_prune_roundtrip_defaults_frozen(mod, ledger):
    digest = "sha256:" + "ab" * 32
    rec = ledger.prune(
        "mdl-1", 1, pruning_kind="structured-pruning", sparsity=75,
        verdict="pruned", prune_digest=digest,
    )
    assert rec.prune_id == "prn-1"
    assert rec.model_id == "mdl-1"
    assert rec.pruning_kind == "structured-pruning"
    assert rec.sparsity == 75
    assert rec.verdict == "pruned"
    assert rec.prune_digest == digest
    assert rec.verify()
    rec2 = ledger.prune("mdl-1", 2)
    assert rec2.prune_id == "prn-2"
    assert rec2.pruning_kind == "weight-pruning"  # default kind
    assert rec2.sparsity == 0                     # default sparsity
    assert rec2.verdict == "not-pruned"          # default verdict
    assert rec2.prune_digest == ""               # default digest
    assert rec2.verify()
    with pytest.raises(FrozenInstanceError):
        rec.pruning_kind = "neuron-pruning"  # type: ignore


# 4. bad inputs + seq-burn + rejected rows + rewinds bare -------------------------


def test_bad_inputs_burn_seq_and_rewinds_bare(mod, ledger):
    base = ledger.stats(0)["n_audit_rows"]
    seq = 0

    def expect_fail(seq, exc, **kwargs):
        nonlocal base
        with pytest.raises(exc):
            ledger.prune("mdl-1", seq, **kwargs)

    seq += 1  # 1: empty model id
    with pytest.raises(mod.AIPruningError):
        ledger.prune("", seq)
    seq += 1  # 2: bool model id
    with pytest.raises(mod.AIPruningError):
        ledger.prune(True, seq)
    seq += 1; expect_fail(seq, mod.BadPruningKindError, pruning_kind="nope")
    seq += 1; expect_fail(seq, mod.BadVerdictError, verdict="maybe")
    seq += 1; expect_fail(seq, mod.BadSparsityError, sparsity=-1)
    seq += 1; expect_fail(seq, mod.BadSparsityError, sparsity=101)
    seq += 1; expect_fail(seq, mod.BadSparsityError, sparsity=True)
    seq += 1; expect_fail(seq, mod.BadDigestError, prune_digest="not-a-digest")
    # Every failed mutation burned its seq and booked one rejected row.
    assert seq == 8
    assert ledger.stats(seq)["seq"] == 8
    audit = ledger.audit_log(seq)
    assert len(audit) - base == 8
    assert all(row["kind"] == "rejected" for row in audit[base:])
    # Rewind raises bare with no new row.
    with pytest.raises(mod.SeqOrderError):
        ledger.prune("mdl-1", 8)
    assert ledger.stats(0)["n_audit_rows"] == len(audit)
    # Malformed seqs raise bare (bool / str / negative-shape for mutation).
    with pytest.raises(mod.SeqOrderError):
        ledger.prune("mdl-1", True)
    with pytest.raises(mod.SeqOrderError):
        ledger.prune("mdl-1", "1")
    assert ledger.stats(0)["n_audit_rows"] == len(audit)


# 5. full kind vocabulary --------------------------------------------------------


def test_full_kind_vocabulary(mod, ledger):
    seq = 0
    for i, kind in enumerate(mod.PRUNING_KINDS, start=1):
        rec = ledger.prune("mdl-k", i, pruning_kind=kind, sparsity=50,
                           verdict="pruned")
        assert rec.verify()
        seq = i
    ids = ledger.prunes_for("mdl-k", seq)
    assert {r.pruning_kind for r in ids} == set(mod.PRUNING_KINDS)


# 6. full verdict vocabulary + sparsity bounds + tallies ----------------------------


def test_full_verdict_vocabulary_and_tallies(mod, ledger):
    seq = 0
    for i, verdict in enumerate(mod.VERDICTS, start=1):
        rec = ledger.prune("mdl-v", i, verdict=verdict, sparsity=10 * i)
        assert rec.verify()
        seq = i
    # sparsity boundary values are accepted as declared data
    rec0 = ledger.prune("mdl-b", seq + 1, sparsity=0, verdict="pruned")
    rec100 = ledger.prune("mdl-b", seq + 2, sparsity=100, verdict="pruned")
    assert rec0.verify() and rec100.verify()
    ev = ledger.evaluate("mdl-v", seq + 3)
    assert ev.n_prunes == 5
    assert ev.n_pruned == 1
    assert ev.n_partial == 1
    assert ev.n_failed == 1
    assert ev.n_inconclusive == 1
    assert ev.n_not_pruned == 1
    assert ev.verify()


# 7. verify semantics ----------------------------------------------------------------


def test_verify_semantics(mod, ledger):
    rec = ledger.prune("mdl-1", 1, pruning_kind="layer-pruning",
                       sparsity=60, verdict="pruned")
    rep = ledger.verify(rec.prune_id, 2)
    assert rep.verdict == "verified"
    assert rep.integrity_ok
    assert rep.verify()
    # Tamper is reported as data, never raised.
    object.__setattr__(rec, "sparsity", 99)
    rep2 = ledger.verify(rec.prune_id, 3)
    assert rep2.verdict == "tampered"
    assert not rep2.integrity_ok
    # Unknown record refuses.
    with pytest.raises(mod.UnknownRecordError):
        ledger.verify("prn-999", 4)
    # Pure read: same seq twice is fine, consumes nothing.
    ledger.verify(rec.prune_id, 5)
    ledger.verify(rec.prune_id, 5)
    assert ledger.stats(0)["seq"] == 1


# 8. evaluate posture math ------------------------------------------------------------


def test_evaluate_posture_math(mod):
    cases = [
        ("mdl-f", [("failed",)], "failed"),
        ("mdl-c", [("inconclusive",)], "contested"),
        ("mdl-p", [("partial",)], "partially-pruned"),
        ("mdl-n", [("not-pruned",)], "partially-pruned"),
        ("mdl-ok", [("pruned",), ("pruned",)], "pruned"),
        ("mdl-mix", [("pruned",), ("partial",)], "partially-pruned"),
        ("mdl-fo", [("failed",), ("inconclusive",)], "failed"),
        ("mdl-co", [("inconclusive",), ("partial",)], "contested"),
        ("mdl-po", [("pruned",), ("not-pruned",)], "partially-pruned"),
    ]
    for model_id, verdicts, expected in cases:
        ledger = mod.AIPruning()
        seq = 0
        for v, in verdicts:
            seq += 1
            ledger.prune(model_id, seq, verdict=v)
        ev = ledger.evaluate(model_id, seq + 1)
        assert ev.posture == expected, model_id
        assert ev.verify()
    # Unknown model refuses.
    ledger = mod.AIPruning()
    with pytest.raises(mod.UnknownModelError):
        ledger.evaluate("nope", 0)


# 9. evaluate purity + integrity flip -------------------------------------------------


def test_evaluate_purity_and_integrity(mod, ledger):
    rec = ledger.prune("mdl-1", 1, verdict="pruned")
    ev1 = ledger.evaluate("mdl-1", 2)
    ev2 = ledger.evaluate("mdl-1", 2)
    assert ev1.posture == "pruned"
    assert ev1.integrity_ok
    assert ev1.digest == ev2.digest  # deterministic
    before = ledger.stats(0)["n_audit_rows"]
    ledger.evaluate("mdl-1", 3)  # pure read: no audit row
    assert ledger.stats(0)["n_audit_rows"] == before
    # Tamper flips integrity_ok as data.
    object.__setattr__(rec, "verdict", "failed")
    ev3 = ledger.evaluate("mdl-1", 4)
    assert not ev3.integrity_ok
    assert ev3.posture == "failed"


# 10. retire terminality ----------------------------------------------------------------


def test_retire_terminality(mod, ledger):
    rec = ledger.prune("mdl-1", 1, verdict="pruned")
    ret = ledger.retire("mdl-1", 2)
    assert ret.model_id == "mdl-1"
    assert ret.reason == "manual"
    assert ret.verify()
    # Ids are never recycled.
    assert "mdl-1" in ledger.retired_ids(2)
    # Post-retire mutations are refused...
    with pytest.raises(mod.RetiredModelError):
        ledger.prune("mdl-1", 3)
    # ...but reads still work.
    assert ledger.prune_record(rec.prune_id, 3) is not None
    ev = ledger.evaluate("mdl-1", 4)
    assert ev.posture == "pruned"
    with pytest.raises(mod.RetiredModelError):
        ledger.retire("mdl-1", 5)  # double retire
    with pytest.raises(mod.BadReasonError):
        ledger.retire("mdl-1", 6, reason="nope")


# 11. retire reasons and unknown model ----------------------------------------------------


def test_retire_reasons_and_unknown(mod, ledger):
    for i, reason in enumerate(mod.RETIRE_REASONS):
        model = f"mdl-r{i}"
        ledger.prune(model, i * 2 + 1)
        ret = ledger.retire(model, i * 2 + 2, reason=reason)
        assert ret.reason == reason
        assert ret.verify()
    with pytest.raises(mod.UnknownModelError):
        ledger.retire("never-seen", 100)


# 12. audit shapes + leak ban + bad kind ------------------------------------------------------


def test_audit_shapes_and_leak_ban(mod, ledger):
    digest = "sha256:" + "cd" * 32
    rec = ledger.prune("mdl-1", 1, sparsity=80, prune_digest=digest)
    rows = ledger.audit_log(1)
    row = rows[0]
    assert row["schema"] == "audit.ndjson/1"
    assert row["module"] == "ai-pruning"
    assert row["version"] == "ai-pruning.v1"
    assert row["kind"] == "pruned"
    assert row["seq"] == 1
    assert row["details"]["prune_id"] == rec.prune_id
    assert row["details"]["sparsity"] == 80  # declared scalar data emittable
    # Raw material keys are banned from the audit boundary.
    with pytest.raises(mod.AIPruningError):
        mod.ai_pruning_audit_event(
            "pruned", 2, prune_id="prn-9", weights={"w": 1}
        )
    with pytest.raises(mod.AIPruningError):
        mod.ai_pruning_audit_event("pruned", 2, pruning_mask=[1, 0])
    with pytest.raises(mod.AIPruningError):
        mod.ai_pruning_audit_event("pruned", 2, checkpoint="raw")
    # Digest pins of those values are fine.
    ok = mod.ai_pruning_audit_event(
        "pruned", 2, prune_id="prn-9", prune_digest=digest
    )
    assert ok["details"]["prune_digest"] == digest
    # Bad kinds raise.
    with pytest.raises(mod.AuditKindError):
        mod.ai_pruning_audit_event("nonsense", 3)


# 13. views / stats / unknown lookups ------------------------------------------------------------


def test_views_stats_unknown(mod, ledger):
    r1 = ledger.prune("mdl-a", 1, verdict="pruned")
    r2 = ledger.prune("mdl-a", 2, verdict="partial")
    ledger.prune("mdl-b", 3, verdict="failed")
    assert ledger.model_ids(3) == ("mdl-a", "mdl-b")
    assert ledger.prune_ids(3) == ("prn-1", "prn-2", "prn-3")
    assert ledger.prunes_for("mdl-a", 3)[0].prune_id == "prn-1"
    assert ledger.prune_record(r2.prune_id, 3).verdict == "partial"
    stats = ledger.stats(3)
    assert stats == {
        "seq": 3,
        "n_models": 2,
        "n_prunes": 3,
        "n_retired": 0,
        "n_audit_rows": 3,
    }
    assert ledger.prunes_for("nope", 3) == ()
    with pytest.raises(mod.UnknownPruneError):
        ledger.prune_record("prn-999", 3)
    assert r1.verify()


# 14. determinism + thread smoke ----------------------------------------------------------------------


def test_determinism_and_thread_smoke(mod):
    a = mod.AIPruning()
    b = mod.AIPruning()
    for ledger in (a, b):
        ledger.prune("mdl-1", 1, pruning_kind="neuron-pruning", sparsity=70,
                     verdict="pruned")
        ledger.prune("mdl-1", 2, pruning_kind="channel-pruning", sparsity=20,
                     verdict="partial")
    assert a.evaluate("mdl-1", 3).digest == b.evaluate("mdl-1", 3).digest
    ledger = mod.AIPruning()

    def worker(i):
        ledger.prune(f"mdl-t{i}", i + 1, sparsity=i % 101)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert ledger.stats(8)["n_prunes"] == 8
    assert ledger.stats(8)["n_audit_rows"] == 8


# 15. main() self-check subprocess -----------------------------------------------------------------------


def test_main_subprocess():
    import subprocess

    proc = subprocess.run(
        [sys.executable, str(_MOD_PATH)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert "ai-pruning OK: prune, verify, evaluate, retire, pins, audit" in proc.stdout
