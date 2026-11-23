"""Tests for ai_distillation.py - AI knowledge-distillation decision ledger."""

import importlib.util
import sys
import threading
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

_MOD_PATH = Path(__file__).resolve().parent.parent / "ai_distillation.py"


def _load():
    spec = importlib.util.spec_from_file_location("ai_distillation", str(_MOD_PATH))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["ai_distillation"] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def mod():
    return _load()


@pytest.fixture()
def ledger(mod):
    return mod.AIDistillation()


# 1. pins / vocabularies -------------------------------------------------------


def test_pins_and_vocabularies(mod):
    assert mod.AI_DISTILLATION_VERSION == "ai-distillation.v1"
    assert mod.SCHEMA_PIN == "northstar.ai-distillation.v1"
    assert mod.DISTILLATION_KINDS == (
        "logit-matching",
        "feature-matching",
        "attention-transfer",
        "relation-distillation",
        "self-distillation",
        "data-free-distillation",
        "online-distillation",
        "quantization-aware-distillation",
    )
    assert mod.FIDELITIES == (
        "faithful",
        "partial",
        "degraded",
        "inconclusive",
        "not-distilled",
    )
    assert mod.VERIFY_VERDICTS == ("verified", "tampered")
    assert mod.POSTURES == (
        "unexamined",
        "degraded",
        "contested",
        "partial",
        "distilled",
    )
    assert set(mod.AUDIT_KINDS) == {"distilled", "retired", "rejected"}


# 2. stdlib-only ----------------------------------------------------------------


def test_stdlib_only(mod):
    assert mod.stdlib_only()


# 3. distill roundtrip / defaults / minting / frozen-ness ------------------------


def test_distill_roundtrip_defaults_frozen(mod, ledger):
    digest = "sha256:" + "ab" * 32
    rec = ledger.distill(
        "pair-1", 1, distillation_kind="logit-matching", fidelity="faithful",
        distillation_digest=digest,
    )
    assert rec.distillation_id == "dst-1"
    assert rec.pair_id == "pair-1"
    assert rec.distillation_kind == "logit-matching"
    assert rec.fidelity == "faithful"
    assert rec.distillation_digest == digest
    assert rec.verify()
    rec2 = ledger.distill("pair-1", 2)
    assert rec2.distillation_id == "dst-2"
    assert rec2.distillation_kind == "logit-matching"   # default kind
    assert rec2.fidelity == "not-distilled"              # default fidelity
    assert rec2.distillation_digest == ""               # default digest
    assert rec2.verify()
    with pytest.raises(FrozenInstanceError):
        rec.distillation_kind = "feature-matching"  # type: ignore


# 4. bad inputs + seq-burn + rejected rows + rewinds bare -------------------------


def test_bad_inputs_burn_seq_and_rewinds_bare(mod, ledger):
    bad = [
        ("", "logit-matching", "faithful", ""),              # empty pair id
        (123, "logit-matching", "faithful", ""),             # bad id type
        (True, "logit-matching", "faithful", ""),            # bool id
        ("pair-1", "bogus-kind", "faithful", ""),            # bad kind
        ("pair-1", "logit-matching", "bogus", ""),           # bad fidelity
        ("pair-1", "logit-matching", "faithful", "nope"),    # bad digest
        ("pair-1", "logit-matching", "faithful", "sha256:zz"),  # bad digest hex
    ]
    seq = 0
    for pair_id, kind, fidelity, d in bad:
        seq += 1
        with pytest.raises(mod.AIDistillationError):
            ledger.distill(pair_id, seq, kind, fidelity, d)
    rows = ledger.audit_log(1)
    rejected_rows = [r for r in rows if r["kind"] == "rejected"]
    assert len(rejected_rows) == len(bad)
    assert ledger.stats(1)["n_distillations"] == 0
    # failed mutations consumed their seqs: next valid claim must be seq+1
    rec = ledger.distill("pair-1", seq + 1, fidelity="faithful")
    assert rec.distillation_id == "dst-1"
    # rewinds raise bare with zero new rows
    n_rows = len(ledger.audit_log(1))
    with pytest.raises(mod.SeqOrderError):
        ledger.distill("pair-1", seq + 1)
    with pytest.raises(mod.SeqOrderError):
        ledger.distill("pair-1", 0)
    assert len(ledger.audit_log(1)) == n_rows
    # malformed seq types raise bare with zero rows
    for bad_seq in ("1", 1.5, True, None):
        with pytest.raises(mod.SeqOrderError):
            ledger.distill("pair-1", bad_seq)
    assert len(ledger.audit_log(1)) == n_rows


# 5. full 8-kind vocabulary ----------------------------------------------------


def test_full_kind_vocabulary(mod, ledger):
    seq = 0
    for kind in mod.DISTILLATION_KINDS:
        seq += 1
        rec = ledger.distill(f"pair-{seq}", seq, distillation_kind=kind)
        assert rec.verify()
        assert rec.distillation_kind == kind
    assert ledger.stats(1)["n_distillations"] == 8


# 6. full 5-fidelity vocabulary + tallies ----------------------------------------


def test_full_fidelity_vocabulary_and_tallies(mod, ledger):
    seq = 0
    for fidelity in mod.FIDELITIES:
        seq += 1
        rec = ledger.distill("pair-1", seq, fidelity=fidelity)
        assert rec.verify()
    ev = ledger.evaluate("pair-1", seq + 1)
    assert ev.n_distillations == 5
    assert ev.n_faithful == 1
    assert ev.n_partial == 1
    assert ev.n_degraded == 1
    assert ev.n_inconclusive == 1
    assert ev.n_not_distilled == 1
    assert ev.verify()


# 7. verify semantics: verified / tamper-as-data / read purity / unknown --------


def test_verify_semantics(mod, ledger):
    rec = ledger.distill("pair-1", 1, distillation_kind="feature-matching", fidelity="faithful")
    rep = ledger.verify(rec.distillation_id, 2)
    assert rep.verdict == "verified"
    assert rep.integrity_ok
    assert rep.verify()
    with pytest.raises(mod.UnknownRecordError):
        ledger.verify("dst-999", 3)
    # read purity: same-seq-twice, no audit rows, seq never consumed
    n_rows = len(ledger.audit_log(1))
    ledger.verify(rec.distillation_id, 2)
    ledger.verify(rec.distillation_id, 2)
    assert len(ledger.audit_log(1)) == n_rows
    # tamper reported as data, never raised
    object.__setattr__(rec, "fidelity", "degraded")
    assert not rec.verify()
    rep2 = ledger.verify(rec.distillation_id, 2)
    assert rep2.verdict == "tampered"
    assert not rep2.integrity_ok


# 8. evaluate posture math: all postures + precedence ------------------------------


def test_evaluate_posture_math(mod):
    cases = [
        ([("faithful",)], "distilled"),
        ([("faithful",), ("faithful",)], "distilled"),
        ([("partial",)], "partial"),
        ([("not-distilled",)], "partial"),
        ([("faithful",), ("partial",)], "partial"),
        ([("inconclusive",)], "contested"),
        ([("faithful",), ("inconclusive",)], "contested"),
        ([("partial",), ("inconclusive",)], "contested"),   # inconclusive > partial
        ([("degraded",)], "degraded"),
        ([("faithful",), ("degraded",)], "degraded"),       # degraded outranks
        ([("inconclusive",), ("degraded",)], "degraded"),
    ]
    for fidelities, want in cases:
        ledger = mod.AIDistillation()
        seq = 0
        for (f,) in fidelities:
            seq += 1
            ledger.distill("pair-1", seq, fidelity=f)
        ev = ledger.evaluate("pair-1", seq + 1)
        assert ev.posture == want, (fidelities, ev.posture)
        assert ev.integrity_ok
        assert ev.verify()


# 9. evaluate purity + integrity flip + unknown refusal -----------------------------


def test_evaluate_purity_and_integrity(mod, ledger):
    ledger.distill("pair-1", 1, fidelity="faithful")
    ev = ledger.evaluate("pair-1", 2)
    assert ev.posture == "distilled"
    assert ev.integrity_ok
    # read purity: same-seq-twice adds no rows
    n_rows = len(ledger.audit_log(1))
    ledger.evaluate("pair-1", 2)
    ledger.evaluate("pair-1", 2)
    assert len(ledger.audit_log(1)) == n_rows
    # tamper flips integrity_ok as data
    rec = ledger.distillation_record("dst-1", 1)
    object.__setattr__(rec, "distillation_kind", "feature-matching")
    ev2 = ledger.evaluate("pair-1", 3)
    assert not ev2.integrity_ok
    # unknown pair refused
    with pytest.raises(mod.UnknownPairError):
        ledger.evaluate("nope", 1)
    with pytest.raises(mod.BadInputError):
        ledger.evaluate("", 1)


# 10. retire terminality: reasons, terminal, non-recycling, reads ----------------------


def test_retire_terminality(mod, ledger):
    ledger.distill("pair-1", 1)
    ret = ledger.retire("pair-1", 2)
    assert ret.verify()
    assert "pair-1" in ledger.retired_ids(1)
    with pytest.raises(mod.RetiredPairError):
        ledger.distill("pair-1", 3)      # post-retire mutation refused + burned
    with pytest.raises(mod.RetiredPairError):
        ledger.retire("pair-1", 4)       # double retire refused
    with pytest.raises(mod.BadReasonError):
        ledger.retire("pair-1", 5, reason="bogus")
    # reads still work after retire
    ev = ledger.evaluate("pair-1", 6)
    assert ev.posture == "partial"      # default fidelity not-distilled
    rec = ledger.distillation_record("dst-1", 6)
    assert rec.verify()
    assert ledger.distillations_for("pair-1", 6)[0] == rec
    # ids never recycled
    with pytest.raises(mod.RetiredPairError):
        ledger.distill("pair-1", 7, fidelity="faithful")
    assert ledger.stats(1)["n_distillations"] == 1


def test_retire_reasons_and_unknown(mod, ledger):
    with pytest.raises(mod.UnknownPairError):
        ledger.retire("ghost", 1)
    for reason in mod.RETIRE_REASONS:
        led = mod.AIDistillation()
        led.distill("pair-1", 1)
        ret = led.retire("pair-1", 2, reason=reason)
        assert ret.reason == reason
        assert ret.verify()


# 11. audit shapes + leak ban + pinned-data passthrough ----------------------------------


def test_audit_shapes_and_leak_ban(mod, ledger):
    digest = "sha256:" + "cd" * 32
    ledger.distill("pair-1", 1, distillation_kind="logit-matching", fidelity="faithful",
                   distillation_digest=digest)
    with pytest.raises(mod.BadKindError):
        ledger.distill("pair-x", 2, distillation_kind="bogus")
    ledger.retire("pair-1", 3)
    rows = ledger.audit_log(1)
    kinds = [r["kind"] for r in rows]
    assert kinds[0] == "distilled" and kinds[-1] == "retired"
    assert any(r["kind"] == "rejected" for r in rows)
    for r in rows:
        assert r["schema"] == "audit.ndjson/1"
        assert r["module"] == "ai-distillation"
        assert r["version"] == mod.AI_DISTILLATION_VERSION
    distilled = rows[0]
    assert distilled["details"]["distillation_kind"] == "logit-matching"  # pinned vocab emittable
    assert distilled["details"]["fidelity"] == "faithful"
    assert "distillation_digest" not in distilled["details"]
    # builder leak ban
    for key in ["teacher_weights", "student_weights", "logits", "soft_targets",
                "temperature", "distillation_loss", "training_data", "prompts",
                "teacher_output", "student_output"]:
        with pytest.raises(mod.AIDistillationError):
            mod.ai_distillation_audit_event("distilled", 1, **{key: "raw"})
    with pytest.raises(mod.AuditKindError):
        mod.ai_distillation_audit_event("bogus", 1)


# 12. views / stats / unknown lookups ----------------------------------------------------


def test_views_stats_unknown(mod, ledger):
    assert ledger.pair_ids(1) == ()
    assert ledger.distillation_ids(1) == ()
    assert ledger.retired_ids(1) == ()
    assert ledger.stats(1)["n_pairs"] == 0
    with pytest.raises(mod.UnknownDistillationError):
        ledger.distillation_record("dst-1", 1)
    ledger.distill("pair-b", 1)
    ledger.distill("pair-a", 2)
    assert ledger.pair_ids(1) == ("pair-a", "pair-b")
    assert ledger.distillation_ids(1) == ("dst-1", "dst-2")
    assert len(ledger.distillations_for("pair-a", 1)) == 1
    assert ledger.distillations_for("unknown", 1) == ()
    assert ledger.stats(1)["n_pairs"] == 2
    assert ledger.stats(1)["n_distillations"] == 2


# 13. cross-instance determinism + tamper + thread smoke -----------------------------------


def test_determinism_and_thread_smoke(mod):
    l1, l2 = mod.AIDistillation(), mod.AIDistillation()
    d = "sha256:" + "ef" * 32
    r1 = l1.distill("pair-1", 1, distillation_kind="attention-transfer", fidelity="faithful",
                    distillation_digest=d)
    r2 = l2.distill("pair-1", 1, distillation_kind="attention-transfer", fidelity="faithful",
                    distillation_digest=d)
    assert r1.digest == r2.digest
    e1 = l1.evaluate("pair-1", 2)
    e2 = l2.evaluate("pair-1", 2)
    assert e1.digest == e2.digest
    r3 = l1.distill("pair-2", 2, distillation_kind="attention-transfer", fidelity="faithful",
                    distillation_digest=d)
    assert r3.digest != r1.digest  # different payload -> different pin
    # 8-thread read smoke
    ledger = mod.AIDistillation()
    ledger.distill("pair-1", 1, fidelity="faithful")
    errors = []

    def read():
        try:
            for _ in range(50):
                ledger.evaluate("pair-1", 0)
                ledger.verify("dst-1", 0)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=read) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors


# 14. main() subprocess -------------------------------------------------------------------


def test_main_subprocess():
    import subprocess

    out = subprocess.run(
        [sys.executable, str(_MOD_PATH)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert out.returncode == 0, out.stderr
    assert "ai-distillation OK" in out.stdout
