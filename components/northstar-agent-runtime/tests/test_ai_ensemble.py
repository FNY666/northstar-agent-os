"""Tests for ai_ensemble.py - AI ensemble-composition decision ledger."""

import importlib.util
import sys
import threading
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

_MOD_PATH = Path(__file__).resolve().parent.parent / "ai_ensemble.py"


def _load():
    spec = importlib.util.spec_from_file_location("ai_ensemble", str(_MOD_PATH))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["ai_ensemble"] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def mod():
    return _load()


@pytest.fixture()
def ledger(mod):
    return mod.AIEnsemble()


# 1. pins / vocabularies -------------------------------------------------------


def test_pins_and_vocabularies(mod):
    assert mod.AI_ENSEMBLE_VERSION == "ai-ensemble.v1"
    assert mod.SCHEMA_PIN == "northstar.ai-ensemble.v1"
    assert mod.ENSEMBLE_STRATEGIES == (
        "majority-vote",
        "weighted-vote",
        "stacking",
        "boosting",
        "bagging",
        "mixture-of-experts",
        "snapshot-ensemble",
        "bayesian-average",
    )
    assert mod.AGREEMENTS == (
        "unanimous",
        "majority",
        "plurality",
        "split",
        "not-assessed",
    )
    assert mod.VERIFY_VERDICTS == ("verified", "tampered")
    assert mod.POSTURES == (
        "unassembled",
        "divided",
        "contested",
        "plural",
        "consensus",
    )
    assert set(mod.AUDIT_KINDS) == {"ensembled", "retired", "rejected"}


# 2. stdlib-only ----------------------------------------------------------------


def test_stdlib_only(mod):
    assert mod.stdlib_only()


# 3. ensemble roundtrip / defaults / minting / frozen-ness ------------------------


def test_ensemble_roundtrip_defaults_frozen(mod, ledger):
    digest = "sha256:" + "ab" * 32
    rec = ledger.ensemble(
        "sys-1", 1, ensemble_strategy="stacking", agreement="unanimous",
        ensemble_digest=digest,
    )
    assert rec.ensemble_id == "ens-1"
    assert rec.system_id == "sys-1"
    assert rec.ensemble_strategy == "stacking"
    assert rec.agreement == "unanimous"
    assert rec.ensemble_digest == digest
    assert rec.verify()
    rec2 = ledger.ensemble("sys-1", 2)
    assert rec2.ensemble_id == "ens-2"
    assert rec2.ensemble_strategy == "majority-vote"  # default strategy
    assert rec2.agreement == "not-assessed"           # default agreement
    assert rec2.ensemble_digest == ""                # default digest
    assert rec2.verify()
    with pytest.raises(FrozenInstanceError):
        rec.ensemble_strategy = "bagging"  # type: ignore


# 4. bad inputs + seq-burn + rejected rows + rewinds bare -------------------------


def test_bad_inputs_burn_seq_and_rewinds_bare(mod, ledger):
    bad = [
        ("", "majority-vote", "unanimous", ""),            # empty system id
        (123, "majority-vote", "unanimous", ""),           # bad id type
        (True, "majority-vote", "unanimous", ""),          # bool id
        ("sys-1", "bogus-strategy", "unanimous", ""),      # bad strategy
        ("sys-1", "majority-vote", "bogus", ""),           # bad agreement
        ("sys-1", "majority-vote", "unanimous", "nope"),   # bad digest
        ("sys-1", "majority-vote", "unanimous", "sha256:zz"),  # bad digest hex
    ]
    seq = 0
    for system_id, strategy, agreement, d in bad:
        seq += 1
        with pytest.raises(mod.AIEnsembleError):
            ledger.ensemble(system_id, seq, strategy, agreement, d)
    rows = ledger.audit_log(1)
    rejected_rows = [r for r in rows if r["kind"] == "rejected"]
    assert len(rejected_rows) == len(bad)
    assert ledger.stats(1)["n_ensembles"] == 0
    # failed mutations consumed their seqs: next valid claim must be seq+1
    rec = ledger.ensemble("sys-1", seq + 1, agreement="unanimous")
    assert rec.ensemble_id == "ens-1"
    # rewinds raise bare with zero new rows
    n_rows = len(ledger.audit_log(1))
    with pytest.raises(mod.SeqOrderError):
        ledger.ensemble("sys-1", seq + 1)
    with pytest.raises(mod.SeqOrderError):
        ledger.ensemble("sys-1", 0)
    assert len(ledger.audit_log(1)) == n_rows
    # malformed seq types raise bare with zero rows
    for bad_seq in ("1", 1.5, True, None):
        with pytest.raises(mod.SeqOrderError):
            ledger.ensemble("sys-1", bad_seq)
    assert len(ledger.audit_log(1)) == n_rows


# 5. full 8-strategy vocabulary ----------------------------------------------------


def test_full_strategy_vocabulary(mod, ledger):
    seq = 0
    for strategy in mod.ENSEMBLE_STRATEGIES:
        seq += 1
        rec = ledger.ensemble(f"sys-{seq}", seq, ensemble_strategy=strategy)
        assert rec.verify()
        assert rec.ensemble_strategy == strategy
    assert ledger.stats(1)["n_ensembles"] == 8


# 6. full 5-agreement vocabulary + tallies ----------------------------------------


def test_full_agreement_vocabulary_and_tallies(mod, ledger):
    seq = 0
    for agreement in mod.AGREEMENTS:
        seq += 1
        rec = ledger.ensemble("sys-1", seq, agreement=agreement)
        assert rec.verify()
    ev = ledger.evaluate("sys-1", seq + 1)
    assert ev.n_ensembles == 5
    assert ev.n_unanimous == 1
    assert ev.n_majority == 1
    assert ev.n_plurality == 1
    assert ev.n_split == 1
    assert ev.n_not_assessed == 1
    assert ev.verify()


# 7. verify semantics: verified / tamper-as-data / read purity / unknown --------


def test_verify_semantics(mod, ledger):
    rec = ledger.ensemble("sys-1", 1, ensemble_strategy="bagging", agreement="majority")
    rep = ledger.verify(rec.ensemble_id, 2)
    assert rep.verdict == "verified"
    assert rep.integrity_ok
    assert rep.verify()
    with pytest.raises(mod.UnknownRecordError):
        ledger.verify("ens-999", 3)
    # read purity: same-seq-twice, no audit rows, seq never consumed
    n_rows = len(ledger.audit_log(1))
    ledger.verify(rec.ensemble_id, 2)
    ledger.verify(rec.ensemble_id, 2)
    assert len(ledger.audit_log(1)) == n_rows
    # tamper reported as data, never raised
    object.__setattr__(rec, "agreement", "split")
    assert not rec.verify()
    rep2 = ledger.verify(rec.ensemble_id, 2)
    assert rep2.verdict == "tampered"
    assert not rep2.integrity_ok


# 8. evaluate posture math: all postures + precedence ------------------------------


def test_evaluate_posture_math(mod):
    cases = [
        ([("unanimous",)], "consensus"),
        ([("unanimous",), ("majority",)], "consensus"),
        ([("majority",)], "consensus"),
        ([("plurality",)], "plural"),
        ([("unanimous",), ("plurality",)], "plural"),
        ([("not-assessed",)], "contested"),
        ([("unanimous",), ("not-assessed",)], "contested"),
        ([("plurality",), ("not-assessed",)], "contested"),
        ([("split",)], "divided"),
        ([("unanimous",), ("split",)], "divided"),
        ([("not-assessed",), ("split",)], "divided"),
        ([("plurality",), ("split",)], "divided"),
    ]
    for idx, (agreements, posture) in enumerate(cases):
        mod2 = _load()
        led = mod2.AIEnsemble()
        seq = 0
        for (agreement,) in agreements:
            seq += 1
            led.ensemble("sys-x", seq, agreement=agreement)
        ev = led.evaluate("sys-x", seq + 1)
        assert ev.posture == posture, f"case {idx}: {agreements}"
        assert ev.verify()


# 9. evaluate purity + integrity flip + unknown ------------------------------------


def test_evaluate_purity_and_integrity(mod, ledger):
    rec = ledger.ensemble("sys-1", 1, agreement="unanimous")
    n_rows = len(ledger.audit_log(1))
    ev1 = ledger.evaluate("sys-1", 2)
    ev2 = ledger.evaluate("sys-1", 2)
    assert ev1.posture == "consensus"
    assert ev1.integrity_ok
    assert len(ledger.audit_log(1)) == n_rows
    assert ev1.verify()
    # tamper flips integrity_ok as data
    object.__setattr__(rec, "agreement", "split")
    ev3 = ledger.evaluate("sys-1", 2)
    assert not ev3.integrity_ok
    assert ev3.posture == "divided"
    with pytest.raises(mod.UnknownSystemError):
        ledger.evaluate("nope", 3)


# 10. retire terminality ------------------------------------------------------------


def test_retire_terminality(mod, ledger):
    rec = ledger.ensemble("sys-1", 1, agreement="majority")
    assert rec.verify()
    ret = ledger.retire("sys-1", 2)
    assert ret.verify()
    assert ret.system_id == "sys-1"
    assert ret.reason == "manual"
    # ids never recycled; post-retire mutations refused, reads still work
    with pytest.raises(mod.RetiredSystemError):
        ledger.ensemble("sys-1", 3)
    with pytest.raises(mod.RetiredSystemError):
        ledger.retire("sys-1", 4)
    ev = ledger.evaluate("sys-1", 5)
    assert ev.posture == "consensus"
    rep = ledger.verify(rec.ensemble_id, 6)
    assert rep.verdict == "verified"
    # rejected rows burned seqs but no new ensemble rows
    assert ledger.stats(1)["n_ensembles"] == 1
    assert "sys-1" in ledger.retired_ids(1)


# 11. retire reasons + unknown system -------------------------------------------------


def test_retire_reasons_and_unknown(mod):
    for reason in ("superseded", "decommissioned", "false-start"):
        mod2 = _load()
        led = mod2.AIEnsemble()
        led.ensemble("sys-1", 1)
        ret = led.retire("sys-1", 2, reason=reason)
        assert ret.reason == reason
        assert ret.verify()
    mod3 = _load()
    led3 = mod3.AIEnsemble()
    with pytest.raises(mod3.UnknownSystemError):
        led3.retire("ghost", 1)
    with pytest.raises(mod3.BadReasonError):
        led3.ensemble("sys-9", 2)
        led3.retire("sys-9", 3, reason="bogus")


# 12. audit shapes + leak ban -----------------------------------------------------------


def test_audit_shapes_and_leak_ban(mod, ledger):
    rec = ledger.ensemble("sys-1", 1, ensemble_strategy="stacking", agreement="unanimous")
    rows = ledger.audit_log(1)
    kinds = [r["kind"] for r in rows]
    assert kinds == ["ensembled"]
    row = rows[0]
    assert row["schema"] == "audit.ndjson/1"
    assert row["module"] == "ai-ensemble"
    assert row["version"] == "ai-ensemble.v1"
    assert row["seq"] == 1
    assert row["details"]["ensemble_id"] == rec.ensemble_id
    assert row["details"]["ensemble_strategy"] == "stacking"
    assert row["details"]["agreement"] == "unanimous"
    # banned raw keys raise at the audit builder boundary
    for banned in (
        "member_outputs", "votes", "vote_tally", "member_weights",
        "predictions", "logits", "confidences", "prompt", "weights",
        "ensemble_output", "payload", "password", "api_key",
    ):
        with pytest.raises(mod.AIEnsembleError):
            mod.ai_ensemble_audit_event("ensembled", 2, **{banned: "raw"})
    with pytest.raises(mod.AuditKindError):
        mod.ai_ensemble_audit_event("bogus", 2)
    # pinned vocab values and digest pins remain emittable
    ok = mod.ai_ensemble_audit_event(
        "ensembled", 2, ensemble_strategy="boosting", agreement="split",
        ensemble_digest="sha256:" + "cd" * 32,
    )
    assert ok["details"]["agreement"] == "split"


# 13. views / stats / unknown lookups -----------------------------------------------------


def test_views_stats_unknown(mod, ledger):
    r1 = ledger.ensemble("sys-a", 1, agreement="unanimous")
    r2 = ledger.ensemble("sys-b", 2, agreement="split")
    assert ledger.ensemble_record(r1.ensemble_id, 3) == r1
    assert ledger.ensemble_record(r2.ensemble_id, 3) == r2
    with pytest.raises(mod.UnknownEnsembleError):
        ledger.ensemble_record("ens-999", 3)
    assert ledger.ensembles_for("sys-a", 3) == (r1,)
    assert ledger.ensembles_for("ghost", 3) == ()
    assert ledger.system_ids(3) == ("sys-a", "sys-b")
    assert sorted(ledger.ensemble_ids(3)) == sorted(("ens-1", "ens-2"))
    assert ledger.retired_ids(3) == ()
    st = ledger.stats(3)
    assert st["n_systems"] == 2
    assert st["n_ensembles"] == 2
    assert st["n_retired"] == 0
    assert st["n_audit_rows"] == 2
    ledger.retire("sys-a", 4)
    assert ledger.retired_ids(5) == ("sys-a",)
    assert ledger.stats(5)["n_retired"] == 1


# 14. determinism + thread smoke ------------------------------------------------------------


def test_determinism_and_thread_smoke(mod):
    mod_a = _load()
    mod_b = _load()
    led_a = mod_a.AIEnsemble()
    led_b = mod_b.AIEnsemble()
    for i in range(1, 6):
        rec_a = led_a.ensemble("sys-1", i, ensemble_strategy="bagging", agreement="majority")
        rec_b = led_b.ensemble("sys-1", i, ensemble_strategy="bagging", agreement="majority")
        assert rec_a.digest == rec_b.digest
    # concurrent reads race-free
    led = mod.AIEnsemble()
    led.ensemble("sys-1", 1, agreement="unanimous")
    errors = []

    def reader():
        try:
            for _ in range(50):
                led.evaluate("sys-1", 2)
                led.verify("ens-1", 2)
                led.stats(2)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    ev = led.evaluate("sys-1", 2)
    assert ev.posture == "consensus"


# 15. main() subprocess self-check ------------------------------------------------------------


def test_main_subprocess():
    import subprocess

    proc = subprocess.run(
        [sys.executable, str(_MOD_PATH)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert "ai-ensemble OK: ensemble, verify, evaluate, retire, pins, audit" in proc.stdout
