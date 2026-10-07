"""Tests for ai_uncertainty.py - AI uncertainty-quantification decision ledger."""

import importlib.util
import sys
import threading
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

_MOD_PATH = Path(__file__).resolve().parent.parent / "ai_uncertainty.py"


def _load():
    spec = importlib.util.spec_from_file_location("ai_uncertainty", str(_MOD_PATH))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["ai_uncertainty"] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def mod():
    return _load()


@pytest.fixture()
def ledger(mod):
    return mod.AIUncertainty()


# 1. pins / vocabularies -------------------------------------------------------


def test_pins_and_vocabularies(mod):
    assert mod.AI_UNCERTAINTY_VERSION == "ai-uncertainty.v1"
    assert mod.SCHEMA_PIN == "northstar.ai-uncertainty.v1"
    assert mod.UNCERTAINTY_KINDS == (
        "epistemic",
        "aleatoric",
        "predictive",
        "calibration-error",
        "conformal",
        "ensemble-spread",
        "dropout-mc",
        "ood-uncertainty",
    )
    assert mod.VERDICTS == (
        "well-calibrated",
        "overconfident",
        "underconfident",
        "miscalibrated",
        "not-assessed",
    )
    assert mod.VERIFY_VERDICTS == ("verified", "tampered")
    assert mod.POSTURES == (
        "unexamined",
        "miscalibrated",
        "contested",
        "partially-calibrated",
        "calibrated",
    )
    assert set(mod.AUDIT_KINDS) == {"quantified", "retired", "rejected"}


# 2. stdlib-only ----------------------------------------------------------------


def test_stdlib_only(mod):
    assert mod.stdlib_only()


# 3. quantify roundtrip / defaults / minting / frozen-ness ------------------------


def test_quantify_roundtrip_defaults_frozen(mod, ledger):
    digest = "sha256:" + "ab" * 32
    rec = ledger.quantify(
        "sub-1", 1, uncertainty_kind="conformal", verdict="well-calibrated",
        score=92, uncertainty_digest=digest,
    )
    assert rec.uncertainty_id == "unc-1"
    assert rec.subject_id == "sub-1"
    assert rec.uncertainty_kind == "conformal"
    assert rec.verdict == "well-calibrated"
    assert rec.score == 92
    assert rec.uncertainty_digest == digest
    assert rec.verify()
    rec2 = ledger.quantify("sub-1", 2)
    assert rec2.uncertainty_id == "unc-2"
    assert rec2.uncertainty_kind == "epistemic"   # default kind
    assert rec2.verdict == "not-assessed"        # default verdict
    assert rec2.score == 0                       # default score
    assert rec2.uncertainty_digest == ""         # default digest
    assert rec2.verify()
    with pytest.raises(FrozenInstanceError):
        rec.verdict = "miscalibrated"  # type: ignore


# 4. bad inputs + seq-burn + rejected rows + rewinds bare -------------------------


def test_bad_inputs_burn_seq_and_rewinds_bare(mod, ledger):
    bad = [
        ("", "epistemic", "well-calibrated", 50, ""),            # empty subject id
        (123, "epistemic", "well-calibrated", 50, ""),           # bad id type
        (True, "epistemic", "well-calibrated", 50, ""),          # bool id
        ("sub-1", "bogus-kind", "well-calibrated", 50, ""),      # bad kind
        ("sub-1", "epistemic", "bogus", 50, ""),                 # bad verdict
        ("sub-1", "epistemic", "well-calibrated", -1, ""),       # score < 0
        ("sub-1", "epistemic", "well-calibrated", 101, ""),      # score > 100
        ("sub-1", "epistemic", "well-calibrated", True, ""),     # bool score
        ("sub-1", "epistemic", "well-calibrated", 50, "nope"),   # bad digest
        ("sub-1", "epistemic", "well-calibrated", 50, "sha256:zz"),  # bad hex
    ]
    seq = 0
    for subject_id, kind, verdict, score, d in bad:
        seq += 1
        with pytest.raises(mod.AIUncertaintyError):
            ledger.quantify(subject_id, seq, kind, verdict, score, d)
    rows = ledger.audit_log(1)
    rejected_rows = [r for r in rows if r["kind"] == "rejected"]
    assert len(rejected_rows) == len(bad)
    assert ledger.stats(1)["n_uncertainties"] == 0
    # failed mutations consumed their seqs: next valid claim must be seq+1
    rec = ledger.quantify("sub-1", seq + 1)
    assert rec.uncertainty_id == "unc-1"
    # rewinds raise bare with zero new rows
    n_rows = len(ledger.audit_log(1))
    with pytest.raises(mod.SeqOrderError):
        ledger.quantify("sub-1", 1)
    assert len(ledger.audit_log(1)) == n_rows


# 5. full 8-kind vocabulary --------------------------------------------------------


def test_full_kind_vocabulary(mod, ledger):
    seq = 0
    for kind in mod.UNCERTAINTY_KINDS:
        seq += 1
        rec = ledger.quantify(f"sub-{kind}", seq, uncertainty_kind=kind)
        assert rec.uncertainty_kind == kind
        assert rec.verify()
    assert ledger.stats(1)["n_uncertainties"] == len(mod.UNCERTAINTY_KINDS)


# 6. full 5-verdict vocabulary + score bounds ----------------------------------------


def test_full_verdict_vocabulary_and_score_bounds(mod, ledger):
    seq = 0
    for verdict in mod.VERDICTS:
        seq += 1
        rec = ledger.quantify("sub-1", seq, verdict=verdict, score=100)
        assert rec.verdict == verdict
    for edge in (0, 100):
        seq += 1
        rec = ledger.quantify("sub-edge", seq, score=edge)
        assert rec.score == edge
        assert rec.verify()
    for bad_score in (-1, 101, True, 1.5, "50"):
        seq += 1
        with pytest.raises(mod.BadScoreError):
            ledger.quantify("sub-bad", seq, score=bad_score)


# 7. verify semantics + tamper-as-data + unknown refusal + read purity ---------------


def test_verify_semantics_tamper_purity(mod, ledger):
    rec = ledger.quantify("sub-1", 1)
    rep = ledger.verify(rec.uncertainty_id, 0)
    assert rep.verdict == "verified"
    assert rep.integrity_ok is True
    assert rep.verify()
    # tamper is reported as data, never raised
    object.__setattr__(rec, "verdict", "miscalibrated")
    rep2 = ledger.verify(rec.uncertainty_id, 1)
    assert rep2.verdict == "tampered"
    assert rep2.integrity_ok is False
    # unknown id refused (fail-closed)
    with pytest.raises(mod.UnknownRecordError):
        ledger.verify("unc-999", 2)
    # read purity: same-seq twice, no audit rows
    n_rows = len(ledger.audit_log(2))
    r1 = ledger.verify("unc-1", 3)
    r2 = ledger.verify("unc-1", 3)
    assert r1.verdict == r2.verdict == "tampered"
    assert len(ledger.audit_log(3)) == n_rows
    # malformed read seq
    with pytest.raises(mod.SeqOrderError):
        ledger.verify("unc-1", -1)


# 8. evaluate posture math ------------------------------------------------------------


def test_evaluate_posture_math(mod):
    # miscalibrated outranks everything
    led = mod.AIUncertainty()
    led.quantify("s", 1, verdict="well-calibrated")
    led.quantify("s", 2, verdict="miscalibrated")
    led.quantify("s", 3, verdict="overconfident")
    ev = led.evaluate("s", 4)
    assert ev.posture == "miscalibrated"
    assert ev.n_quantifications == 3
    assert ev.n_miscalibrated == 1
    assert ev.integrity_ok is True
    assert ev.verify()
    # contested: overconfident / underconfident
    led2 = mod.AIUncertainty()
    led2.quantify("s", 1, verdict="overconfident")
    led2.quantify("s", 2, verdict="underconfident")
    assert led2.evaluate("s", 3).posture == "contested"
    # partially-calibrated: any not-assessed
    led3 = mod.AIUncertainty()
    led3.quantify("s", 1, verdict="well-calibrated")
    led3.quantify("s", 2, verdict="not-assessed")
    ev3 = led3.evaluate("s", 3)
    assert ev3.posture == "partially-calibrated"
    assert ev3.n_well_calibrated == 1
    assert ev3.n_not_assessed == 1
    # calibrated: all well-calibrated
    led4 = mod.AIUncertainty()
    led4.quantify("s", 1, verdict="well-calibrated")
    led4.quantify("s", 2, uncertainty_kind="conformal", verdict="well-calibrated")
    assert led4.evaluate("s", 3).posture == "calibrated"
    # unknown subject refused
    with pytest.raises(mod.UnknownSubjectError):
        led4.evaluate("nope", 4)


# 9. evaluate read purity + tamper flips integrity --------------------------------------


def test_evaluate_purity_and_integrity(mod, ledger):
    rec = ledger.quantify("sub-1", 1, verdict="well-calibrated")
    n_rows = len(ledger.audit_log(1))
    e1 = ledger.evaluate("sub-1", 2)
    e2 = ledger.evaluate("sub-1", 2)
    assert e1.posture == e2.posture == "calibrated"
    assert e1.integrity_ok is True
    assert len(ledger.audit_log(2)) == n_rows
    object.__setattr__(rec, "score", 1)
    e3 = ledger.evaluate("sub-1", 3)
    assert e3.posture == "calibrated"      # posture unchanged as data
    assert e3.integrity_ok is False        # integrity flips as data


# 10. retire terminality -----------------------------------------------------------------


def test_retire_terminality(mod, ledger):
    ledger.quantify("sub-1", 1)
    with pytest.raises(mod.BadReasonError):
        ledger.retire("sub-1", 2, reason="bogus")
    ret = ledger.retire("sub-1", 3, reason="superseded")
    assert ret.subject_id == "sub-1"
    assert ret.reason == "superseded"
    assert ret.verify()
    # double-retire refused
    with pytest.raises(mod.RetiredSubjectError):
        ledger.retire("sub-1", 4)
    # ids never recycled: post-retire mutations refused, reads still work
    with pytest.raises(mod.RetiredSubjectError):
        ledger.quantify("sub-1", 5)
    assert ledger.evaluate("sub-1", 6).posture == "partially-calibrated"
    assert ledger.uncertainties_for("sub-1", 7)[0].uncertainty_id == "unc-1"
    # unknown subject retire refused
    with pytest.raises(mod.UnknownSubjectError):
        ledger.retire("ghost", 8)
    # all four reasons accepted on fresh subjects
    for i, reason in enumerate(mod.RETIRE_REASONS):
        sid = f"sub-r{i}"
        ledger.quantify(sid, 9 + i * 2)
        r = ledger.retire(sid, 10 + i * 2, reason=reason)
        assert r.reason == reason
    assert ledger.retired_ids(99) == tuple(
        sorted(["sub-1"] + [f"sub-r{i}" for i in range(4)])
    )


# 11. seq discipline -----------------------------------------------------------------------


def test_seq_discipline(mod, ledger):
    # genesis rewind (seq=0) raises bare with zero rows
    with pytest.raises(mod.SeqOrderError):
        ledger.quantify("sub-1", 0)
    assert len(ledger.audit_log(1)) == 0
    # malformed seqs
    for bad_seq in (True, 1.5, "2", None):
        with pytest.raises(mod.SeqOrderError):
            ledger.quantify("sub-1", bad_seq)
    assert len(ledger.audit_log(1)) == 0
    # failed mutation consumes seq; gap seqs allowed
    with pytest.raises(mod.BadKindError):
        ledger.quantify("sub-1", 3, uncertainty_kind="bogus")
    rec = ledger.quantify("sub-1", 10)   # gap is fine
    assert rec.uncertainty_id == "unc-1"
    # rewind raises bare
    n_rows = len(ledger.audit_log(11))
    with pytest.raises(mod.SeqOrderError):
        ledger.quantify("sub-1", 5)
    assert len(ledger.audit_log(11)) == n_rows


# 12. audit shapes + leak ban + bad-kind ----------------------------------------------------


def test_audit_shapes_leak_ban_bad_kind(mod, ledger):
    rec = ledger.quantify("sub-1", 1, uncertainty_kind="ensemble-spread",
                          verdict="overconfident", score=77)
    rows = ledger.audit_log(1)
    q = [r for r in rows if r["kind"] == "quantified"][0]
    assert q["schema"] == "audit.ndjson/1"
    assert q["module"] == "ai-uncertainty"
    assert q["version"] == "ai-uncertainty.v1"
    assert q["seq"] == 1
    assert q["details"]["uncertainty_id"] == "unc-1"
    # pinned vocab + declared scalar score remain emittable
    assert q["details"]["verdict"] == "overconfident"
    assert q["details"]["score"] == 77
    # raw material banned at the audit boundary
    for banned in ("probabilities", "model_outputs", "samples", "password",
                   "ensemble_predictions", "calibration_data"):
        with pytest.raises(mod.AIUncertaintyError):
            mod.ai_uncertainty_audit_event("quantified", 2, **{banned: "x"})
    # bad audit kind
    with pytest.raises(mod.AuditKindError):
        mod.ai_uncertainty_audit_event("bogus", 3)
    # bad audit seq
    with pytest.raises(mod.SeqOrderError):
        mod.ai_uncertainty_audit_event("quantified", True)


# 13. views / stats / unknown lookups -----------------------------------------------------------


def test_views_stats_unknown_lookups(mod, ledger):
    ledger.quantify("sub-a", 1, uncertainty_kind="conformal")
    ledger.quantify("sub-a", 2, uncertainty_kind="dropout-mc")
    ledger.quantify("sub-b", 3, uncertainty_kind="aleatoric")
    assert ledger.subject_ids(4) == ("sub-a", "sub-b")
    assert ledger.uncertainty_ids(5) == ("unc-1", "unc-2", "unc-3")
    assert [r.uncertainty_id for r in ledger.uncertainties_for("sub-a", 6)] == [
        "unc-1", "unc-2"
    ]
    assert ledger.uncertainties_for("ghost", 7) == ()
    st = ledger.stats(8)
    assert st["seq"] == 3
    assert st["n_subjects"] == 2
    assert st["n_uncertainties"] == 3
    assert st["n_retired"] == 0
    assert st["n_audit_rows"] == 3
    rec = ledger.uncertainty_record("unc-1", 9)
    assert rec.subject_id == "sub-a"
    with pytest.raises(mod.UnknownUncertaintyError):
        ledger.uncertainty_record("unc-999", 10)
    with pytest.raises(mod.UnknownRecordError):
        ledger.verify("unc-999", 11)


# 14. cross-instance determinism + thread smoke + frozen-ness -------------------------------------


def test_cross_instance_determinism_threads_frozen(mod):
    a, b = mod.AIUncertainty(), mod.AIUncertainty()
    ra = a.quantify("s", 1, uncertainty_kind="ood-uncertainty",
                    verdict="well-calibrated", score=88)
    rb = b.quantify("s", 1, uncertainty_kind="ood-uncertainty",
                    verdict="well-calibrated", score=88)
    assert ra.digest == rb.digest
    # frozen records
    with pytest.raises(FrozenInstanceError):
        ra.score = 0  # type: ignore
    with pytest.raises(FrozenInstanceError):
        a.evaluate("s", 2).posture = "x"  # type: ignore
    # 8-thread concurrent read smoke
    errs = []

    def _read():
        try:
            for _ in range(50):
                a.verify("unc-1", 0)
                a.evaluate("s", 0)
        except Exception as exc:  # pragma: no cover
            errs.append(exc)

    threads = [threading.Thread(target=_read) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errs


# 15. main() subprocess self-check ---------------------------------------------------------------


def test_main_subprocess(mod):
    import subprocess

    out = subprocess.run(
        [sys.executable, str(_MOD_PATH)], capture_output=True, text=True,
        timeout=60,
    )
    assert out.returncode == 0, out.stderr
    assert "ai-uncertainty OK: quantify, verify, evaluate, retire, pins, audit" in out.stdout
