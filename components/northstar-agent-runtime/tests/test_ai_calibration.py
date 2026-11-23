"""Tests for ai_calibration.py - AI calibration-method declaration decision ledger."""

import importlib.util
import sys
import threading
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

_MOD_PATH = Path(__file__).resolve().parent.parent / "ai_calibration.py"


def _load():
    spec = importlib.util.spec_from_file_location("ai_calibration", str(_MOD_PATH))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["ai_calibration"] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def mod():
    return _load()


@pytest.fixture()
def ledger(mod):
    return mod.AICalibration()


# 1. pins / vocabularies -------------------------------------------------------


def test_pins_and_vocabularies(mod):
    assert mod.AI_CALIBRATION_VERSION == "ai-calibration.v1"
    assert mod.SCHEMA_PIN == "northstar.ai-calibration.v1"
    assert mod.CALIBRATION_METHODS == (
        "temperature-scaling",
        "platt-scaling",
        "isotonic-regression",
        "histogram-binning",
        "beta-calibration",
        "dirichlet-calibration",
        "bayesian-binning",
        "ensemble-calibration",
    )
    assert mod.VERDICTS == (
        "calibrated",
        "partial",
        "miscalibrated",
        "inconclusive",
        "not-calibrated",
    )
    assert mod.VERIFY_VERDICTS == ("verified", "tampered")
    assert mod.POSTURES == (
        "uncalibrated",
        "miscalibrated",
        "contested",
        "partial",
        "calibrated",
    )
    assert mod.RETIRE_REASONS == ("manual", "superseded", "decommissioned", "false-start")
    assert mod.AUDIT_KINDS == ("calibrated", "retired", "rejected")


# 2. stdlib-only ---------------------------------------------------------------


def test_stdlib_only(mod):
    assert mod.stdlib_only() is True


# 3. calibrate roundtrip / defaults / frozen-ness ------------------------------


def test_calibrate_roundtrip_defaults_frozen(mod, ledger):
    rec = ledger.calibrate("m-1", 1)
    assert rec.calibration_id == "cal-1"
    assert rec.model_id == "m-1"
    assert rec.calibration_method == "temperature-scaling"
    assert rec.verdict == "not-calibrated"
    assert rec.calibration_error == 0
    assert rec.calibration_digest == ""
    assert rec.digest.startswith("sha256:")
    assert rec.verify() is True
    assert "m-1" in ledger.model_ids(0)
    with pytest.raises(FrozenInstanceError):
        rec.verdict = "calibrated"  # type: ignore


# 4. bad inputs burn seq, rewinds raise bare -----------------------------------


def test_bad_inputs_burn_seq_and_rewinds_bare(mod, ledger):
    bad_calls = [
        lambda: ledger.calibrate("", 1),  # bad model_id
        lambda: ledger.calibrate("m-1", 2, calibration_method="nope"),  # bad method
        lambda: ledger.calibrate("m-1", 3, verdict="nope"),  # bad verdict
        lambda: ledger.calibrate("m-1", 4, calibration_error=101),  # bad error high
        lambda: ledger.calibrate("m-1", 5, calibration_error=-1),  # bad error low
        lambda: ledger.calibrate("m-1", 6, calibration_error=True),  # bool refused
        lambda: ledger.calibrate("m-1", 7, calibration_digest="bogus"),  # bad digest
    ]
    for call in bad_calls:
        with pytest.raises(mod.AICalibrationError):
            call()
    rejected = [r for r in ledger.audit_log(0) if r["kind"] == "rejected"]
    assert len(rejected) == len(bad_calls)
    # every burn consumed its seq, so seq is now 7; rewinds raise bare, no row
    n_rows = len(ledger.audit_log(0))
    with pytest.raises(mod.SeqOrderError):
        ledger.calibrate("m-1", 7)
    with pytest.raises(mod.SeqOrderError):
        ledger.calibrate("m-1", 0)
    assert len(ledger.audit_log(0)) == n_rows
    # malformed seqs also raise bare without burning
    for bad in (True, 1.5, "8", None):
        with pytest.raises(mod.SeqOrderError):
            ledger.calibrate("m-1", bad)


# 5. full method vocabulary ----------------------------------------------------


def test_full_method_vocabulary(mod, ledger):
    seq = 1
    for i, method in enumerate(mod.CALIBRATION_METHODS):
        rec = ledger.calibrate(
            f"m-{i}", seq, calibration_method=method, verdict="calibrated"
        )
        assert rec.calibration_method == method
        seq += 1
    assert len(ledger.calibration_ids(0)) == len(mod.CALIBRATION_METHODS)


# 6. full verdict vocabulary + error bounds ------------------------------------


def test_full_verdict_vocabulary_and_error_bounds(mod, ledger):
    for i, verdict in enumerate(mod.VERDICTS):
        rec = ledger.calibrate("m-v", i + 1, verdict=verdict, calibration_error=i * 25)
        assert rec.verdict == verdict
    ev = ledger.evaluate("m-v", 6)
    assert ev.n_calibrations == len(mod.VERDICTS)
    assert ev.n_calibrated == 1
    assert ev.n_partial == 1
    assert ev.n_miscalibrated == 1
    assert ev.n_inconclusive == 1
    assert ev.n_not_calibrated == 1
    # 0 and 100 accepted as bounds
    assert ledger.calibrate("m-b", 7, calibration_error=0).calibration_error == 0
    assert ledger.calibrate("m-b", 8, calibration_error=100).calibration_error == 100


# 7. verify semantics ----------------------------------------------------------


def test_verify_semantics(mod, ledger):
    rec = ledger.calibrate("m-1", 1, verdict="calibrated")
    rep = ledger.verify(rec.calibration_id, 2)
    assert rep.verdict == "verified"
    assert rep.integrity_ok is True
    assert rep.verify() is True
    # tamper is reported as data, never raised
    object.__setattr__(rec, "verdict", "miscalibrated")
    rep2 = ledger.verify(rec.calibration_id, 3)
    assert rep2.verdict == "tampered"
    assert rep2.integrity_ok is False
    assert rep2.verify() is True
    # unknown record refuses
    with pytest.raises(mod.UnknownRecordError):
        ledger.verify("cal-999", 4)
    # verify is a pure read: seq is validated but not consumed
    rep3 = ledger.verify(rec.calibration_id, 3)
    assert rep3.verdict == "tampered"
    with pytest.raises(mod.SeqOrderError):
        ledger.verify(rec.calibration_id, -1)


# 8. evaluate posture math -----------------------------------------------------


def test_evaluate_posture_math(mod):
    seq = 0

    def fresh(**kw):
        led = mod.AICalibration()
        return led

    # all calibrated -> calibrated
    led = fresh()
    led.calibrate("a", 1, verdict="calibrated")
    led.calibrate("a", 2, verdict="calibrated")
    assert led.evaluate("a", 3).posture == "calibrated"

    # any miscalibrated outranks everything
    led = fresh()
    led.calibrate("b", 1, verdict="calibrated")
    led.calibrate("b", 2, verdict="miscalibrated")
    led.calibrate("b", 3, verdict="inconclusive")
    assert led.evaluate("b", 4).posture == "miscalibrated"

    # inconclusive (without miscalibrated) -> contested
    led = fresh()
    led.calibrate("c", 1, verdict="partial")
    led.calibrate("c", 2, verdict="inconclusive")
    assert led.evaluate("c", 3).posture == "contested"

    # partial or not-calibrated (without the above) -> partial
    led = fresh()
    led.calibrate("d", 1, verdict="not-calibrated")
    assert led.evaluate("d", 2).posture == "partial"
    led.calibrate("d", 3, verdict="partial")
    assert led.evaluate("d", 4).posture == "partial"

    # unknown model refuses
    with pytest.raises(mod.UnknownModelError):
        led.evaluate("nope", 5)


# 9. evaluate purity + integrity flip ------------------------------------------


def test_evaluate_purity_and_integrity(mod, ledger):
    rec = ledger.calibrate("m-1", 1, verdict="calibrated")
    ev1 = ledger.evaluate("m-1", 2)
    assert ev1.integrity_ok is True
    assert ev1.verify() is True
    # same read seq twice: no new audit rows, seq not consumed
    n_rows = len(ledger.audit_log(0))
    ev2 = ledger.evaluate("m-1", 2)
    assert ev2.posture == ev1.posture
    assert len(ledger.audit_log(0)) == n_rows
    # tamper flips integrity_ok as data
    object.__setattr__(rec, "calibration_error", 99)
    ev3 = ledger.evaluate("m-1", 3)
    assert ev3.integrity_ok is False
    assert ev3.verify() is True


# 10. retire terminality --------------------------------------------------------


def test_retire_terminality(mod, ledger):
    ledger.calibrate("m-1", 1, verdict="calibrated")
    ret = ledger.retire("m-1", 2)
    assert ret.model_id == "m-1"
    assert ret.reason == "manual"
    assert ret.verify() is True
    assert "m-1" in ledger.retired_ids(0)
    # post-retire mutations refused
    with pytest.raises(mod.RetiredModelError):
        ledger.calibrate("m-1", 3, verdict="calibrated")
    # double retire refused
    with pytest.raises(mod.RetiredModelError):
        ledger.retire("m-1", 4)
    # post-retire reads still work
    assert ledger.evaluate("m-1", 5).posture == "calibrated"
    assert len(ledger.calibrations_for("m-1", 5)) == 1
    # ids never recycled: new calibrations on another model keep minting
    ledger.calibrate("m-2", 6, verdict="calibrated")
    assert ledger.calibration_record("cal-2", 6).model_id == "m-2"


# 11. retire reasons / unknown --------------------------------------------------


def test_retire_reasons_and_unknown(mod, ledger):
    with pytest.raises(mod.UnknownModelError):
        ledger.retire("ghost", 1)
    with pytest.raises(mod.BadReasonError):
        ledger.calibrate("m-1", 2)
        ledger.retire("m-1", 3, reason="nope")
    for i, reason in enumerate(mod.RETIRE_REASONS):
        led = mod.AICalibration()
        led.calibrate(f"m-{i}", 1)
        ret = led.retire(f"m-{i}", 2, reason=reason)
        assert ret.reason == reason
        assert ret.verify() is True


# 12. audit shapes + leak ban --------------------------------------------------


def test_audit_shapes_and_leak_ban(mod, ledger):
    rec = ledger.calibrate("m-1", 1, verdict="calibrated", calibration_error=5)
    ledger.retire("m-1", 2)
    rows = ledger.audit_log(0)
    kinds = [r["kind"] for r in rows]
    assert kinds == ["calibrated", "retired"]
    row = rows[0]
    assert row["schema"] == "audit.ndjson/1"
    assert row["module"] == "ai-calibration"
    assert row["version"] == "ai-calibration.v1"
    assert row["seq"] == 1
    # pinned values and declared scalars remain emittable
    assert row["details"]["verdict"] == "calibrated"
    assert row["details"]["calibration_error"] == 5
    # raw calibration material banned at the audit boundary
    for banned in ("confidence_scores", "reliability_diagram", "temperature", "bins"):
        with pytest.raises(mod.AICalibrationError):
            mod.ai_calibration_audit_event("calibrated", 3, **{banned: "raw"})
    # bad audit kind fails closed
    with pytest.raises(mod.AuditKindError):
        mod.ai_calibration_audit_event("nope", 3)
    # rejected-row accounting
    with pytest.raises(mod.BadMethodError):
        ledger.calibrate("m-2", 3, calibration_method="nope")
    assert ledger.audit_log(0)[-1]["kind"] == "rejected"


# 13. views / stats / unknown lookups --------------------------------------------


def test_views_stats_unknown(mod, ledger):
    ledger.calibrate("m-1", 1, verdict="calibrated")
    ledger.calibrate("m-2", 2, verdict="partial")
    assert ledger.calibration_record("cal-1", 0).model_id == "m-1"
    with pytest.raises(mod.UnknownCalibrationError):
        ledger.calibration_record("cal-999", 0)
    assert [r.calibration_id for r in ledger.calibrations_for("m-1", 0)] == ["cal-1"]
    assert ledger.model_ids(0) == ("m-1", "m-2")
    assert ledger.calibration_ids(0) == ("cal-1", "cal-2")
    assert ledger.retired_ids(0) == ()
    stats = ledger.stats(0)
    assert stats["n_models"] == 2
    assert stats["n_calibrations"] == 2
    assert stats["n_retired"] == 0
    assert stats["n_audit_rows"] == 2
    assert stats["seq"] == 2


# 14. determinism + thread smoke -------------------------------------------------


def test_determinism_and_thread_smoke(mod):
    led_a, led_b = mod.AICalibration(), mod.AICalibration()
    kwargs = dict(
        calibration_method="isotonic-regression",
        verdict="calibrated",
        calibration_error=7,
    )
    ra = led_a.calibrate("m", 1, **kwargs)
    rb = led_b.calibrate("m", 1, **kwargs)
    assert ra.digest == rb.digest
    # tamper on one instance breaks verify() there only
    object.__setattr__(ra, "verdict", "partial")
    assert ra.verify() is False
    assert rb.verify() is True
    # 8-thread concurrent read smoke
    errors = []

    def read_many():
        try:
            for _ in range(50):
                led_b.evaluate("m", 2)
                led_b.verify("cal-1", 3)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=read_many) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    # records are frozen even under concurrency
    with pytest.raises(FrozenInstanceError):
        rb.verdict = "partial"  # type: ignore


# 15. main() subprocess self-check -------------------------------------------------


def test_main_subprocess():
    import subprocess

    proc = subprocess.run(
        [sys.executable, str(_MOD_PATH)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert "ai-calibration OK: calibrate, verify, evaluate, retire, pins, audit" in (
        proc.stdout
    )
