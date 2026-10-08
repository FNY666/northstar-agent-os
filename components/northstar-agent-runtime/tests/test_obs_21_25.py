"""Tests for obs_21..obs_25."""
import importlib.util, sys
from pathlib import Path
import pytest
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
o21 = _load("obs_21"); o22 = _load("obs_22"); o23 = _load("obs_23")
o24 = _load("obs_24"); o25 = _load("obs_25")

# ---- obs_21: SLO definitions ----
def test_o21_evaluate_met():
    slo = o21.SLO("api", "success fraction", 0.999, 30.0)
    out = o21.evaluate(slo, 9990, 10000)
    assert out["sli"] == 0.999 and out["met"] is True
    assert abs(out["gap"]) < 1e-12 and out["target"] == 0.999
def test_o21_evaluate_missed():
    slo = o21.SLO("api", "success fraction", 0.999, 30.0)
    out = o21.evaluate(slo, 995, 1000)
    assert out["met"] is False and out["gap"] < 0.0
def test_o21_bad_target():
    with pytest.raises(o21.Obs21Error): o21.SLO("a", "b", 1.0, 30.0)
    with pytest.raises(o21.Obs21Error): o21.SLO("a", "b", 0.0, 30.0)
def test_o21_good_gt_total():
    slo = o21.SLO("api", "success fraction", 0.99, 7.0)
    with pytest.raises(o21.Obs21Error): o21.evaluate(slo, 101, 100)
def test_o21_stdlib(): assert o21.stdlib_only()
def test_o21_version(): assert o21.OBS21_VERSION == "obs-21.v1"

# ---- obs_22: Error budgets ----
def test_o22_allowed():
    eb = o22.ErrorBudget(0.999, 30.0)
    assert abs(eb.allowed_bad_events(10000) - 10.0) < 1e-9
def test_o22_consume_remaining():
    eb = o22.ErrorBudget(0.999, 30.0)
    assert eb.consume(4) == 4
    st = eb.remaining(10000, 4)
    assert st["consumed"] == 4 and abs(st["remaining"] - 6.0) < 1e-9
    assert abs(st["pct_remaining"] - 60.0) < 1e-9 and st["exhausted"] is False
def test_o22_exhausted():
    eb = o22.ErrorBudget(0.99, 30.0)
    st = eb.remaining(1000, 15)
    assert st["exhausted"] is True and st["remaining"] < 0.0
def test_o22_bad_gt_total():
    eb = o22.ErrorBudget(0.99, 30.0)
    with pytest.raises(o22.Obs22Error): eb.remaining(100, 101)
def test_o22_stdlib(): assert o22.stdlib_only()
def test_o22_version(): assert o22.OBS22_VERSION == "obs-22.v1"

# ---- obs_23: Burn rate alerts ----
def test_o23_rate():
    # budgeted = 0.001*3600*300/3600 = 0.3 -> 30/0.3 = 100
    assert abs(o23.burn_rate(30, 3600, 0.999, 3600.0, 300.0) - 100.0) < 1e-9
def test_o23_classify():
    assert o23.classify(100.0) == "fast"
    assert o23.classify(10.0) == "slow"
    assert o23.classify(2.0) == "ok"
def test_o23_should_alert():
    assert o23.should_alert(100.0, 2) is True
    assert o23.should_alert(100.0, 1) is False
    assert o23.should_alert(2.0, 5) is False
def test_o23_zero_elapsed():
    with pytest.raises(o23.Obs23Error): o23.burn_rate(5, 100, 0.99, 3600.0, 0.0)
def test_o23_stdlib(): assert o23.stdlib_only()
def test_o23_version(): assert o23.OBS23_VERSION == "obs-23.v1"

# ---- obs_24: Multi-window alerts ----
def test_o24_firing():
    a = o24.MultiWindowAlert(3600.0, 300.0, 2.0, 0.99)
    for i in range(12):
        a.update(i * 300.0, 200, 1000)
    out = a.evaluate(3300.0)
    assert out["firing"] is True
    assert out["long_burn"] > 2.0 and out["short_burn"] > 2.0
def test_o24_resolved_not_firing():
    a = o24.MultiWindowAlert(3600.0, 300.0, 2.0, 0.99)
    a.update(0.0, 900, 1000)
    a.update(3500.0, 0, 1000)
    out = a.evaluate(3600.0)
    assert out["firing"] is False
def test_o24_out_of_order():
    a = o24.MultiWindowAlert(3600.0, 300.0, 2.0)
    a.update(100.0, 1, 10)
    with pytest.raises(o24.Obs24Error): a.update(100.0, 1, 10)
    with pytest.raises(o24.Obs24Error): a.update(50.0, 1, 10)
def test_o24_reset():
    a = o24.MultiWindowAlert(3600.0, 300.0, 2.0)
    a.update(1.0, 5, 10)
    a.reset()
    out = a.evaluate(100.0)
    assert out["samples"] == 0 and out["firing"] is False
def test_o24_stdlib(): assert o24.stdlib_only()
def test_o24_version(): assert o24.OBS24_VERSION == "obs-24.v1"

# ---- obs_25: Runbook automation ----
def test_o25_success():
    calls = []
    rb = o25.Runbook("ok", [("a", lambda c: calls.append("a") or 1),
                            ("b", lambda c: calls.append("b") or 2)])
    out = rb.run()
    assert out["status"] == "ok" and out["completed"] == 2
    assert calls == ["a", "b"] and all(s["ok"] for s in out["steps"])
def test_o25_failure_rolls_back():
    calls = []
    def s1(ctx): calls.append("s1"); return 1
    def rb1(ctx): calls.append("rb1")
    def boom(ctx): calls.append("boom"); raise RuntimeError("x")
    rb = o25.Runbook("f", [("s1", s1, rb1), ("s2", boom, None), ("s3", s1, None)])
    out = rb.run()
    assert out["status"] == "failed" and out["completed"] == 1
    assert calls == ["s1", "boom", "rb1"]  # step3 never ran, rollback reversed
    assert out["rollbacks"] == [{"label": "s1", "rolled_back": True, "error": None}]
def test_o25_bad_label():
    with pytest.raises(o25.Obs25Error): o25.Runbook("b", [("", lambda c: None)])
def test_o25_bad_action():
    with pytest.raises(o25.Obs25Error): o25.Runbook("b", [("x", 42)])  # type: ignore
def test_o25_stdlib(): assert o25.stdlib_only()
def test_o25_version(): assert o25.OBS25_VERSION == "obs-25.v1"
