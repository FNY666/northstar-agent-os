"""Tests for obs_16..obs_20."""
import importlib.util, sys, time
from pathlib import Path
import pytest
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
o16 = _load("obs_16"); o17 = _load("obs_17"); o18 = _load("obs_18")
o19 = _load("obs_19"); o20 = _load("obs_20")

def test_o16_roundtrip():
    samples = [(["a", "b"], 5), (["a", "c"], 2)]
    doc = o16.parse_pprof(o16.emit_pprof(samples, sample_type="cpu samples"))
    assert doc["sample_type"] == "cpu samples"
    assert [(s["frames"], s["value"]) for s in doc["samples"]] == samples
    assert [l["func"] for l in doc["locations"]] == ["a", "b", "c"]
def test_o16_bad_header():
    with pytest.raises(o16.Obs16Error): o16.parse_pprof("garbage\n")
def test_o16_bad_emit():
    with pytest.raises(o16.Obs16Error): o16.emit_pprof([(["a", ""], 1)])
def test_o16_stdlib(): assert o16.stdlib_only()
def test_o16_version(): assert o16.OBS16_VERSION == "obs-16.v1"

def test_o17_collect_top():
    p = o17.MockEBPFProfiler()
    p.attach("kprobe:sys_open")
    stacks = iter([["m", "f"], ["m", "f"], ["m", "g"]])
    rep = p.collect(lambda: next(stacks), 3)
    assert rep["samples"] == 3 and rep["probe"] == "kprobe:sys_open"
    assert p.top_functions(1) == [("m", 3)]
def test_o17_collect_before_attach():
    p = o17.MockEBPFProfiler()
    with pytest.raises(o17.Obs17Error): p.collect(lambda: ["x"], 1)
def test_o17_bad_probe():
    p = o17.MockEBPFProfiler()
    with pytest.raises(o17.Obs17Error): p.attach("  ")
def test_o17_stdlib(): assert o17.stdlib_only()

def test_o18_summary():
    rum = o18.RUMCollector()
    for v in (1000.0, 2000.0, 3000.0, 4000.0):
        rum.record_page_view("/p", v, 50.0, 0.01)
    s = rum.vitals_summary("/p")
    assert s["count"] == 4 and s["lcp_p50"] == 2500.0
    assert s["good_pct"]["lcp"] == 50.0
def test_o18_negative():
    rum = o18.RUMCollector()
    with pytest.raises(o18.Obs18Error): rum.record_page_view("/p", -1.0, 1.0, 0.0)
def test_o18_unknown_page():
    rum = o18.RUMCollector()
    with pytest.raises(o18.Obs18Error): rum.vitals_summary("/nope")
def test_o18_stdlib(): assert o18.stdlib_only()

def test_o19_run_ok():
    c = o19.SyntheticCheck("s", [("a", lambda: (True, 10.0)), ("b", lambda: (True, 5.0))])
    r = c.run()
    assert r["ok"] is True and r["total_latency_ms"] == 15.0 and len(r["steps"]) == 2
def test_o19_stops_on_failure():
    c = o19.SyntheticCheck("s", [("a", lambda: (True, 10.0)), ("b", lambda: (False, 5.0)), ("c", lambda: (True, 1.0))])
    r = c.run()
    assert r["ok"] is False and r["failed_step"] == "b" and len(r["steps"]) == 2
def test_o19_bad_label():
    with pytest.raises(o19.Obs19Error): o19.SyntheticCheck("s", [("", lambda: (True, 1.0))])
def test_o19_stdlib(): assert o19.stdlib_only()

def test_o20_uptime():
    t = o20.UptimeTracker()
    t.add_target("api")
    now = time.time()
    t.record("api", True, now - 10); t.record("api", False, now - 5)
    assert t.uptime_pct("api", 60) == 50.0
    assert t.targets() == ["api"]
def test_o20_unknown_target():
    t = o20.UptimeTracker()
    with pytest.raises(o20.Obs20Error): t.record("ghost", True, time.time())
def test_o20_bad_window():
    t = o20.UptimeTracker()
    t.add_target("api")
    t.record("api", True, time.time())
    with pytest.raises(o20.Obs20Error): t.uptime_pct("api", 0)
def test_o20_stdlib(): assert o20.stdlib_only()
