"""Tests for obs_11..obs_15."""
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
o11 = _load("obs_11"); o12 = _load("obs_12"); o13 = _load("obs_13")
o14 = _load("obs_14"); o15 = _load("obs_15")

def test_o11_quantile():
    s = o11.MockSummary(5)
    for i in (1, 2, 3, 4, 5): s.observe(i)
    assert s.quantile(0.0) == 1.0 and s.quantile(1.0) == 5.0
def test_o11_bad_q():
    s = o11.MockSummary(5); s.observe(1.0)
    with pytest.raises(o11.Obs11Error): s.quantile(2.0)
def test_o11_empty():
    s = o11.MockSummary(5)
    with pytest.raises(o11.Obs11Error): s.quantile(0.5)
def test_o11_stdlib(): assert o11.stdlib_only()

def test_o12_add_get():
    st = o12.ExemplarStore(5)
    st.add("m", "t1", 1.5)
    ex = st.get("m")
    assert len(ex) == 1 and ex[0].trace_id == "t1"
def test_o12_evict():
    st = o12.ExemplarStore(1)
    st.add("m", "t1", 1.0); st.add("m", "t2", 2.0)
    assert [e.trace_id for e in st.get("m")] == ["t2"]
def test_o12_bad():
    st = o12.ExemplarStore(5)
    with pytest.raises(o12.Obs12Error): st.add("", "t", 1.0)
def test_o12_stdlib(): assert o12.stdlib_only()

def test_o13_profile():
    out = o13.profile(lambda: 42, top_n=3)
    assert out["result"] == 42 and len(out["top"]) <= 3
def test_o13_not_callable():
    with pytest.raises(o13.Obs13Error): o13.profile(123)  # type: ignore
def test_o13_stats_shape():
    out = o13.profile(sum, [1, 2, 3], top_n=3)
    assert out["result"] == 6
    assert all("cumtime" in s for s in out["top"])
def test_o13_stdlib(): assert o13.stdlib_only()

def test_o14_lifecycle():
    p = o14.MockContinuousProfiler(10)
    p.start(); assert p.running
    s = p.snapshot("x")
    assert s["mock"] is True
    p.stop(); assert not p.running
def test_o14_double_start():
    p = o14.MockContinuousProfiler(10)
    p.start()
    with pytest.raises(o14.Obs14Error): p.start()
def test_o14_snapshot_stopped():
    p = o14.MockContinuousProfiler(10)
    with pytest.raises(o14.Obs14Error): p.snapshot()
def test_o14_stdlib(): assert o14.stdlib_only()

def test_o15_roundtrip():
    stacks = [(["a", "b"], 5), (["a"], 2)]
    assert o15.from_folded(o15.to_folded(stacks)) == stacks
def test_o15_bad_frame():
    with pytest.raises(o15.Obs15Error): o15.to_folded([(["a;b"], 1)])
def test_o15_bad_line():
    with pytest.raises(o15.Obs15Error): o15.from_folded("nonsense")
def test_o15_stdlib(): assert o15.stdlib_only()
def test_o15_version(): assert o15.OBS15_VERSION == "obs-15.v1"
