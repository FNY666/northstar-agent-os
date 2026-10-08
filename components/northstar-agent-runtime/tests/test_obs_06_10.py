"""Tests for obs_06..obs_10."""
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
o6 = _load("obs_06"); o7 = _load("obs_07"); o8 = _load("obs_08")
o9 = _load("obs_09"); o10 = _load("obs_10")

def test_o6_attrs():
    s = o6.Span("op")
    s.set_attribute("k", "v"); s.set_attribute("n", 3)
    assert s.attributes() == {"k": "v", "n": 3}
def test_o6_bad_value():
    s = o6.Span("op")
    with pytest.raises(o6.Obs06Error): s.set_attribute("k", [1])  # type: ignore
def test_o6_bad_key():
    s = o6.Span("op")
    with pytest.raises(o6.Obs06Error): s.set_attribute("", "v")
def test_o6_nan():
    s = o6.Span("op")
    with pytest.raises(o6.Obs06Error): s.set_attribute("k", float("nan"))
def test_o6_stdlib(): assert o6.stdlib_only()

def test_o7_roundtrip():
    b = o7.Baggage(); b.set("t", "acme")
    b2 = o7.Baggage.deserialize(b.serialize())
    assert b2.get("t") == "acme"
def test_o7_bad_key():
    b = o7.Baggage()
    with pytest.raises(o7.Obs07Error): b.set("a=b", "v")
def test_o7_bad_header():
    with pytest.raises(o7.Obs07Error): o7.Baggage.deserialize("noequals")
def test_o7_stdlib(): assert o7.stdlib_only()

def test_o8_keep_error():
    assert o8.should_keep([o8.FinishedSpan("a", 5, True)])
def test_o8_keep_slow():
    assert o8.should_keep([o8.FinishedSpan("a", 9999)])
def test_o8_drop():
    assert not o8.should_keep([o8.FinishedSpan("a", 5)])
def test_o8_bad():
    with pytest.raises(o8.Obs08Error): o8.should_keep("x")  # type: ignore
def test_o8_stdlib(): assert o8.stdlib_only()

def test_o9_limit():
    lim = o9.CardinalityLimiter(2)
    assert lim.check("l", "a") and lim.check("l", "b")
    assert not lim.check("l", "c")
    assert lim.overflow_count("l") == 1
def test_o9_reseen():
    lim = o9.CardinalityLimiter(1)
    lim.check("l", "a")
    assert lim.check("l", "a")  # already seen
def test_o9_bad():
    with pytest.raises(o9.Obs09Error): o9.CardinalityLimiter(0)
def test_o9_stdlib(): assert o9.stdlib_only()

def test_o10_buckets():
    h = o10.Histogram([1.0, 2.0])
    h.observe(0.5); h.observe(1.5); h.observe(5.0)
    c = h.counts()
    assert c["1.0"] == 1 and c["2.0"] == 2 and h.total == 3
def test_o10_bad_value():
    h = o10.Histogram([1.0])
    with pytest.raises(o10.Obs10Error): h.observe("x")  # type: ignore
def test_o10_unsorted():
    with pytest.raises(o10.Obs10Error): o10.Histogram([2.0, 1.0])
def test_o10_stdlib(): assert o10.stdlib_only()
def test_o10_version(): assert o10.OBS10_VERSION == "obs-10.v1"
