"""Tests for obs_01..obs_05."""
import importlib.util, sys, json
from pathlib import Path
import pytest
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
o1 = _load("obs_01"); o2 = _load("obs_02"); o3 = _load("obs_03")
o4 = _load("obs_04"); o5 = _load("obs_05")

def test_o1_json_shape():
    r = json.loads(o1.log_json("INFO", "m", k="v"))
    assert r["level"] == "INFO" and r["k"] == "v" and "timestamp" in r
def test_o1_bad_level():
    with pytest.raises(o1.Obs01Error): o1.log_json("X", "m")
def test_o1_nonserializable():
    with pytest.raises(o1.Obs01Error): o1.log_json("INFO", "m", bad=object())
def test_o1_stdlib(): assert o1.stdlib_only()
def test_o1_version(): assert o1.OBS01_VERSION == "obs-01.v1"

def test_o2_ordering():
    assert o2.should_log(o2.LogLevel.INFO, o2.LogLevel.WARN)
    assert not o2.should_log(o2.LogLevel.ERROR, o2.LogLevel.DEBUG)
def test_o2_parse():
    assert o2.parse_level("error") == o2.LogLevel.ERROR
    with pytest.raises(o2.Obs02Error): o2.parse_level("nope")
def test_o2_stdlib(): assert o2.stdlib_only()

def test_o3_sampling():
    s = o3.Sampler(2)
    assert [s.should_sample() for _ in range(4)] == [False, True, False, True]
def test_o3_keep_all():
    s = o3.Sampler(1)
    assert all(s.should_sample() for _ in range(3))
def test_o3_bad_n():
    with pytest.raises(o3.Obs03Error): o3.Sampler(0)
def test_o3_stdlib(): assert o3.stdlib_only()

def test_o4_redact():
    r = o4.redact("a@b.com and 555-123-4567")
    assert "[REDACTED:EMAIL]" in r and "[REDACTED:PHONE]" in r
def test_o4_clean(): assert o4.redact("hello") == "hello"
def test_o4_bad_input():
    with pytest.raises(o4.Obs04Error): o4.redact(None)  # type: ignore
def test_o4_stdlib(): assert o4.stdlib_only()

def test_o5_roundtrip():
    tid, sid = o5.new_trace_id(), o5.new_span_id()
    c = o5.inject({}, tid, sid)
    ctx = o5.extract(c)
    assert ctx["trace_id"] == tid and ctx["span_id"] == sid
def test_o5_missing(): assert o5.extract({}) is None
def test_o5_bad_carrier():
    with pytest.raises(o5.Obs05Error): o5.inject([], "t", "s")  # type: ignore
def test_o5_stdlib(): assert o5.stdlib_only()
def test_o5_version(): assert o5.OBS05_VERSION == "obs-05.v1"
