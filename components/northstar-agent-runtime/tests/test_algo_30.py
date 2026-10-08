"""algo_30 (min cut, simplified mock) tests."""

import importlib.util
import sys
from pathlib import Path

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


m = _load("algo_30")

spec29 = importlib.util.spec_from_file_location("algo_29", RUNTIME / "algo_29.py")
f29 = importlib.util.module_from_spec(spec29)
sys.modules["algo_29"] = f29
spec29.loader.exec_module(f29)


def test_known_answer():
    cap = {
        "s": {"a": 5, "b": 5},
        "a": {"t": 3},
        "b": {"t": 7},
        "t": {},
    }
    value, reach = m.min_cut(cap, "s", "t")
    assert value == 8
    assert reach == {"s", "a"}


def test_cut_value_equals_max_flow():
    cap = {
        "s": {"a": 10, "b": 10},
        "a": {"b": 2, "t": 10},
        "b": {"t": 10},
        "t": {},
    }
    value, reach = m.min_cut(cap, "s", "t")
    assert value == f29.max_flow(cap, "s", "t") == 20
    assert "s" in reach and "t" not in reach


def test_disconnected():
    value, reach = m.min_cut({"s": {}, "t": {}}, "s", "t")
    assert value == 0
    assert reach == {"s"}


def test_single_edge():
    value, reach = m.min_cut({"s": {"t": 7}}, "s", "t")
    assert value == 7
    assert reach == {"s"}


def test_reachable_set_is_source_side():
    # all forward capacity from the reachable set must be saturated,
    # and nothing in the set connects to the sink with residual capacity
    cap = {
        "s": {"a": 4, "b": 4},
        "a": {"t": 2},
        "b": {"t": 6},
        "t": {},
    }
    value, reach = m.min_cut(cap, "s", "t")
    assert value == 6
    assert reach == {"s", "a"}


def test_empty():
    value, reach = m.min_cut({}, "s", "t")
    assert value == 0
    assert reach == {"s"}


def test_stdlib_only():
    assert m.stdlib_only() is True
