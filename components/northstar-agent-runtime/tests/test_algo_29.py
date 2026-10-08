"""algo_29 (max flow, simplified mock) tests."""

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


m = _load("algo_29")


def test_known_answer():
    cap = {
        "s": {"a": 10, "b": 10},
        "a": {"b": 2, "t": 10},
        "b": {"t": 10},
        "t": {},
    }
    assert m.max_flow(cap, "s", "t") == 20


def test_bottleneck():
    cap = {
        "s": {"a": 3, "b": 2},
        "a": {"b": 1, "t": 3},
        "b": {"t": 2},
        "t": {},
    }
    assert m.max_flow(cap, "s", "t") == 5


def test_disconnected_source_sink():
    assert m.max_flow({"s": {}, "t": {}}, "s", "t") == 0


def test_single_edge():
    assert m.max_flow({"s": {"t": 7}}, "s", "t") == 7


def test_needs_augmenting_path_reversal():
    # classic case where a naive greedy choice must be undone via residual edges
    cap = {
        "s": {"a": 1, "b": 1},
        "a": {"t": 1, "b": 1},
        "b": {"t": 1},
        "t": {},
    }
    assert m.max_flow(cap, "s", "t") == 2


def test_empty():
    assert m.max_flow({}, "s", "t") == 0


def test_stdlib_only():
    assert m.stdlib_only() is True
