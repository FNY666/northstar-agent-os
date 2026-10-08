"""Tests for dx_23. benchmark runners."""
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

dx = _load("dx_23")

def _bench():
    b = dx.BenchmarkRunner()
    b.register("sort", [1.0, 2.0, 3.0])
    return b


def test_run_stats():
    s = _bench().run("sort", reps=4)
    assert s.min == 1.0 and s.max == 3.0
    assert abs(s.mean - 1.75) < 1e-9
    assert s.unit == "ms" and s.reps == 4


def test_unknown_raises():
    with pytest.raises(dx.BenchError):
        _bench().run("nope")


def test_negative_rejected():
    b = dx.BenchmarkRunner()
    with pytest.raises(dx.BenchError):
        b.register("neg", [-1.0])


def test_bad_reps_raises():
    with pytest.raises(dx.BenchError):
        _bench().run("sort", reps=0)


def test_stdlib_only():
    assert dx.stdlib_only() is True


def test_version_pin():
    assert dx.DX23_BENCH_VERSION == "dx-bench.v1"
