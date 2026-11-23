"""Tests for input_defense_22."""
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


mod = _load("input_defense_22")

def _bucket():
    clock = [100.0]
    return mod.TokenBucket(capacity=3, refill_per_sec=1.0,
                           time_fn=lambda: clock[0]), clock


def test_allow_and_exhaust():
    b, _ = _bucket()
    assert b.allow("u") and b.allow("u") and b.allow("u")
    assert b.allow("u") is False


def test_refill():
    b, clock = _bucket()
    b.allow("u"); b.allow("u"); b.allow("u")
    clock[0] += 5.0
    assert b.allow("u") is True


def test_per_user_isolation():
    b, _ = _bucket()
    b.allow("a"); b.allow("a"); b.allow("a")
    assert b.allow("b") is True


def test_rejects_bad_args():
    b, _ = _bucket()
    try:
        b.allow("", 1)
    except mod.InputDefenseError:
        pass
    else:
        raise AssertionError("should raise")


def test_stdlib_only():
    assert mod.stdlib_only() is True

