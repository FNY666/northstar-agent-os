"""Tests for input_defense_26."""
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


mod = _load("input_defense_26")

def test_solve_verify():
    ch = mod.issue_challenge()
    nonce = mod.solve(ch, bits=8)
    assert mod.verify(ch, nonce, 8) is True


def test_wrong_nonce():
    ch = mod.issue_challenge()
    assert mod.verify(ch, 123456789, 20) is False


def test_negative_nonce():
    assert mod.verify("abc", -5, 8) is False


def test_bad_bits():
    try:
        mod.solve("abc", bits=99)
    except mod.InputDefenseError:
        pass
    else:
        raise AssertionError("should raise")


def test_stdlib_only():
    assert mod.stdlib_only() is True

