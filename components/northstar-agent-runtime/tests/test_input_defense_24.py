"""Tests for input_defense_24."""
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


mod = _load("input_defense_24")

def _quota():
    day = ["2026-10-09"]
    return mod.DailyQuota(max_calls_per_day=2, max_tokens_per_day=50,
                          date_fn=lambda: day[0]), day


def test_consume_ok():
    q, _ = _quota()
    assert q.consume("u", tokens=10) is True


def test_call_quota():
    q, _ = _quota()
    q.consume("u"); q.consume("u")
    assert q.consume("u") is False


def test_token_quota():
    q, _ = _quota()
    assert q.consume("u", tokens=60) is False


def test_day_reset():
    q, day = _quota()
    q.consume("u"); q.consume("u")
    day[0] = "2026-10-10"
    assert q.consume("u") is True


def test_stdlib_only():
    assert mod.stdlib_only() is True

