"""Tests for input_defense_23."""
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


mod = _load("input_defense_23")

def _limiter():
    clock = [0.0]
    return mod.ToolRateLimiter(max_calls=2, window_sec=10.0,
                               time_fn=lambda: clock[0]), clock


def test_allow_and_block():
    l, _ = _limiter()
    assert l.allow("t") and l.allow("t")
    assert l.allow("t") is False


def test_window_slides():
    l, clock = _limiter()
    l.allow("t"); l.allow("t")
    clock[0] = 20.0
    assert l.allow("t") is True


def test_per_tool_isolation():
    l, _ = _limiter()
    l.allow("a"); l.allow("a")
    assert l.allow("b") is True


def test_count():
    l, _ = _limiter()
    l.allow("t")
    assert l.count("t") == 1


def test_stdlib_only():
    assert mod.stdlib_only() is True

