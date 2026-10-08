"""util_17 tests."""

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


m = _load("util_17")

def test_backoff():
    assert m.backoff_delay(0) == 1.0
    assert m.backoff_delay(2) == 4.0
    assert m.backoff_delay(100) == 60.0


def test_jitter_bounds():
    import random
    rng = random.Random(0)
    for _ in range(50):
        v = m.with_jitter(10.0, 0.25, rng)
        assert 7.5 <= v <= 12.5


def test_retry_delays():
    assert m.retry_delays(3) == [1.0, 2.0, 4.0]
    assert m.retry_delays(0) == []


def test_should_retry():
    assert m.should_retry(ValueError("x"), retry_on=(ValueError,)) is True
    assert m.should_retry(ValueError("x"), retry_on=(KeyError,)) is False


def test_stdlib_only():
    assert m.stdlib_only() is True
