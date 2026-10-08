"""util_18 tests."""

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


m = _load("util_18")

def test_lru_eviction():
    c = m.LRUCache(maxsize=2)
    c.set("a", 1)
    c.set("b", 2)
    c.set("c", 3)
    assert "a" not in c
    assert c.get("b") == 2
    assert len(c) == 2


def test_lru_refresh():
    c = m.LRUCache(maxsize=2)
    c.set("a", 1)
    c.set("b", 2)
    c.get("a")
    c.set("c", 3)
    assert "b" not in c
    assert c.get("a") == 1


def test_ttl_expiry():
    class Clock:
        def __init__(self):
            self.t = 100.0
        def __call__(self):
            return self.t
    clock = Clock()
    c = m.TTLCache(ttl=10.0, clock=clock)
    c.set("k", "v")
    assert c.get("k") == "v"
    clock.t += 11
    assert c.get("k") is None


def test_memoize():
    calls = []
    @m.memoize
    def f(x):
        calls.append(x)
        return x * 2
    assert f(3) == 6
    assert f(3) == 6
    assert len(calls) == 1


def test_stdlib_only():
    assert m.stdlib_only() is True
