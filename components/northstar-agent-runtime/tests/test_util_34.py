"""util_34 tests."""

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


m = _load("util_34")

def test_percent():
    assert m.percent(1, 2) == 50.0
    assert m.percent(1, 0) == 0.0


def test_bar():
    assert m.bar(1, 2, 10) == "[#####-----] 50%"
    assert m.bar(0, 4, 4) == "[----] 0%"
    assert m.bar(4, 4, 4) == "[####] 100%"


def test_eta():
    assert m.eta_seconds(10.0, 1, 4) == 30.0
    assert m.eta_seconds(10.0, 0, 4) is None
    assert m.eta_seconds(10.0, 4, 4) == 0.0


def test_stdlib_only():
    assert m.stdlib_only() is True
