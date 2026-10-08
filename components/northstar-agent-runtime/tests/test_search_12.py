"""Predicate binary search tests."""

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


mod = _load("search_12")

def test_middle():
    assert mod.first_true(lambda i: i * i >= 30, 10) == 6


def test_all_false():
    assert mod.first_true(lambda i: False, 5) == 5


def test_all_true():
    assert mod.first_true(lambda i: True, 5) == 0


def test_zero():
    assert mod.first_true(lambda i: True, 0) == 0
