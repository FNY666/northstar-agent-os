"""Horspool search tests."""

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


mod = _load("search_15")

def test_found():
    assert mod.horspool_search("find the needle", "needle") == 9


def test_not_found():
    assert mod.horspool_search("abcdef", "xyz") == -1


def test_single_char():
    assert mod.horspool_search("abc", "b") == 1


def test_full_match():
    assert mod.horspool_search("abc", "abc") == 0
