"""KMP substring search tests."""

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


mod = _load("search_13")

def test_found_start():
    assert mod.kmp_search("abcabc", "abc") == 0


def test_found_middle():
    assert mod.kmp_search("xxabcxx", "abc") == 2


def test_not_found():
    assert mod.kmp_search("abcdef", "xyz") == -1


def test_empty_pattern():
    assert mod.kmp_search("abc", "") == 0
