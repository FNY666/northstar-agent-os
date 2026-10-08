"""Rabin-Karp search tests."""

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


mod = _load("search_14")

def test_found():
    assert mod.rabin_karp_search("abracadabra", "cada") == 4


def test_not_found():
    assert mod.rabin_karp_search("abcdef", "xyz") == -1


def test_pattern_longer():
    assert mod.rabin_karp_search("ab", "abc") == -1


def test_repeated():
    assert mod.rabin_karp_search("aaaa", "aa") == 0
