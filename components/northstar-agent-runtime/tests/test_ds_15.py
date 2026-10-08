"""DS tests: Trie (ds_15)."""
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


m = _load("ds_15")


def _trie():
    t = m.Trie()
    t.insert("cat"); t.insert("car"); t.insert("dog")
    return t


def test_search():
    t = _trie()
    assert t.search("cat") is True
    assert t.search("ca") is False
    assert t.search("cats") is False


def test_starts_with():
    t = _trie()
    assert t.starts_with("ca") is True
    assert t.starts_with("do") is True
    assert t.starts_with("z") is False


def test_duplicate_insert():
    t = _trie()
    t.insert("cat")
    assert len(t) == 3
