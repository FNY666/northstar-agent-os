"""DS tests: BK-Tree (ds_43)."""
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


m = _load("ds_43")


def _tree():
    t = m.BKTree(m.levenshtein)
    for w in ("cat", "bat", "rat", "dog"):
        t.insert(w)
    return t


def test_tolerance_query():
    assert sorted(_tree().query("cat", 1)) == ["bat", "cat", "rat"]


def test_exact():
    assert _tree().query("dog", 0) == ["dog"]


def test_empty_tree():
    assert m.BKTree(m.levenshtein).query("x", 3) == []


def test_levenshtein():
    assert m.levenshtein("kitten", "sitting") == 3
    assert m.levenshtein("abc", "abc") == 0
