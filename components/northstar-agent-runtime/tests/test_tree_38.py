"""Tests for tree_38 (Decision tree mock)."""
import importlib.util, sys
from pathlib import Path
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / (name + ".py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
t = _load("tree_38")
DATA = [("a", 1, "y"), ("a", 2, "y"), ("b", 1, "n"), ("b", 2, "n")]
def test_fit_predict():
    tree = t.fit(DATA, [0, 1])
    assert t.predict(tree, ("a", 1)) == "y"
def test_other_branch():
    tree = t.fit(DATA, [0, 1])
    assert t.predict(tree, ("b", 2)) == "n"
def test_pure_leaf():
    tree = t.fit([("a", 1, "y")], [0, 1])
    assert tree.label == "y"
def test_entropy():
    assert t._entropy([("x", "y"), ("x", "y")]) == 0.0
