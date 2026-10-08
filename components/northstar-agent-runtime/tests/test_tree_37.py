"""Tests for tree_37 (Expression tree)."""
import importlib.util, sys
from pathlib import Path
RUNTIME = Path(__file__).resolve().parent.parent
def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / (name + ".py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m
t = _load("tree_37")
def test_eval():
    assert t.evaluate(t.build_postfix(["2", "3", "+"])) == 5.0
def test_precedence():
    assert t.evaluate(t.build_postfix(["2", "3", "4", "*", "+"])) == 14.0
def test_infix():
    assert t.to_infix(t.build_postfix(["1", "2", "-"])) == "(1 - 2)"
def test_div():
    assert t.evaluate(t.build_postfix(["7", "2", "/"])) == 3.5
