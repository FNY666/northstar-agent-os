"""algo_26 (Tarjan SCC) tests."""

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


m = _load("algo_26")


def _norm(sccs):
    return {frozenset(c) for c in sccs}


def test_known_answer():
    g = {"A": ["B"], "B": ["C"], "C": ["A", "D"], "D": ["E"], "E": []}
    assert _norm(m.tarjan_scc(g)) == {
        frozenset({"A", "B", "C"}),
        frozenset({"D"}),
        frozenset({"E"}),
    }


def test_two_cycles():
    g = {"A": ["B"], "B": ["A", "C"], "C": ["D"], "D": ["C"]}
    assert _norm(m.tarjan_scc(g)) == {
        frozenset({"A", "B"}),
        frozenset({"C", "D"}),
    }


def test_empty_and_singletons():
    assert m.tarjan_scc({}) == []
    assert _norm(m.tarjan_scc({"A": [], "B": []})) == {
        frozenset({"A"}), frozenset({"B"})
    }


def test_self_loop():
    assert m.tarjan_scc({"X": ["X"]}) == [["X"]]


def test_disconnected_acyclic():
    g = {"A": ["B"], "B": [], "C": ["D"], "D": []}
    assert _norm(m.tarjan_scc(g)) == {
        frozenset({"A"}), frozenset({"B"}),
        frozenset({"C"}), frozenset({"D"}),
    }


def test_stdlib_only():
    assert m.stdlib_only() is True
