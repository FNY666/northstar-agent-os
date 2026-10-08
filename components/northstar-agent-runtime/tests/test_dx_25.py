"""Tests for dx_25. dependency graphs."""
import importlib.util, sys
from pathlib import Path

import pytest

RUNTIME = Path(__file__).resolve().parent.parent

def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m

dx = _load("dx_25")

def _graph():
    g = dx.DepGraph()
    g.add_edge("app", "lib")
    g.add_edge("app", "util")
    g.add_edge("lib", "util")
    return g


def test_dependencies():
    assert _graph().dependencies("app") == ["lib", "util"]


def test_dependents():
    assert _graph().dependents("util") == ["app", "lib"]


def test_transitive():
    assert _graph().transitive("app") == ["lib", "util"]


def test_topo_order():
    order = _graph().topo_sort()
    assert order.index("app") < order.index("lib") < order.index("util")


def test_cycle_raises():
    g = dx.DepGraph()
    g.add_edge("a", "b")
    g.add_edge("b", "a")
    with pytest.raises(dx.DepGraphError):
        g.topo_sort()


def test_self_edge_raises():
    g = dx.DepGraph()
    with pytest.raises(dx.DepGraphError):
        g.add_edge("x", "x")


def test_unknown_pkg_raises():
    with pytest.raises(dx.DepGraphError):
        _graph().dependencies("nope")


def test_stdlib_only():
    assert dx.stdlib_only() is True


def test_version_pin():
    assert dx.DX25_DEPS_VERSION == "dx-deps.v1"
