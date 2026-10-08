"""Tests for state_mgmt_30."""
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
m = _load("state_mgmt_30")

def test_vertices_edges():
    g = m.CRDTGraph("n")
    g.add_vertex("a"); g.add_vertex("b"); g.add_edge("a", "b")
    assert g.vertices() == {"a", "b"}
    assert g.edges() == {("a", "b")}
def test_remove_vertex_cascades():
    g = m.CRDTGraph("n")
    g.add_vertex("a"); g.add_vertex("b"); g.add_edge("a", "b")
    g.remove_vertex("a")
    assert g.edges() == set()
def test_merge():
    a, b = m.CRDTGraph("n1"), m.CRDTGraph("n2")
    a.add_vertex("x"); b.add_vertex("y")
    a.merge(b); b.merge(a)
    assert a.vertices() == b.vertices() == {"x", "y"}
def test_edge_unknown_endpoint():
    g = m.CRDTGraph("n")
    g.add_vertex("a")
    with pytest.raises(m.GraphError):
        g.add_edge("a", "ghost")
def test_self_loop():
    g = m.CRDTGraph("n")
    g.add_vertex("a")
    with pytest.raises(m.GraphError):
        g.add_edge("a", "a")
def test_stdlib():
    assert m.stdlib_only()
