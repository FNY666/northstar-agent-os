"""Tests for tool_system_25."""
import importlib.util, sys
from pathlib import Path
R = Path(__file__).resolve().parent.parent
def _load(n):
    s = importlib.util.spec_from_file_location(n, R / f"{n}.py")
    m = importlib.util.module_from_spec(s); sys.modules[n] = m; s.loader.exec_module(m); return m
m = _load("tool_system_25")
import pytest

def _spec(**kw):
    spec = {
        "name": "search",
        "description": "Search the web for `docs`.",
        "args": {"query": "str", "limit": "int"},
        "examples": ["search(query='cats')"],
    }
    spec.update(kw)
    return spec

def test_render_structure():
    dg = m.DocGenerator()
    doc = dg.render(_spec())
    assert doc.startswith("# search\n")
    assert "## Arguments" in doc
    assert "| query | str |" in doc
    assert "## Examples" in doc
    assert "```\nsearch(query='cats')\n```" in doc

def test_backtick_escaping():
    dg = m.DocGenerator()
    doc = dg.render(_spec())
    assert "Search the web for \\`docs\\`." in doc
    assert "for `docs`." not in doc.replace("\\`", "")

def test_render_index():
    dg = m.DocGenerator()
    index = dg.render_index([_spec(), _spec(name="files", description="File tools.", args={}, examples=[])])
    assert index.startswith("# Tool Index\n")
    assert "- [search](#search)" in index
    assert "- [files](#files) -- File tools." in index

def test_validate_missing_field():
    dg = m.DocGenerator()
    bad = _spec()
    del bad["examples"]
    with pytest.raises(m.ToolSystem25Error):
        dg.render(bad)
    with pytest.raises(m.ToolSystem25Error):
        dg.render_index([bad])

def test_validate_wrong_types():
    dg = m.DocGenerator()
    with pytest.raises(m.ToolSystem25Error):
        dg.render(_spec(args=["query"]))
    with pytest.raises(m.ToolSystem25Error):
        dg.render(_spec(examples="not-a-list"))
    with pytest.raises(m.ToolSystem25Error):
        dg.render(_spec(name=""))

def test_stdlib():
    assert m.stdlib_only() is True
