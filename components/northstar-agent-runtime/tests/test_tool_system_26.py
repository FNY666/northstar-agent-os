"""Tests for tool_system_26."""
import importlib.util, sys
from pathlib import Path
R = Path(__file__).resolve().parent.parent
def _load(n):
    s = importlib.util.spec_from_file_location(n, R / f"{n}.py")
    m = importlib.util.module_from_spec(s); sys.modules[n] = m; s.loader.exec_module(m); return m
m = _load("tool_system_26")
import pytest

def _pg():
    pg = m.Playground(max_log=3)
    pg.register_schema(
        "search",
        m.ArgSchema(required={"query": str}, optional={"limit": int}),
    )
    return pg

def test_dry_run_ok():
    pg = _pg()
    out = pg.dry_run(
        "search", {"query": "x"}, lambda t, a: {"hits": [a["query"]]}
    )
    assert out == {"hits": ["x"]}
    assert pg.last_run().ok is True

def test_schema_violation():
    pg = _pg()
    with pytest.raises(m.SchemaViolation):
        pg.dry_run("search", {}, lambda t, a: None)
    with pytest.raises(m.SchemaViolation):
        pg.dry_run("search", {"query": 1}, lambda t, a: None)
    with pytest.raises(m.SchemaViolation):
        pg.dry_run("search", {"query": "x", "extra": 1}, lambda t, a: None)

def test_unsafe_dunder_rejected():
    pg = _pg()
    with pytest.raises(m.UnsafeArgs):
        pg.dry_run("search", {"query": "x", "__dunder__": 1}, lambda t, a: None)
    with pytest.raises(m.UnsafeArgs):
        pg.dry_run(
            "search", {"query": "x", "nested": {"__x": 1}}, lambda t, a: None
        )

def test_unknown_tool():
    pg = _pg()
    with pytest.raises(m.UnknownTool):
        pg.dry_run("nope", {}, lambda t, a: None)

def test_log_bounded():
    pg = _pg()
    for i in range(5):
        pg.dry_run("search", {"query": str(i)}, lambda t, a: {"n": 1})
    assert len(pg.runs()) == 3
    assert pg.runs()[-1].args["query"] == "4"

def test_stdlib():
    assert m.stdlib_only() is True
