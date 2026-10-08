"""Tests for tool_system_11."""
import importlib.util, sys
from pathlib import Path
R = Path(__file__).resolve().parent.parent
def _load(n):
    s = importlib.util.spec_from_file_location(n, R / f"{n}.py")
    m = importlib.util.module_from_spec(s); sys.modules[n] = m; s.loader.exec_module(m); return m
m = _load("tool_system_11")
import pytest

def _p(name, yes=True, log=None):
    log = log if log is not None else []
    return m.Participant(name,
        prepare=lambda: (log.append(f"{name}:p"), yes)[1],
        commit=lambda: log.append(f"{name}:c"),
        abort=lambda: log.append(f"{name}:a"))

def test_all_yes_commits():
    r = m.run_2pc([_p("a"), _p("b")])
    assert r.committed is True
    assert r.votes == {"a": "yes", "b": "yes"}

def test_one_no_aborts():
    log = []
    r = m.run_2pc([_p("a", log=log), _p("b", yes=False, log=log)])
    assert r.committed is False
    assert "a:a" in log and "a:c" not in log

def test_prepare_exception_is_no():
    bad = m.Participant("x", prepare=lambda: 1/0, commit=lambda: None, abort=lambda: None)
    r = m.run_2pc([_p("a"), bad])
    assert r.committed is False

def test_no_participants():
    with pytest.raises(m.ToolSystem11Error):
        m.run_2pc([])

def test_stdlib():
    assert m.stdlib_only() is True
