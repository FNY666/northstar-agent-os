"""Tests for tool_system_19."""
import importlib.util, sys
from pathlib import Path
R = Path(__file__).resolve().parent.parent
def _load(n):
    s = importlib.util.spec_from_file_location(n, R / f"{n}.py")
    m = importlib.util.module_from_spec(s); sys.modules[n] = m; s.loader.exec_module(m); return m
m = _load("tool_system_19")
import pytest

def test_stable_bucketing():
    exp = m.Experiment("e", split_a=0.5, min_samples=1)
    assert exp.assign("k1") == exp.assign("k1")
    for k in [f"u{i}" for i in range(50)]:
        assert exp.assign(k) in ("A", "B")
    seen = {exp.assign(f"u{i}") for i in range(200)}
    assert seen == {"A", "B"}  # both variants reachable

def test_winner_and_rates():
    exp = m.Experiment("e", split_a=0.5, min_samples=4)
    assert exp.winner() is None  # not enough data
    for _ in range(4):
        exp.record_outcome("A", True)
        exp.record_outcome("B", False)
    assert exp.winner() == "A"
    rates = exp.rates()
    assert rates["A"] == (4, 1.0)
    assert rates["B"] == (4, 0.0)

def test_tie_undecided():
    exp = m.Experiment("e", split_a=0.5, min_samples=2)
    for _ in range(2):
        exp.record_outcome("A", True)
        exp.record_outcome("B", True)
    assert exp.winner() is None

def test_unknown_variant():
    exp = m.Experiment("e")
    with pytest.raises(m.ToolSystem19Error):
        exp.record_outcome("C", True)

def test_bad_split():
    with pytest.raises(m.ToolSystem19Error):
        m.Experiment("e", split_a=1.5)

def test_stdlib():
    assert m.stdlib_only() is True
