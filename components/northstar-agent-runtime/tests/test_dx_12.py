"""Tests for dx_12 autocomplete."""
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

dx = _load("dx_12")


def _c():
    return dx.Completer({"print": "builtin", "printf": "function",
                         "priority": "variable", "len": "builtin"})


def test_prefix_ranking():
    out = _c().complete("pr")
    labels = [x.label for x in out]
    # prefix matches first (alphabetical), then substring
    assert labels[0] == "print" and labels[1] == "printf"
    assert labels[2] == "priority"


def test_limit():
    assert len(_c().complete("pr", limit=2)) == 2


def test_fuzzy_subsequence():
    out = _c().complete("ptf", fuzzy=True)
    assert [x.label for x in out] == ["printf"]
    assert _c().complete("ptf", fuzzy=False) == []


def test_no_hallucination():
    assert _c().complete("zzz") == []


def test_bad_prefix_raises():
    with pytest.raises(dx.CompleteError):
        _c().complete(123)  # type: ignore


def test_bad_limit_raises():
    with pytest.raises(dx.CompleteError):
        _c().complete("pr", limit=0)


def test_add_symbol():
    c = _c()
    c.add("prune", "function")
    assert "prune" in [x.label for x in c.complete("pr")]


def test_stdlib_only():
    assert dx.stdlib_only() is True


def test_version_pin():
    assert dx.DX12_COMPLETE_VERSION == "dx-autocomplete.v1"
