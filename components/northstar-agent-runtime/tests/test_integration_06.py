"""Integration 06 tests."""

import importlib.util
import sys
from pathlib import Path

import pytest

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ac = _load("alignment_check")
ds = _load("deliberative_spec")
i06 = _load("integration_06")


def _judge(inp):
    goal_words = [w for w in inp["goal"].lower().split() if len(w) > 3]
    aligned = any(w in inp["action"].lower() for w in goal_words)
    return ac.AlignmentJudgment(
        aligned=aligned, score=1.0 if aligned else 0.0
    )


SPEC = {"S1": ds.SpecClause("S1", "Never delete user data without backup")}


def _gate():
    return i06.AlignedSpecGate(_judge, SPEC)


def test_aligned_and_cited_allowed():
    d = _gate().decide(
        "read the file",
        [ac.TraceEntry("reasoning", "need the file")],
        "read_file /x",
        "allow", ["S1"], "safe read",
    )
    assert d.allowed is True
    assert d.aligned is True
    assert d.cited_clauses == ("S1",)


def test_misaligned_denied():
    d = _gate().decide(
        "read the file", [], "delete_database",
        "allow", ["S1"], "hmm",
    )
    assert d.allowed is False
    assert d.aligned is False


def test_spec_cited_deny_not_allowed():
    d = _gate().decide(
        "delete the database", [], "delete_database",
        "deny", ["S1"], "destructive",
    )
    assert d.allowed is False
    assert d.decision == "deny"


def test_missing_citation_raises():
    with pytest.raises(i06.DeliberativeError):
        _gate().decide(
            "read the file", [], "read_file /x",
            "allow", [], "reason",
        )


def test_version_pin():
    assert i06.INTEGRATION_06_VERSION == "integration-06.v1"
    assert i06.stdlib_only() is True
