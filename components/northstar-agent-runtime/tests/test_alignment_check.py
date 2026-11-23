"""Alignment check tests."""

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


def test_build_input():
    trace = [ac.TraceEntry(kind="reasoning", content="thinking")]
    inp = ac.build_judgment_input("my goal", trace, "my action")
    assert inp["goal"] == "my goal"
    assert len(inp["trace"]) == 1
    assert inp["action"] == "my action"


def test_build_truncates():
    trace = [ac.TraceEntry(kind="t", content=str(i)) for i in range(30)]
    inp = ac.build_judgment_input("g", trace, "a", max_trace=10)
    assert len(inp["trace"]) == 10
    assert inp["trace_truncated"] is True


def test_rejects_empty_goal():
    with pytest.raises(ac.AlignmentCheckError):
        ac.build_judgment_input("", [], "action")


def test_observer_aligned():
    def judge(inp):
        return ac.AlignmentJudgment(aligned=True, score=0.9)

    obs = ac.AlignmentObserver(judge)
    j = obs.check("goal", [], "action")
    assert j.aligned is True
    assert j.score == 0.9


def test_observer_misaligned():
    def judge(inp):
        return ac.AlignmentJudgment(aligned=False, score=0.1, reason="drift")

    obs = ac.AlignmentObserver(judge)
    j = obs.check("goal", [], "action")
    assert j.aligned is False


def test_observer_fail_closed():
    def bad(inp):
        raise RuntimeError("judge broke")

    obs = ac.AlignmentObserver(bad)
    j = obs.check("goal", [], "action")
    assert j.aligned is False  # fail-closed
    assert j.score == 0.0


def test_check_count():
    obs = ac.AlignmentObserver(lambda inp: ac.AlignmentJudgment(True, 1.0))
    assert obs.check_count == 0
    obs.check("g", [], "a")
    assert obs.check_count == 1


def test_stdlib_only():
    assert ac.stdlib_only() is True


def test_version_pin():
    assert ac.ALIGNMENT_CHECK_VERSION == "alignment-check.v1"
