"""Tests for dx_06 tutorials."""
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

dx = _load("dx_06")


def _tut():
    return dx.Tutorial(
        "t",
        [dx.Step("s1", "type a", "hint a"), dx.Step("s2", "type b", "hint b")],
        [lambda t: t.strip() == "a", lambda t: t.strip() == "b"],
    )


def test_wrong_answer_no_advance():
    tut = _tut()
    r = tut.answer("x")
    assert not r.correct and not r.done
    assert tut.progress == {"done": 0, "total": 2}
    assert "hint" in r.message


def test_correct_advances_and_completes():
    tut = _tut()
    r = tut.answer("a")
    assert r.correct and not r.done
    r = tut.answer("b")
    assert r.correct and r.done


def test_answer_after_complete_raises():
    tut = _tut()
    tut.answer("a")
    tut.answer("b")
    with pytest.raises(dx.TutorialError):
        tut.answer("b")


def test_empty_steps_raises():
    with pytest.raises(dx.TutorialError):
        dx.Tutorial("t", [], [])


def test_mismatched_checkers_raises():
    with pytest.raises(dx.TutorialError):
        dx.Tutorial("t", [dx.Step("s", "i")], [])


def test_checker_exception_is_wrong():
    tut = dx.Tutorial("t", [dx.Step("s", "i")], [lambda t: 1 / 0])
    r = tut.answer("anything")
    assert not r.correct


def test_stdlib_only():
    assert dx.stdlib_only() is True


def test_version_pin():
    assert dx.DX06_TUTORIAL_VERSION == "dx-tutorial.v1"
