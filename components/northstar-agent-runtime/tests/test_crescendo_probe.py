"""Crescendo probe tests."""

import importlib.util
import sys
from pathlib import Path

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


cp = _load("crescendo_probe")


def test_scripts_exist():
    assert len(cp.SCRIPTS) >= 2


def test_run_stopped():
    def gate(prompt):
        return "verbatim" in prompt

    def scorer(prompts):
        return 0.9

    result = cp.run_script(cp.SCRIPTS[0], gate, scorer)
    assert result["stopped"] is True


def test_trajectory_scoring():
    turns = [cp.EscalationTurn(1, "hello", 0.1)]
    score = cp.score_trajectory(turns, lambda p: 0.5)
    assert score == 0.5


def test_scorer_exception_fail_closed():
    turns = [cp.EscalationTurn(1, "hello", 0.1)]

    def bad(prompts):
        raise RuntimeError("oops")

    score = cp.score_trajectory(turns, bad)
    assert score == 1.0  # fail-closed


def test_stdlib_only():
    assert cp.stdlib_only() is True


def test_version_pin():
    assert cp.CRESCENDO_VERSION == "crescendo-probe.v1"
