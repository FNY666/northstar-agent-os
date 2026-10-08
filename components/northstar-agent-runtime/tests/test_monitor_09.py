"""Tests for monitor_09 (SOAR playbooks)."""
import importlib.util, sys
from pathlib import Path

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


soar = _load("monitor_09")


def test_conditional_steps():
    pb = soar.deny_spike_playbook()
    rep = pb.run({"risk_score": 80})
    assert [s["step"] for s in rep["executed"]] == ["record", "quarantine", "notify"]
    rep2 = pb.run({"risk_score": 5})
    assert [s["step"] for s in rep2["executed"]] == ["record", "notify"]


def test_abort_on_condition_error():
    pb = soar.Playbook(name="x", trigger="y")
    pb.add_step(soar.Step("bad", "log", {}, condition=lambda c: 1 / 0))
    rep = pb.run({})
    assert rep["status"] == "aborted"


def test_bad_action():
    import pytest

    with pytest.raises(soar.PlaybookError):
        soar.Step("x", "launch_missiles")


def test_bad_context():
    import pytest

    pb = soar.Playbook(name="x", trigger="y")
    with pytest.raises(soar.PlaybookError):
        pb.run("nope")


def test_stdlib_only():
    assert soar.stdlib_only() is True
