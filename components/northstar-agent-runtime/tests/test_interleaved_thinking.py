"""Interleaved thinking tests."""

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


it = _load("interleaved_thinking")


def test_require_reasoning():
    a = it.require_reasoning("I think", "tool", {"x": 1})
    assert a.reasoning == "I think"
    assert a.tool_name == "tool"
    assert a.reasoning_hash.startswith("sha256:")


def test_rejects_empty_reasoning():
    with pytest.raises(it.InterleavedError):
        it.require_reasoning("", "tool", {})


def test_rejects_none_reasoning():
    with pytest.raises(it.InterleavedError):
        it.require_reasoning(None, "tool", {})  # type: ignore


def test_rejects_whitespace_only():
    with pytest.raises(it.InterleavedError):
        it.require_reasoning("   ", "tool", {})


def test_runner_enforces():
    runner = it.InterleavedRunner(executor=lambda t, a: "ok")
    result = runner.run("reason", "tool", {})
    assert result == "ok"
    assert len(runner.actions) == 1


def test_runner_rejects():
    runner = it.InterleavedRunner(executor=lambda t, a: "ok")
    with pytest.raises(it.InterleavedError):
        runner.run("", "tool", {})


def test_runner_logs():
    logged = []
    runner = it.InterleavedRunner(
        executor=lambda t, a: "ok", log_fn=logged.append
    )
    runner.run("r", "t", {"k": "v"})
    assert len(logged) == 1
    assert logged[0].tool_name == "t"
    assert logged[0].args == {"k": "v"}


def test_reasoning_hash_binds():
    a1 = it.require_reasoning("reason one", "t", {})
    a2 = it.require_reasoning("reason two", "t", {})
    assert a1.reasoning_hash != a2.reasoning_hash


def test_stdlib_only():
    assert it.stdlib_only() is True


def test_version_pin():
    assert it.INTERLEAVED_VERSION == "interleaved-thinking.v1"
