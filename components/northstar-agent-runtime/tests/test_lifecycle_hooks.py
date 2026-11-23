"""Lifecycle hooks tests."""

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


lh = _load("lifecycle_hooks")


def test_hook_allow():
    r = lh.HookRegistry()
    r.register(lh.HookPoint.PRE_TOOL, lambda ctx: True)
    allowed, _ = r.fire(lh.HookPoint.PRE_TOOL, {})
    assert allowed is True


def test_hook_block():
    r = lh.HookRegistry()
    r.register(lh.HookPoint.PRE_TOOL, lambda ctx: False)
    allowed, _ = r.fire(lh.HookPoint.PRE_TOOL, {})
    assert allowed is False


def test_hook_exception_fail_closed():
    def bad(ctx):
        raise RuntimeError("oops")

    r = lh.HookRegistry()
    r.register(lh.HookPoint.PRE_TOOL, bad)
    allowed, reason = r.fire(lh.HookPoint.PRE_TOOL, {})
    assert allowed is False
    assert "raised" in reason


def test_canary_pass():
    r = lh.HookRegistry()
    # Block everything canary tests.
    def runner(tool, args):
        return True  # all blocked

    result = r.run_canary(runner)
    assert result["status"] == "pass"


def test_canary_detects_fail_open():
    r = lh.HookRegistry()

    def runner(tool, args):
        return False  # nothing blocked (fail-open)

    with pytest.raises(lh.HookError) as exc:
        r.run_canary(runner)
    assert "fail-open" in str(exc.value).lower()


def test_canary_probes_exist():
    assert len(lh.CANARY_PROBES) >= 4


def test_stdlib_only():
    assert lh.stdlib_only() is True


def test_version_pin():
    assert lh.LIFECYCLE_HOOKS_VERSION == "lifecycle-hooks.v1"
