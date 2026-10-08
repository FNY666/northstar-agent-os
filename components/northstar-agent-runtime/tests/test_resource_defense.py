"""Resource defense tests."""

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


rd = _load("resource_defense")


def test_nesting_bomb():
    ok, _ = rd.check_resources(
        "t", {"x": "f(f(f(f(f(f(x))))))"}
    )
    assert ok is False


def test_normal():
    ok, _ = rd.check_resources("t", {"x": "hello"})
    assert ok is True


def test_repetition():
    ok, _ = rd.check_resources("t", {"x": "a(" * 20})
    assert ok is False


def test_custom_limits():
    limits = rd.ResourceLimits(max_nesting_depth=2)
    ok, _ = rd.check_resources("t", {"x": "f(f(f(x)))"}, limits)
    assert ok is False


def test_stdlib_only():
    assert rd.stdlib_only() is True


def test_version_pin():
    assert rd.RESOURCE_DEFENSE_VERSION == "resource-defense.v1"
