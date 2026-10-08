"""util_37 tests."""

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


m = _load("util_37")

def test_typed(monkeypatch):
    monkeypatch.setenv("U37_N", "42")
    monkeypatch.setenv("U37_F", "1.5")
    monkeypatch.setenv("U37_B", "yes")
    monkeypatch.setenv("U37_S", "hi")
    assert m.getenv_int("U37_N") == 42
    assert m.getenv_float("U37_F") == 1.5
    assert m.getenv_bool("U37_B") is True
    assert m.getenv_str("U37_S") == "hi"


def test_defaults(monkeypatch):
    monkeypatch.delenv("U37_MISSING", raising=False)
    assert m.getenv_int("U37_MISSING", default=7) == 7
    assert m.getenv_bool("U37_MISSING", default=True) is True


def test_bad_int(monkeypatch):
    import pytest
    monkeypatch.setenv("U37_BAD", "xx")
    with pytest.raises(m.EnvError):
        m.getenv_int("U37_BAD")


def test_require(monkeypatch):
    import pytest
    monkeypatch.setenv("U37_REQ", "v")
    assert m.require_env("U37_REQ") == "v"
    monkeypatch.delenv("U37_REQ")
    with pytest.raises(m.EnvError):
        m.require_env("U37_REQ")


def test_stdlib_only():
    assert m.stdlib_only() is True
