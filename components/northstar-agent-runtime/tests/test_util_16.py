"""util_16 tests."""

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


m = _load("util_16")

def test_wrap():
    try:
        raise ValueError("bad")
    except ValueError as e:
        w = m.wrap(e, "ctx")
    assert isinstance(w.__cause__, ValueError)
    assert "ctx" in str(w)


def test_chain_str():
    try:
        raise ValueError("bad")
    except ValueError as e:
        w = m.wrap(e, "ctx")
    assert m.chain_str(w) == "RuntimeError -> ValueError"


def test_to_dict():
    assert m.to_dict(ValueError("x")) == {"type": "ValueError", "message": "x"}


def test_error_context():
    import pytest
    with pytest.raises(RuntimeError, match="step 1"):
        with m.ErrorContext("step 1"):
            raise KeyError("k")


def test_stdlib_only():
    assert m.stdlib_only() is True
