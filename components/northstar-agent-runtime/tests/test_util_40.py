"""util_40 tests."""

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


m = _load("util_40")

def test_unique_int():
    m.reset_counter()
    assert m.unique_int() == 1
    assert m.unique_int() == 2


def test_short_id():
    m.reset_counter()
    a = m.short_id(8)
    b = m.short_id(8)
    assert len(a) == 8 and a != b


def test_prefixed_id():
    pid = m.prefixed_id("run")
    assert pid.startswith("run-")
    assert len(pid.split("-")) == 3


def test_bad_n():
    import pytest
    with pytest.raises(m.IdError):
        m.short_id(0)


def test_stdlib_only():
    assert m.stdlib_only() is True
