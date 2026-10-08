"""util_39 tests."""

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


m = _load("util_39")

def test_signature():
    def f(a, b=2):
        return a
    assert m.signature_str(f) == "(a, b=2)"


def test_callable_name():
    def f():
        pass
    assert m.callable_name(f) == "f"
    assert m.callable_name(len) == "len"


def test_generator():
    def g():
        yield 1
    def h():
        pass
    assert m.is_generator_fn(g) is True
    assert m.is_generator_fn(h) is False


def test_source_file():
    def f():
        pass
    assert m.source_file(f).endswith(".py")


def test_stdlib_only():
    assert m.stdlib_only() is True
