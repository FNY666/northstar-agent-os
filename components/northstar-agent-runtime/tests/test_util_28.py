"""util_28 tests."""

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


m = _load("util_28")

def test_find_groups():
    assert m.find_groups(r"(\d+)-(\d+)", "a1-2 b3-4") == [("1", "2"), ("3", "4")]


def test_replace_all():
    assert m.replace_all("aaa", "a", "b") == "bbb"


def test_split_keep():
    assert m.split_keep("a1b2", r"\d") == ["a", "1", "b", "2", ""]


def test_too_long():
    import pytest
    with pytest.raises(m.RegexError):
        m.safe_compile("x" * 1001)


def test_stdlib_only():
    assert m.stdlib_only() is True
