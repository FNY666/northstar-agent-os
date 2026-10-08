"""util_35 tests."""

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


m = _load("util_35")

def test_format_table():
    t = m.format_table([["a", "bb"], ["ccc", "d"]], headers=["x", "yy"])
    lines = t.splitlines()
    assert len(lines) == 4
    assert "x" in lines[0] and "ccc" in lines[3]


def test_markdown_table():
    md = m.markdown_table([["a", "b"]], ["h1", "h2"])
    lines = md.splitlines()
    assert lines[0].startswith("|")
    assert set(lines[1].replace("|", "").replace(" ", "")) == {"-"}


def test_column_widths():
    assert m.column_widths([["ab", "c"]], ["x"]) == [2, 1]


def test_stdlib_only():
    assert m.stdlib_only() is True
