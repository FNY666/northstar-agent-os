"""util_08 tests."""

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


m = _load("util_08")

def test_safe_parse():
    assert m.safe_parse('{"a": 1}') == {"a": 1}
    assert m.safe_parse("bad", default=[]) == []


def test_canonical():
    assert m.canonical({"b": 1, "a": 2}) == '{"a":2,"b":1}'


def test_pretty_and_file(tmp_path):
    p = tmp_path / "c.json"
    p.write_text('{"x": 1}')
    assert m.parse_file(str(p)) == {"x": 1}
    assert m.parse_file(str(tmp_path / "missing"), default=9) == 9


def test_not_serializable():
    import pytest
    with pytest.raises(m.JsonError):
        m.canonical(object())


def test_stdlib_only():
    assert m.stdlib_only() is True
