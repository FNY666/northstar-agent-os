"""util_19 tests."""

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


m = _load("util_19")

def test_from_env(monkeypatch):
    monkeypatch.setenv("U19_FOO", "1")
    monkeypatch.setenv("U19_BAR", "2")
    cfg = m.from_env("U19_")
    assert cfg["foo"] == "1" and cfg["bar"] == "2"


def test_from_json_file(tmp_path):
    p = tmp_path / "c.json"
    p.write_text('{"a": 1}')
    assert m.from_json_file(str(p)) == {"a": 1}


def test_merge_and_typed():
    assert m.merge_configs({"a": 1}, {"a": 2}) == {"a": 2}
    assert m.get_typed({"n": "5"}, "n", int) == 5
    assert m.get_typed({}, "x", int, default=9) == 9


def test_bad_typed():
    import pytest
    with pytest.raises(m.ConfigError):
        m.get_typed({"n": "xx"}, "n", int)


def test_stdlib_only():
    assert m.stdlib_only() is True
