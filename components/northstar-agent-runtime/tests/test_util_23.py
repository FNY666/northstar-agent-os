"""util_23 tests."""

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


m = _load("util_23")

def test_roundtrip(tmp_path):
    p = str(tmp_path / "t.csv")
    m.write_csv(p, [{"a": "1", "b": "2"}])
    assert m.read_csv(p) == [{"a": "1", "b": "2"}]


def test_to_csv_string():
    s = m.to_csv_string([{"x": 1, "y": 2}])
    lines = s.splitlines()
    assert lines[0] == "x,y"
    assert lines[1] == "1,2"


def test_empty_no_fieldnames():
    import pytest
    with pytest.raises(m.CsvError):
        m.write_csv("/tmp/x.csv", [])


def test_stdlib_only():
    assert m.stdlib_only() is True
