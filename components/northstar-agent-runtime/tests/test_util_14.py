"""util_14 tests."""

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


m = _load("util_14")

def test_human_bytes():
    assert m.human_bytes(0) == "0 B"
    assert m.human_bytes(1536) == "1.5 KiB"
    assert m.human_bytes(1024 * 1024) == "1.0 MiB"


def test_human_duration():
    assert m.human_duration(30) == "30s"
    assert m.human_duration(90) == "1m 30s"
    assert m.human_duration(3700) == "1h 1m"


def test_human_number():
    assert m.human_number(1234567) == "1.23M"
    assert m.human_number(1500) == "1.5K"
    assert m.human_number(999) == "999"


def test_pluralize():
    assert m.pluralize(1, "file") == "1 file"
    assert m.pluralize(2, "file") == "2 files"
    assert m.pluralize(2, "child", "children") == "2 children"


def test_stdlib_only():
    assert m.stdlib_only() is True
