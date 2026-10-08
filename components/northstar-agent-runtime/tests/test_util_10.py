"""util_10 tests."""

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


m = _load("util_10")

def test_safe_join(tmp_path):
    out = m.safe_join(str(tmp_path), "a", "b.txt")
    assert out.endswith("b.txt")


def test_escape_rejected(tmp_path):
    import pytest
    with pytest.raises(m.PathError):
        m.safe_join(str(tmp_path), "..", "evil.txt")


def test_is_within(tmp_path):
    assert m.is_within(str(tmp_path), str(tmp_path / "x")) is True
    assert m.is_within(str(tmp_path), "/etc") is False


def test_ext_of():
    assert m.ext_of("a.TAR.GZ") == "gz"
    assert m.ext_of("noext") == ""


def test_stdlib_only():
    assert m.stdlib_only() is True
