"""util_09 tests."""

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


m = _load("util_09")

def test_roundtrip(tmp_path):
    p = tmp_path / "a.txt"
    m.atomic_write(str(p), "hi")
    assert m.safe_read(str(p)) == "hi"


def test_read_lines(tmp_path):
    p = tmp_path / "b.txt"
    p.write_text("a\nb\n")
    assert m.read_lines(str(p)) == ["a", "b"]


def test_too_large(tmp_path):
    import pytest
    p = tmp_path / "c.txt"
    p.write_text("12345")
    with pytest.raises(m.FileError):
        m.safe_read(str(p), max_bytes=2)


def test_ensure_parent(tmp_path):
    p = tmp_path / "x" / "y" / "z.txt"
    m.ensure_parent(str(p))
    assert p.parent.is_dir()


def test_stdlib_only():
    assert m.stdlib_only() is True
