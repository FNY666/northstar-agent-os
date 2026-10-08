"""util_38 tests."""

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


m = _load("util_38")

def test_temp_dir_cleanup():
    with m.temp_dir() as d:
        assert d.is_dir()
        (d / "f.txt").write_text("x")
    assert not d.exists()


def test_temp_file_path(tmp_path):
    p = m.temp_file_path(dir=str(tmp_path))
    assert p.is_file()
    p.unlink()


def test_cleanup_old(tmp_path):
    import os, time
    old = tmp_path / "old.txt"
    old.write_text("x")
    new = tmp_path / "new.txt"
    new.write_text("y")
    ancient = time.time() - 10000
    os.utime(old, (ancient, ancient))
    assert m.cleanup_old(str(tmp_path), 3600) == 1
    assert not old.exists() and new.exists()


def test_stdlib_only():
    assert m.stdlib_only() is True
