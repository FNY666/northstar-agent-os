"""util_03 tests."""

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


m = _load("util_03")

def test_format_duration():
    assert m.format_duration(45) == "45s"
    assert m.format_duration(90) == "1m30s"
    assert m.format_duration(3661) == "1h1m1s"


def test_parse_iso():
    dt = m.parse_iso("2026-10-09T01:00:00Z")
    assert dt.year == 2026 and dt.tzinfo is not None


def test_duration_between():
    assert m.duration_between("2026-01-01T00:00:00Z", "2026-01-01T00:01:30Z") == 90.0


def test_epoch_ms():
    assert m.epoch_ms() > 0


def test_stdlib_only():
    assert m.stdlib_only() is True
