"""util_36 tests."""

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


m = _load("util_36")

def test_parse():
    assert m.parse_semver("1.2.3") == (1, 2, 3)
    assert m.parse_semver(" 2.0.0-rc1 ") == (2, 0, 0)


def test_compare():
    assert m.compare("1.2.3", "1.2.4") == -1
    assert m.compare("2.0.0", "1.9.9") == 1
    assert m.compare("1.0.0", "1.0.0") == 0


def test_newer_and_bump():
    assert m.is_newer("1.2.4", "1.2.3") is True
    assert m.is_newer("1.2.3", "1.2.3") is False
    assert m.bump_patch("1.2.3") == "1.2.4"


def test_bad():
    import pytest
    with pytest.raises(m.VersionError):
        m.parse_semver("notaversion")


def test_stdlib_only():
    assert m.stdlib_only() is True
