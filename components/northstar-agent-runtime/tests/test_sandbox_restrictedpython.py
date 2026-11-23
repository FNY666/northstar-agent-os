"""RestrictedPython sandbox tests."""

import importlib.util
import sys
from pathlib import Path

import pytest

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


rp = _load("sandbox_restrictedpython")


def test_allows_safe_code():
    assert rp.check_source("x = sum(range(10))")["status"] == "allowed"


def test_allows_safe_import():
    assert rp.check_source("import math")["status"] == "allowed"


def test_blocks_eval():
    with pytest.raises(rp.RestrictedPythonError):
        rp.check_source("eval('1')")


def test_blocks_os_import():
    with pytest.raises(rp.RestrictedPythonError):
        rp.check_source("import os")


def test_blocks_dunder():
    with pytest.raises(rp.RestrictedPythonError):
        rp.check_source("x.__class__")


def test_safe_builtins():
    b = rp.safe_builtins()
    assert "eval" not in b
    assert "len" in b


def test_version_pin():
    assert rp.RESTRICTED_PYTHON_VERSION == "sandbox-restricted-python.v1"
