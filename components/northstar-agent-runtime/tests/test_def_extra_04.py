"""Tests for def_extra_04 (time-based access control)."""
import importlib.util
import sys
from datetime import datetime
from pathlib import Path

import pytest

RUNTIME = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


m = _load("def_extra_04")


def test_inside_window():
    tac = m.TimeAccessControl([m.TimeWindow(0, 9, 18)])
    assert tac.is_allowed(datetime(2026, 10, 5, 10, 30)) is True


def test_outside_hours():
    tac = m.TimeAccessControl([m.TimeWindow(0, 9, 18)])
    assert tac.is_allowed(datetime(2026, 10, 5, 20, 0)) is False


def test_wrong_weekday():
    tac = m.TimeAccessControl([m.TimeWindow(0, 9, 18)])
    assert tac.is_allowed(datetime(2026, 10, 6, 10, 30)) is False


def test_no_windows_fail_closed():
    tac = m.TimeAccessControl([])
    assert tac.is_allowed(datetime(2026, 10, 5, 10, 30)) is False


def test_bad_window_rejected():
    with pytest.raises(m.TimeAccessError):
        m.TimeWindow(0, 18, 9)


def test_version_pin():
    assert m.DEF_EXTRA_04_VERSION == "def-extra-04.v1"
    assert m.SCHEMA_PIN == "northstar.def-extra-04.v1"
