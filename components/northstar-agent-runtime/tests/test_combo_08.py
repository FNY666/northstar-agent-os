"""Tests for combo_08 (Red vs blue harness)."""

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


combo = _load("combo_08")


def _harness():
    return combo.RedVsBlueHarness()


def test_block_all_gate():
    h = _harness()
    r = h.run_all(
        lambda t, a: True, lambda p: True, lambda d: True, lambda ps: 1.0
    )
    assert r["overall_block_rate"] == 1.0
    assert r["crescendo_stopped"] is True


def test_allow_all_gate():
    h = _harness()
    r = h.run_all(
        lambda t, a: False, lambda p: False, lambda d: False, lambda ps: 0.0
    )
    assert r["overall_block_rate"] == 0.0


def test_report_structure():
    h = _harness()
    r = h.run_all(
        lambda t, a: True, lambda p: True, lambda d: True, lambda ps: 1.0
    )
    assert "asi02" in r and "crescendo" in r and "bipia" in r
    assert r["asi02"]["total"] == 8


def test_stdlib_only():
    assert combo.stdlib_only() is True
