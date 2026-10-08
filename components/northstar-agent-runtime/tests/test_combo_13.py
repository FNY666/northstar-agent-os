"""Tests for combo_13 (Session immune system)."""

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


combo = _load("combo_13")


def _immune():
    tw = combo.tw
    tripwire = tw.TripwireGuard("t", lambda tool, args: "evil" in str(args))
    return combo.SessionImmuneSystem(tripwire)


def test_clean_allowed():
    im = _immune()
    r = im.attempt("read", {})
    assert r["allowed"] is True


def test_violation_recorded():
    im = _immune()
    r = im.attempt("run", {"x": "evil"})
    assert r["hook_allowed"] is False
    assert r["risk"] > 0


def test_repeat_offenders_rate_limited():
    im = _immune()
    for _ in range(15):
        im.attempt("run", {"x": "evil"})
    r = im.attempt("run", {"x": "evil"})
    assert r["rate_limited"] is True


def test_stdlib_only():
    assert combo.stdlib_only() is True
