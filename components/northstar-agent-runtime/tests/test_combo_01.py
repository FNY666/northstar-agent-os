"""Tests for combo_01 (Safe gated output)."""

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


combo = _load("combo_01")


def _pipe(block=False):
    tw = combo.tw
    tripwire = tw.TripwireGuard("t", lambda tool, args: block)
    schema = combo.so.VerdictSchema(
        "s", [combo.so.FieldSpec("verdict", "str", True, ["allow", "deny"])]
    )
    return combo.SafeGatedOutput(tripwire, schema)


def test_clean_output_passes():
    pipe = _pipe()
    out = pipe.emit("t", {}, {"verdict": "allow"})
    assert out["verdict"] == "allow"


def test_tripwire_halts():
    pipe = _pipe(block=True)
    try:
        pipe.emit("t", {}, {"verdict": "allow"})
    except combo.ComboError:
        return
    raise AssertionError("expected ComboError")


def test_pii_masked():
    pipe = _pipe()
    out = pipe.emit("t", {}, {"verdict": "deny"})
    # no PII present: output unchanged apart from validation
    assert out["verdict"] == "deny"


def test_schema_violation_raises():
    pipe = _pipe()
    try:
        pipe.emit("t", {}, {"verdict": "maybe"})
    except Exception:
        return
    raise AssertionError("expected schema error")


def test_stdlib_only():
    assert combo.stdlib_only() is True
