"""Tests for combo_20 (Full-stack gate)."""

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


combo = _load("combo_20")


def _gate(policy=None):
    tw = combo.tw
    tripwire = tw.TripwireGuard("t", lambda tool, args: "evil" in str(args))
    policy = policy or {"read": {"allowed_sources": {"read"}}}
    return combo.FullStackGate(tripwire, policy)


def test_clean_passes_all_layers():
    g = _gate()
    r = g.guard("read", {"path": "/x"}, combo.dv.Consequence.REVERSIBLE_LOW)
    assert r["layers_passed"] == 4


def test_layer1_tripwire():
    g = _gate()
    try:
        g.guard("read", {"q": "evil"}, combo.dv.Consequence.REVERSIBLE_LOW)
    except combo.ComboError as exc:
        assert "layer 1" in str(exc)
        return
    raise AssertionError("expected ComboError")


def test_layer2_provenance():
    g = _gate({"read": {"allowed_sources": {"user"}}})
    try:
        g.guard("read", {"path": "/x"}, combo.dv.Consequence.REVERSIBLE_LOW)
    except combo.ComboError as exc:
        assert "layer 2" in str(exc)
        return
    raise AssertionError("expected ComboError")


def test_layer3_veto():
    g = _gate()
    try:
        g.guard("read", {"path": "/x"}, combo.dv.Consequence.IRREVERSIBLE_BROAD)
    except combo.ComboError as exc:
        assert "layer 3" in str(exc)
        return
    raise AssertionError("expected ComboError")


def test_layer4_resource():
    g = _gate()
    try:
        g.guard("read", {"x": "f(" * 60}, combo.dv.Consequence.REVERSIBLE_LOW)
    except combo.ComboError as exc:
        assert "layer 4" in str(exc)
        return
    raise AssertionError("expected ComboError")


def test_stdlib_only():
    assert combo.stdlib_only() is True
