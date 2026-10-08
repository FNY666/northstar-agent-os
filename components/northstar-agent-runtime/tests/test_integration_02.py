"""Integration 02 tests."""

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


tw = _load("tripwire_guardrails")
cg = _load("confidence_gate")
i02 = _load("integration_02")


def _gate():
    guard = tw.TripwireGuard(
        "no_evil",
        lambda t, a: t == "evil",
        on_violation=tw.TripwireOutcome.HALT,
    )
    return i02.CombinedGate(guard, cg.ConfidenceGate())


def test_halt_on_tripwire():
    d = _gate().check("evil", {}, 95, "low")
    assert d.decision == "halt"
    assert d.tripwire_outcome == "halt"


def test_allow_clean_high_confidence():
    d = _gate().check("read", {}, 95, "low")
    assert d.decision == "allow"
    assert d.confidence_action == "allow"


def test_escalate_maps_to_reject_content():
    d = _gate().check("read", {}, 60, "low")
    assert d.decision == "reject_content"


def test_observer_tier():
    d = _gate().check("read", {}, 80, "low")
    assert d.decision == "observer"


def test_low_confidence_halts():
    d = _gate().check("read", {}, 30, "low")
    assert d.decision == "halt"


def test_version_pin():
    assert i02.INTEGRATION_02_VERSION == "integration-02.v1"
    assert i02.stdlib_only() is True
