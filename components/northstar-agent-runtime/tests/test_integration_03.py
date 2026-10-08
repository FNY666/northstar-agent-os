"""Integration 03 tests."""

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


dv = _load("deterministic_veto")
sv = _load("stateful_veto")
i03 = _load("integration_03")


def _layered():
    lv = i03.LayeredVeto()
    lv.add_rule("no_broad", dv.Consequence.IRREVERSIBLE_BROAD)
    return lv


def test_vetoed_and_recorded():
    lv = _layered()
    allowed, reason = lv.decide(
        "s1", "rm", dv.Consequence.IRREVERSIBLE_BROAD
    )
    assert allowed is False
    assert "vetoed" in reason
    assert lv.stateful.risk_score("s1") == 10


def test_rate_limited_after_retries():
    lv = _layered()
    for _ in range(3):
        lv.decide("s1", "rm", dv.Consequence.IRREVERSIBLE_BROAD)
    allowed, reason = lv.decide(
        "s1", "rm", dv.Consequence.IRREVERSIBLE_BROAD
    )
    assert allowed is False
    assert "rate-limited" in reason


def test_allowed_reversible():
    lv = _layered()
    allowed, _ = lv.decide("s1", "read", dv.Consequence.REVERSIBLE_LOW)
    assert allowed is True


def test_human_override_bypasses():
    lv = _layered()
    allowed, _ = lv.decide(
        "s1", "rm", dv.Consequence.IRREVERSIBLE_BROAD,
        human_override=True,
    )
    assert allowed is True


def test_version_pin():
    assert i03.INTEGRATION_03_VERSION == "integration-03.v1"
    assert i03.stdlib_only() is True
