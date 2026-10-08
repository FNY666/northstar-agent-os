"""Tripwire guardrails tests."""

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


def test_allow_when_clean():
    g = tw.TripwireGuard("test", lambda t, a: False)
    r = g.check("tool", {})
    assert r.outcome == tw.TripwireOutcome.ALLOW


def test_halt_on_violation():
    g = tw.TripwireGuard(
        "test", lambda t, a: True, on_violation=tw.TripwireOutcome.HALT
    )
    r = g.check("tool", {})
    assert r.outcome == tw.TripwireOutcome.HALT


def test_reject_content():
    g = tw.TripwireGuard(
        "test",
        lambda t, a: True,
        on_violation=tw.TripwireOutcome.REJECT_CONTENT,
        substitute_message="[blocked]",
    )
    r = g.check("tool", {})
    assert r.outcome == tw.TripwireOutcome.REJECT_CONTENT
    assert r.substitute_message == "[blocked]"


def test_advisory_allows_but_logs():
    g = tw.TripwireGuard(
        "test", lambda t, a: True, mode=tw.TripwireMode.ADVISORY
    )
    r = g.check("tool", {})
    assert r.outcome == tw.TripwireOutcome.ALLOW
    assert "advisory" in r.reason.lower()


def test_fail_closed_on_exception():
    def bad(t, a):
        raise ValueError("boom")

    g = tw.TripwireGuard("test", bad)
    r = g.check("tool", {})
    # Fail-closed: exception -> treated as violation -> HALT (default).
    assert r.outcome == tw.TripwireOutcome.HALT


def test_rejects_allow_as_violation_outcome():
    import pytest

    with pytest.raises(tw.TripwireError):
        tw.TripwireGuard(
            "test",
            lambda t, a: True,
            on_violation=tw.TripwireOutcome.ALLOW,
        )


def test_fired_count():
    g = tw.TripwireGuard("test", lambda t, a: True)
    assert g.fired_count == 0
    g.check("t", {})
    assert g.fired_count == 1


def test_stdlib_only():
    assert tw.stdlib_only() is True


def test_version_pin():
    assert tw.TRIPWIRE_VERSION == "tripwire-guardrails.v1"
