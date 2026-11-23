"""Command registry tests."""

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


cr = _load("command_registry")


def test_automatic():
    r = cr.CommandRegistry()
    r.register(cr.CommandSpec("cmd", cr.AutonomyLevel.AUTOMATIC))
    ok, _ = r.check("cmd")
    assert ok is True


def test_approval_required_denied():
    r = cr.CommandRegistry()
    r.register(cr.CommandSpec("cmd", cr.AutonomyLevel.APPROVAL_REQUIRED))
    ok, _ = r.check("cmd")
    assert ok is False


def test_preauth():
    r = cr.CommandRegistry()
    r.register(cr.CommandSpec("cmd", cr.AutonomyLevel.APPROVAL_REQUIRED))
    r.grant_preauth(1)
    ok, _ = r.check("cmd")
    assert ok is True
    assert r.pre_auth_remaining == 0
    ok, _ = r.check("cmd")
    assert ok is False


def test_human_only():
    r = cr.CommandRegistry()
    r.register(cr.CommandSpec("cmd", cr.AutonomyLevel.HUMAN_ONLY))
    r.grant_preauth(10)
    ok, _ = r.check("cmd")
    assert ok is False  # pre-auth doesn't help
    ok, _ = r.check("cmd", human_approved=True)
    assert ok is True


def test_unknown_denied():
    r = cr.CommandRegistry()
    ok, reason = r.check("nope")
    assert ok is False
    assert "unknown" in reason


def test_grant_rejects_negative():
    r = cr.CommandRegistry()
    with pytest.raises(cr.RegistryError):
        r.grant_preauth(-1)


def test_stdlib_only():
    assert cr.stdlib_only() is True


def test_version_pin():
    assert cr.CMD_REGISTRY_VERSION == "command-registry.v1"
