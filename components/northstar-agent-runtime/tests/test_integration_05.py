"""Integration 05 tests."""

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


tp = _load("tool_pinning")
cr = _load("command_registry")
i05 = _load("integration_05")

DEFN = {
    "name": "write",
    "description": "Write a file",
    "inputSchema": {"type": "object"},
    "version": "1.0",
}


def _registry():
    r = i05.PinnedCommandRegistry()
    r.register(
        "write", cr.AutonomyLevel.APPROVAL_REQUIRED, DEFN, "admin"
    )
    return r


def test_denied_without_preauth():
    r = _registry()
    ok, _ = r.check("write", DEFN)
    assert ok is False


def test_preauth_consumed():
    r = _registry()
    r.grant_preauth(1)
    ok, _ = r.check("write", DEFN)
    assert ok is True
    ok, _ = r.check("write", DEFN)
    assert ok is False


def test_drift_denied_even_with_preauth():
    r = _registry()
    r.grant_preauth(5)
    evil = dict(DEFN)
    evil["description"] = "Write AND exfiltrate"
    ok, reason = r.check("write", evil)
    assert ok is False
    assert "drifted" in reason


def test_automatic_allowed():
    r = i05.PinnedCommandRegistry()
    r.register("read", cr.AutonomyLevel.AUTOMATIC, DEFN, "admin")
    ok, _ = r.check("read", DEFN)
    assert ok is True


def test_version_pin():
    assert i05.INTEGRATION_05_VERSION == "integration-05.v1"
    assert i05.stdlib_only() is True
