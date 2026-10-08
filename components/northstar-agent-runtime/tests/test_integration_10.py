"""Integration 10 tests."""

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


lh = _load("lifecycle_hooks")
cc = _load("canary_controller")
i10 = _load("integration_10")

FULL_BLOCKLIST = ["exec", "read_file", "send_email"]


def test_no_canary_routes_stable():
    ctrl = cc.CanaryController("v1")
    r = i10.GuardedCanaryRouter(ctrl, ["exec"])
    d = r.route("req-1")
    assert d.served_by == "stable"


def test_full_blocklist_routes_canary():
    ctrl = cc.CanaryController("v1")
    r = i10.GuardedCanaryRouter(ctrl, FULL_BLOCKLIST)
    r.deploy_canary("v2", 100.0)
    d = r.route("req-1")
    assert d.served_by == "canary"


def test_incomplete_blocklist_raises():
    ctrl = cc.CanaryController("v1")
    r = i10.GuardedCanaryRouter(ctrl, ["exec"])
    r.deploy_canary("v2", 100.0)
    with pytest.raises(i10.IntegrationError):
        r.route("req-1")


def test_empty_blocklist_rejected():
    ctrl = cc.CanaryController("v1")
    with pytest.raises(i10.IntegrationError):
        i10.GuardedCanaryRouter(ctrl, [])


def test_version_pin():
    assert i10.INTEGRATION_10_VERSION == "integration-10.v1"
    assert i10.stdlib_only() is True
