"""Tests for def_extra_15 (certificate transparency mock)."""
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


m = _load("def_extra_15")

CERT = "sha256:cert123"


def _enforcer():
    return m.CTEnforcer({"log-a": b"ka", "log-b": b"kb"}, quorum=2)


def test_quorum_met():
    enf = _enforcer()
    scts = [enf.issue_sct("log-a", CERT), enf.issue_sct("log-b", CERT)]
    ok, reason = enf.verify_quorum(CERT, scts)
    assert ok is True, reason


def test_below_quorum_rejected():
    enf = _enforcer()
    ok, _ = enf.verify_quorum(CERT, [enf.issue_sct("log-a", CERT)])
    assert ok is False


def test_unknown_log_ignored():
    enf = _enforcer()
    rogue = m.SCT("log-evil", CERT, "deadbeef")
    ok, _ = enf.verify_quorum(CERT, [enf.issue_sct("log-a", CERT), rogue])
    assert ok is False


def test_wrong_cert_rejected():
    enf = _enforcer()
    other = enf.issue_sct("log-b", "sha256:other")
    ok, _ = enf.verify_quorum(CERT, [enf.issue_sct("log-a", CERT), other])
    assert ok is False


def test_version_pin():
    assert m.DEF_EXTRA_15_VERSION == "def-extra-15.v1"
    assert m.SCHEMA_PIN == "northstar.def-extra-15.v1"
