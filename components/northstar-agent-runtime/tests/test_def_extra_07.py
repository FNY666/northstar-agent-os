"""Tests for def_extra_07 (step-up authentication mock)."""
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


m = _load("def_extra_07")


def _auth():
    return m.StepUpAuth(b"server-secret", ttl_s=60.0)


def test_issue_verify_ok():
    auth = _auth()
    cid, token = auth.issue("alice", now=1000.0)
    ok, reason = auth.verify(cid, "alice", token, now=1010.0)
    assert ok is True, reason


def test_replay_rejected():
    auth = _auth()
    cid, token = auth.issue("alice", now=1000.0)
    auth.verify(cid, "alice", token, now=1010.0)
    ok, reason = auth.verify(cid, "alice", token, now=1011.0)
    assert ok is False
    assert "used" in reason


def test_expired_rejected():
    auth = _auth()
    cid, token = auth.issue("alice", now=1000.0)
    ok, reason = auth.verify(cid, "alice", token, now=9999.0)
    assert ok is False
    assert "expired" in reason


def test_unknown_challenge_fail_closed():
    auth = _auth()
    ok, _ = auth.verify("ch-nope", "alice", "x", now=1010.0)
    assert ok is False


def test_version_pin():
    assert m.DEF_EXTRA_07_VERSION == "def-extra-07.v1"
    assert m.SCHEMA_PIN == "northstar.def-extra-07.v1"
