"""Tests for def_extra_13 (non-repudiation mock)."""
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


m = _load("def_extra_13")


def test_issue_verify_ok():
    auth = m.ReceiptAuthority(b"nr-key")
    receipt = auth.issue("alice", "deploy", "sha256:cfg", now=1000.0)
    ok, reason = auth.verify(receipt)
    assert ok is True, reason


def test_actor_swap_rejected():
    auth = m.ReceiptAuthority(b"nr-key")
    receipt = auth.issue("alice", "deploy", "sha256:cfg", now=1000.0)
    forged = m.Receipt("mallory", receipt.action, receipt.payload_hash, receipt.ts, receipt.mac)
    ok, _ = auth.verify(forged)
    assert ok is False


def test_action_swap_rejected():
    auth = m.ReceiptAuthority(b"nr-key")
    receipt = auth.issue("alice", "deploy", "sha256:cfg", now=1000.0)
    forged = m.Receipt(receipt.actor, "delete", receipt.payload_hash, receipt.ts, receipt.mac)
    ok, _ = auth.verify(forged)
    assert ok is False


def test_version_pin():
    assert m.DEF_EXTRA_13_VERSION == "def-extra-13.v1"
    assert m.SCHEMA_PIN == "northstar.def-extra-13.v1"
