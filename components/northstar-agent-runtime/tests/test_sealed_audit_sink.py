"""Sealed audit sink: real integration test (no stubs for the wiring).

Proves: PermissionEngine(audit_sink=SealedAuditSink(ledger)) seals
real gate decisions into a forward-secure ledger, and the chain
verifies.  This is production wiring, not a mock.
"""

import importlib.util
import os
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


perm = _load("permissions")
fsl = _load("forward_seal_ledger")
sas = _load("sealed_audit_sink")


def _engine_with_sealed_sink():
    initial_key = os.urandom(32)
    checkpoint_key = os.urandom(32)
    ledger = fsl.ForwardSealLedger(initial_key, checkpoint_key)
    sink = sas.SealedAuditSink(ledger)
    engine = perm.PermissionEngine(audit_sink=sink)
    return engine, ledger, sink, initial_key, checkpoint_key


def test_gate_decision_lands_sealed():
    engine, ledger, sink, initial_key, checkpoint_key = _engine_with_sealed_sink()
    decision = engine.evaluate("read_file", kind="read", mutating=False)
    assert decision.allowed is True
    assert sink.sealed_count == 1
    assert len(ledger) == 1
    r = ledger.record(1)
    assert r.event[0][1] == "permission-permission.allow"
    assert r.event[7][1] == "permission.allow"
    # Chain verifies.
    report = ledger.verify(initial_key, checkpoint_key)
    assert report["records_verified"] == 1
    assert report["forward_secure"] is True


def test_multiple_decisions_chain():
    engine, ledger, sink, initial_key, checkpoint_key = _engine_with_sealed_sink()
    for tool in ("read_file", "write_file", "exec_cmd"):
        engine.evaluate(tool, kind="read", mutating=False)
    assert sink.sealed_count == 3
    assert len(ledger) == 3
    # Hash-chained.
    for s in range(2, 4):
        assert ledger.record(s).prev_hash == ledger.record(s - 1).record_hash
    report = ledger.verify(initial_key, checkpoint_key)
    assert report["records_verified"] == 3


def test_deny_also_sealed():
    engine, ledger, sink, initial_key, checkpoint_key = _engine_with_sealed_sink()
    # Try something likely to be denied (mutating without approval).
    decision = engine.evaluate("delete_db", kind="write", mutating=True)
    # Whether allowed or denied, the audit must have fired.
    assert sink.sealed_count >= 1
    r = ledger.record(1)
    assert r.event[7][1] in ("permission.allow", "permission.deny")


def test_sink_fail_closed_on_garbage():
    _, ledger, sink, _, _ = _engine_with_sealed_sink()
    with pytest.raises(sas.SealedAuditSinkError):
        sink({"no": "event"})
    with pytest.raises(sas.SealedAuditSinkError):
        sink("garbage")  # type: ignore[arg-type]
    assert sink.sealed_count == 0
    assert len(ledger) == 0


def test_sealed_sink_module_self_check():
    assert sas.stdlib_only() is True
    assert sas.SEALED_AUDIT_SINK_VERSION == "sealed-audit-sink.v1"
    assert sas.NULL_PIN == "sha256:" + "00" * 32
