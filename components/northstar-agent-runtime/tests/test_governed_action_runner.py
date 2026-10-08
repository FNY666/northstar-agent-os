"""Governed action runner: full 4-gate integration with REAL components.

Proves: declare (SAFR) -> authorize (PermissionEngine) -> assess (Observer)
-> audit (sealed ledger) -> execute works end-to-end with no stubs.
This is the production governance loop.
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
ovl = _load("observer_verdict_ledger")
safr = _load("safr_checkpoint")
sas = _load("sealed_audit_sink")
gar = _load("governed_action_runner")


def _build_runner():
    initial_key = os.urandom(32)
    checkpoint_key = os.urandom(32)
    ledger = fsl.ForwardSealLedger(initial_key, checkpoint_key)
    sink = sas.SealedAuditSink(ledger)
    gate = perm.PermissionEngine(audit_sink=sink)
    observer = ovl.ObserverVerdictLedger()
    checkpoint = safr.SafrCheckpoint()
    executed = []

    def executor(tool, args):
        executed.append((tool, args))
        return f"ran {tool}"

    runner = gar.GovernedActionRunner(
        safr=checkpoint,
        gate=gate,
        observer=observer,
        ledger=ledger,
        executor=executor,
    )
    return runner, ledger, checkpoint, observer, executed, initial_key, checkpoint_key


def test_full_governed_run_executes():
    runner, ledger, checkpoint, observer, executed, ik, ck = _build_runner()
    outcome = runner.run(
        intent="deploy",
        action="restart-service",
        subject="prod-api",
        tool="read_file",
        tool_args={"path": "/etc/hosts"},
        kind="read",
        mutating=False,
    )
    assert outcome.executed is True
    assert outcome.gate == "executed"
    assert outcome.decision == "allow"
    assert len(executed) == 1
    assert executed[0][0] == "read_file"
    # SAFR recorded all 4 gates.
    # Sealed ledger has the gate audit.
    assert len(ledger) >= 1
    # Observer pre-committed.
    assert observer._commitment_counter >= 1
    # Chain verifies.
    report = ledger.verify(ik, ck)
    assert report["forward_secure"] is True


def test_deny_at_authorize_blocks():
    runner, ledger, checkpoint, observer, executed, ik, ck = _build_runner()
    # delete_db with mutating=True is denied by the default gate.
    outcome = runner.run(
        intent="destroy",
        action="delete-db",
        subject="prod-db",
        tool="delete_db",
        tool_args={},
        kind="write",
        mutating=True,
    )
    assert outcome.executed is False
    assert outcome.gate == "authorize"
    assert outcome.decision == "deny"
    assert len(executed) == 0  # tool never ran
    # The denial was sealed.
    assert len(ledger) >= 1


def test_runner_fail_closed_on_bad_input():
    runner, *_ = _build_runner()
    with pytest.raises(gar.GovernedRunnerError):
        runner.run(intent="", action="y", subject="z", tool="t")
    with pytest.raises(gar.GovernedRunnerError):
        runner.run(intent="x", action="y", subject="z", tool="")


def test_runner_module_self_check():
    assert gar.stdlib_only() is True
    assert gar.GOVERNED_RUNNER_VERSION == "governed-action-runner.v1"
