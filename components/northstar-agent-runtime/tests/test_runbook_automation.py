"""Tests for runbook_automation (Rundeck/Ansible-shaped bookkeeping)."""

import ast
import subprocess
import sys

import pytest

import runbook_automation as ra_mod
from runbook_automation import (
    RUNBOOK_AUTOMATION_VERSION,
    RUNBOOK_AUTOMATION_SCHEMA,
    AUDIT_SCHEMA,
    STEP_TYPES,
    ON_FAILURE_POLICIES,
    EXECUTION_KINDS,
    EXECUTION_STATUSES,
    RunbookAutomation,
    StepDeclaration,
    RunbookAutomationError,
    BadRunbookError,
    DuplicateRunbookError,
    UnknownRunbookError,
    BadStepError,
    UnknownExecutionError,
    BadRollbackError,
    BadScheduleError,
    DuplicateScheduleError,
    UnknownScheduleError,
    SeqOrderError,
    runbook_automation_audit_event,
)

STEPS = [
    {"step_id": "s1", "name": "build", "step_type": "shell"},
    {
        "step_id": "s2",
        "name": "deploy",
        "step_type": "script",
        "on_failure": "continue",
        "rollback_type": "script",
    },
]


def make(**kwargs):
    return RunbookAutomation(seed=kwargs.pop("seed", ""), **kwargs)


def defined(mod=None, steps=STEPS, rid="rb-1"):
    mod = mod or make()
    seqs = iter(range(1, 1000))
    record = mod.define(rid, "name", steps, next(seqs))
    return mod, record, seqs


# ---------------------------------------------------------------------------
# pins and stdlib-only
# ---------------------------------------------------------------------------


def test_version_schema_pins():
    assert RUNBOOK_AUTOMATION_VERSION == "runbook-automation.v1"
    assert RUNBOOK_AUTOMATION_SCHEMA == "northstar.runbook-automation.v1"
    assert AUDIT_SCHEMA == "audit.ndjson/1"
    assert set(STEP_TYPES) == {"shell", "http", "script", "approval", "noop"}
    assert set(ON_FAILURE_POLICIES) == {"stop", "continue"}
    assert set(EXECUTION_KINDS) == {"run", "rollback"}
    assert set(EXECUTION_STATUSES) == {"completed", "failed"}


def test_stdlib_only():
    tree = ast.parse(open(ra_mod.__file__).read())
    allowed = {
        "hashlib",
        "hmac",
        "re",
        "threading",
        "dataclasses",
        "typing",
        "json",
        "canonical_json",
    }
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imported.add(node.module.split(".")[0])
    assert imported <= allowed | {"__future__"}, imported


# ---------------------------------------------------------------------------
# define
# ---------------------------------------------------------------------------


def test_define_roundtrip_and_verify():
    mod, record, _ = defined()
    assert record.verify()
    assert record.runbook_id == "rb-1"
    assert [s.step_id for s in record.steps] == ["s1", "s2"]
    assert all(s.verify() for s in record.steps)
    assert mod.runbook("rb-1") is record
    assert mod.runbook_ids() == ["rb-1"]
    # cross-instance determinism: same seed -> same digests
    mod2, record2, _ = defined()
    assert record2.digest == record.digest


def test_define_bad_inputs():
    mod = make()
    seqs = iter(range(1, 1000))
    bad = [
        ("", "n", STEPS),
        ("rb", "", STEPS),
        ("rb", "n", []),
        ("rb", "n", [{"step_id": "s", "name": "n", "step_type": "bogus"}]),
        (
            "rb",
            "n",
            [
                {"step_id": "s", "name": "n", "step_type": "shell"},
                {"step_id": "s", "name": "m", "step_type": "shell"},
            ],
        ),
        ("rb", "n", [{"step_id": "s", "name": "n"}]),  # missing step_type
        (
            "rb",
            "n",
            [
                {
                    "step_id": "s",
                    "name": "n",
                    "step_type": "shell",
                    "on_failure": "sometimes",
                }
            ],
        ),
        ("rb", "n", "not-a-list"),
    ]
    for rid, name, steps in bad:
        with pytest.raises(RunbookAutomationError):
            mod.define(rid, name, steps, next(seqs))
    mod.define("dup", "a", STEPS, next(seqs))
    with pytest.raises(DuplicateRunbookError):
        mod.define("dup", "b", STEPS, next(seqs))


# ---------------------------------------------------------------------------
# execute
# ---------------------------------------------------------------------------


def test_execute_completed():
    mod, _, seqs = defined()
    run = mod.execute("rb-1", next(seqs), executor=lambda s, a: True)
    assert run.verify()
    assert run.kind == "run"
    assert run.status == "completed"
    assert run.failed_step_id == ""
    assert all(r.outcome and not r.skipped for r in run.results)
    assert all(r.verify() for r in run.results)
    assert mod.execution(run.execution_id) is run
    assert mod.executions_for("rb-1") == [run]


def test_execute_fail_fast_and_skipped():
    mod, _, seqs = defined()
    seen = []

    def fail_first(step, attempt):
        seen.append(step.step_id)
        return step.step_id != "s1"

    run = mod.execute("rb-1", next(seqs), executor=fail_first)
    assert run.status == "failed"
    assert run.failed_step_id == "s1"
    assert run.results[0].outcome is False
    assert run.results[0].skipped is False
    # s1 is on_failure=stop -> s2 booked as skipped, never handed to executor
    assert run.results[1].skipped is True
    assert seen == ["s1"]


def test_execute_on_failure_continue():
    mod, _, seqs = defined()
    run = mod.execute(
        "rb-1", next(seqs), executor=lambda s, a: s.step_id == "s1"
    )
    assert run.status == "failed"
    assert run.failed_step_id == "s2"
    assert run.results[1].outcome is False
    assert run.results[1].skipped is False  # continue: not skipped


def test_execute_raising_executor_is_failure():
    mod, _, seqs = defined()

    def boom(step, attempt):
        raise RuntimeError("executor exploded")

    run = mod.execute("rb-1", next(seqs), executor=boom)
    assert run.status == "failed"
    assert run.failed_step_id == "s1"


def test_execute_unknown_runbook():
    mod = make()
    with pytest.raises(UnknownRunbookError):
        mod.execute("nope", 1)
    with pytest.raises(BadRunbookError):
        mod.define("rb-1", "n", STEPS, 2)
        mod.execute("rb-1", 3, executor="not-callable")


# ---------------------------------------------------------------------------
# rollback
# ---------------------------------------------------------------------------


def test_rollback_compensating_run():
    mod, _, seqs = defined()
    ok = mod.execute("rb-1", next(seqs), executor=lambda s, a: True)
    rbk = mod.rollback(ok.execution_id, next(seqs))
    assert rbk.verify()
    assert rbk.kind == "rollback"
    assert rbk.rollback_of == ok.execution_id
    assert rbk.status == "completed"
    # reverse of completed steps, with rollback step types
    assert [r.step_id for r in rbk.results] == ["rb-s2", "rb-s1"]
    assert [r.step_type for r in rbk.results] == ["script", "noop"]
    assert mod.rollback_of(rbk.execution_id).execution_id == ok.execution_id


def test_rollback_only_compensates_completed_steps():
    mod, _, seqs = defined()
    # s1 fails (stop) -> only s1 never completed; nothing to compensate
    failed = mod.execute(
        "rb-1", next(seqs), executor=lambda s, a: s.step_id != "s1"
    )
    assert failed.status == "failed"
    rbk = mod.rollback(failed.execution_id, next(seqs))
    assert rbk.results == ()
    assert rbk.status == "completed"


def test_rollback_refusals():
    mod, _, seqs = defined()
    ok = mod.execute("rb-1", next(seqs), executor=lambda s, a: True)
    rbk = mod.rollback(ok.execution_id, next(seqs))
    with pytest.raises(BadRollbackError):
        mod.rollback(rbk.execution_id, next(seqs))  # rollback of rollback
    with pytest.raises(UnknownExecutionError):
        mod.rollback("exec-999", next(seqs))
    with pytest.raises(BadRollbackError):
        mod.rollback_of(ok.execution_id)  # not a rollback execution


# ---------------------------------------------------------------------------
# schedule
# ---------------------------------------------------------------------------


def test_schedule_roundtrip_unschedule():
    mod, _, seqs = defined()
    sch = mod.schedule("rb-1", "0 * * * *", next(seqs))
    assert sch.verify()
    assert sch.active is True
    assert mod.schedule_record(sch.schedule_id) is sch
    assert mod.active_schedule_ids() == [sch.schedule_id]
    retired = mod.unschedule(sch.schedule_id, next(seqs))
    assert retired.active is False
    assert mod.active_schedule_ids() == []
    with pytest.raises(DuplicateScheduleError):
        mod2, _, s2 = defined()
        mod2.schedule("rb-1", "0 * * * *", next(s2))
        mod2.schedule("rb-1", "0 * * * *", next(s2))
    with pytest.raises(BadScheduleError):
        mod.schedule("rb-1", "not a cron", next(seqs))
    with pytest.raises(UnknownScheduleError):
        mod.unschedule("sch-999", next(seqs))
    with pytest.raises(UnknownRunbookError):
        mod.schedule("nope", "0 * * * *", next(seqs))


# ---------------------------------------------------------------------------
# seq discipline, audit, main
# ---------------------------------------------------------------------------


def test_seq_discipline_and_failed_mutation_consumes_seq():
    mod = make()
    mod.define("rb-1", "n", STEPS, 5)
    with pytest.raises(SeqOrderError):
        mod.define("rb-2", "n", STEPS, 5)  # rewind: no seq consumed
    with pytest.raises(RunbookAutomationError):
        mod.define("rb-2", "n", STEPS, True)  # bool refused
    with pytest.raises(RunbookAutomationError):
        mod.define("rb-2", "n", STEPS, -1)  # negative refused
    # validation failure AFTER seq consumption burns the seq + books rejection
    with pytest.raises(BadRunbookError):
        mod.define("rb-3", "n", [], 6)
    record = mod.define("rb-2", "n", STEPS, 7)
    assert record.seq == 7
    kinds = [e["kind"] for e in mod.audit_log()]
    assert kinds.count("runbook.rejected") == 1


def test_audit_shapes_and_bad_kind():
    mod, record, seqs = defined()
    run = mod.execute("rb-1", next(seqs), executor=lambda s, a: True)
    rbk = mod.rollback(run.execution_id, next(seqs))
    sch = mod.schedule("rb-1", "*/5 * * * *", next(seqs))
    kinds = [e["kind"] for e in mod.audit_log()]
    for expected in (
        "runbook.defined",
        "runbook.executed",
        "runbook.rolled-back",
        "runbook.scheduled",
    ):
        assert expected in kinds
    for event in mod.audit_log():
        assert event["schema"] == AUDIT_SCHEMA
        assert event["module"] == "runbook_automation"
    with pytest.raises(RunbookAutomationError):
        runbook_automation_audit_event("bogus.kind", 99)
    # failed run emits a step-failed event
    mod2, _, s2 = defined()
    bad = mod2.execute("rb-1", next(s2), executor=lambda s, a: False)
    assert bad.status == "failed"
    assert "runbook.step-failed" in [e["kind"] for e in mod2.audit_log()]
    # stats view
    stats = mod.stats()
    assert stats["runbooks"] == 1
    assert stats["executions"] == 2
    assert stats["rollbacks"] == 1
    assert stats["schedules"] == 1


def test_main_self_check():
    result = subprocess.run(
        [sys.executable, ra_mod.__file__],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert "runbook-automation OK" in result.stdout
