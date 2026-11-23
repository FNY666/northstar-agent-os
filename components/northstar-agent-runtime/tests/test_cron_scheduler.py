"""Targeted tests for cron_scheduler (15 tests)."""

import ast
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
MODULE = HERE.parent / "cron_scheduler.py"

sys.path.insert(0, str(HERE.parent))

from cron_scheduler import (  # noqa: E402
    AUDIT_SCHEMA,
    CRON_SCHEDULER_SCHEMA,
    CRON_SCHEDULER_VERSION,
    SOURCE_DUE,
    SOURCE_TRIGGER,
    VERDICT_EXHAUSTED,
    VERDICT_FIRED,
    VERDICT_PAUSED,
    VERDICT_SKIPPED,
    BadCronExprError,
    BadCronIdError,
    BadFireBudgetError,
    BadOverlapError,
    BadReasonError,
    CancelledCronError,
    CronExpr,
    CronScheduler,
    CronSchedulerError,
    DuplicateCronError,
    RunStateError,
    SeqOrderError,
    UnknownCronError,
    cron_scheduler_audit_event,
)


def test_version_schema_pins():
    assert CRON_SCHEDULER_VERSION == "cron-scheduler.v1"
    assert CRON_SCHEDULER_SCHEMA == "northstar.cron-scheduler.v1"
    assert AUDIT_SCHEMA == "audit.ndjson/1"


def test_stdlib_only():
    tree = ast.parse(MODULE.read_text())
    allowed = {
        "hashlib",
        "threading",
        "time",
        "dataclasses",
        "typing",
        "__future__",
    }
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.level == 0:
                imported.add(node.module.split(".")[0])
    # canonical_json is imported lazily inside a try/except fallback.
    assert imported - allowed <= {"json", "northstar_agent_runtime", "canonical_json"}


def test_schedule_roundtrip_and_verify():
    cs = CronScheduler()
    rec = cs.schedule("nightly", "30 2 * * *", 1)
    assert rec.verify()
    assert rec.cron_id == "nightly"
    assert rec.expression == "30 2 * * *"
    assert rec.expr_digest.startswith("sha256:")
    assert cs.schedule_record("nightly") == rec
    assert cs.schedule_ids() == ("nightly",)
    assert cs.status("nightly") == "active"


def test_schedule_bad_inputs_consume_seq():
    cs = CronScheduler()
    cs.schedule("a", "* * * * *", 1)
    with pytest.raises(DuplicateCronError):
        cs.schedule("a", "* * * * *", 2)
    for i, bad_id in enumerate(["", "   ", "a b", 123, None], start=10):
        with pytest.raises(BadCronIdError):
            cs.schedule(bad_id, "* * * * *", i)
    with pytest.raises(BadFireBudgetError):
        cs.schedule("b", "* * * * *", 20, max_fires=-1)
    with pytest.raises(BadFireBudgetError):
        cs.schedule("b", "* * * * *", 21, max_fires=True)
    with pytest.raises(BadOverlapError):
        cs.schedule("b", "* * * * *", 22, overlap="sometimes")
    # Seq order: failed mutations consumed their seqs.
    with pytest.raises(SeqOrderError):
        cs.schedule("b", "* * * * *", 22)
    kinds = [e["kind"] for e in cs.audit_log()]
    assert "cron.rejected" in kinds


def test_bad_cron_expressions():
    bad = [
        "",
        "* * * *",  # 4 fields
        "* * * * * *",  # 6 fields
        "60 * * * *",  # minute out of range
        "* 24 * * *",  # hour out of range
        "* * 0 * *",  # dom out of range
        "* * * 13 *",  # month out of range
        "* * * * 8",  # dow out of range
        "*/0 * * * *",  # bad step
        "5-2 * * * *",  # reversed range
        "abc * * * *",  # garbage
        "*, * * * *",  # empty token
    ]
    for i, expr in enumerate(bad, start=1):
        cs = CronScheduler()
        with pytest.raises(BadCronExprError):
            cs.schedule(f"job{i}", expr, 1)
    with pytest.raises(BadCronExprError):
        CronExpr(123)


def test_cron_matcher_semantics():
    # 2021-01-01T00:00:00Z is a Friday.
    base = 1609459200
    assert CronExpr("0 0 1 1 *").matches(base)  # midnight Jan 1
    assert not CronExpr("0 0 1 1 *").matches(base + 60)
    assert CronExpr("*/15 * * * *").matches(base + 15 * 60)
    assert not CronExpr("*/15 * * * *").matches(base + 60)
    assert CronExpr("0,30 9-17 * * 1-5").matches(base + 9 * 3600 + 30 * 60)
    assert not CronExpr("0,30 9-17 * * 1-5").matches(base + 18 * 3600)
    # dow 7 == Sunday.
    sunday = base + 2 * 86400  # 2021-01-03, Sunday
    assert CronExpr("0 0 * * 7").matches(sunday)
    assert CronExpr("0 0 * * 0").matches(sunday)
    # dom/dow OR rule: Jan 1 is the 1st AND a Friday.
    assert CronExpr("0 0 1 * 5").matches(base)
    # Neither matches: 2nd of month, not Friday.
    assert not CronExpr("0 0 2 * 3").matches(base)
    # Digest is over parsed sets, not the raw string.
    assert CronExpr("0 0 * * 0").digest() == CronExpr("0 0 * * 7").digest()


def test_trigger_roundtrip_and_fire_count():
    cs = CronScheduler()
    cs.schedule("t", "* * * * *", 1)
    fire = cs.trigger("t", 2)
    assert fire.verify()
    assert fire.verdict == VERDICT_FIRED
    assert fire.source == SOURCE_TRIGGER
    assert fire.fire_no == 1
    assert cs.fire_count("t") == 1
    fire2 = cs.trigger("t", 3)
    assert fire2.fire_no == 2


def test_trigger_unknown_and_cancelled():
    cs = CronScheduler()
    with pytest.raises(UnknownCronError):
        cs.trigger("nope", 1)
    cs.schedule("c", "* * * * *", 2)
    cs.cancel("c", 3, "manual")
    with pytest.raises(CancelledCronError):
        cs.trigger("c", 4)


def test_overlap_skip_verdict_is_data():
    cs = CronScheduler()
    cs.schedule("o", "* * * * *", 1, overlap="skip")
    cs.begin_run("o", 2)
    skipped = cs.trigger("o", 3)
    assert skipped.verdict == VERDICT_SKIPPED  # data, not raised
    cs.end_run("o", 4)
    fired = cs.trigger("o", 5)
    assert fired.verdict == VERDICT_FIRED
    # overlap=allow always fires.
    cs2 = CronScheduler()
    cs2.schedule("o2", "* * * * *", 1, overlap="allow")
    cs2.begin_run("o2", 2)
    assert cs2.trigger("o2", 3).verdict == VERDICT_FIRED


def test_max_fires_exhaustion():
    cs = CronScheduler()
    cs.schedule("m", "* * * * *", 1, max_fires=2)
    assert cs.trigger("m", 2).verdict == VERDICT_FIRED
    assert cs.trigger("m", 3).verdict == VERDICT_FIRED
    exhausted = cs.trigger("m", 4)
    assert exhausted.verdict == VERDICT_EXHAUSTED
    # due() also respects the budget.
    rep = cs.due(1609459200, 5)
    assert rep.verify() and rep.entries == ()


def test_pause_resume_lifecycle():
    cs = CronScheduler()
    cs.schedule("p", "* * * * *", 1)
    cs.pause("p", 2)
    assert cs.status("p") == "paused"
    assert cs.trigger("p", 3).verdict == VERDICT_PAUSED
    with pytest.raises(RunStateError):
        cs.pause("p", 4)  # already paused
    cs.resume("p", 5)
    assert cs.status("p") == "active"
    assert cs.trigger("p", 6).verdict == VERDICT_FIRED
    with pytest.raises(RunStateError):
        cs.resume("p", 7)  # not paused
    cs.pause("p", 8)
    with pytest.raises(RunStateError):
        cs.begin_run("p", 9)  # paused refuses run start


def test_cancel_terminal_and_reasons():
    cs = CronScheduler()
    cs.schedule("x", "* * * * *", 1)
    rec = cs.cancel("x", 2, "superseded")
    assert rec.verify() and rec.reason == "superseded"
    assert cs.status("x") == "cancelled"
    for i, bad in enumerate(["vibes", "", 123], start=1):
        cs2 = CronScheduler()
        cs2.schedule(f"y{i}", "* * * * *", 1)
        with pytest.raises(BadReasonError):
            cs2.cancel(f"y{i}", 2, bad)
    with pytest.raises(CancelledCronError):
        cs.cancel("x", 5)  # already cancelled
    with pytest.raises(CancelledCronError):
        cs.pause("x", 6)


def test_due_sweep_and_misfire():
    cs = CronScheduler()
    cs.schedule("every-minute", "* * * * *", 1)
    # Sweep two ticks; the second sweep skips one fire point.
    rep1 = cs.due(1609459200, 2)
    assert len(rep1.entries) == 1
    assert rep1.entries[0].fired and rep1.entries[0].misfired == 0
    rep2 = cs.due(1609459200 + 180, 3)  # jumped 3 minutes
    # Ticks are per-second and "* * * * *" matches every second, so all
    # 179 skipped ticks count as misfires (same tick semantics as the
    # sibling job_scheduler).
    assert len(rep2.entries) == 1
    assert rep2.entries[0].misfired == 179
    kinds = [e["kind"] for e in cs.audit_log()]
    assert "cron.misfired" in kinds
    assert "cron.fired" in kinds
    # A non-matching tick books no fire.
    cs2 = CronScheduler()
    cs2.schedule("noon", "0 12 * * *", 1)
    rep3 = cs2.due(1609459200, 2)  # midnight, not noon
    assert rep3.verify() and rep3.entries == ()


def test_audit_shapes_and_bad_kind():
    ev = cron_scheduler_audit_event(
        "cron.scheduled", {"cron_id": "a"}, 1
    )
    assert ev["schema"] == AUDIT_SCHEMA
    assert ev["module"] == CRON_SCHEDULER_VERSION
    assert ev["detail"]["cron_id"] == "a"
    with pytest.raises(CronSchedulerError):
        cron_scheduler_audit_event("nope", {}, 2)
    with pytest.raises(CronSchedulerError):
        cron_scheduler_audit_event(
            "cron.scheduled", {"payload": b"x"}, 3
        )
    kinds = {
        "cron.scheduled",
        "cron.triggered",
        "cron.cancelled",
        "cron.paused",
        "cron.resumed",
        "cron.fired",
        "cron.misfired",
        "cron.run-started",
        "cron.run-ended",
        "cron.rejected",
    }
    for kind in kinds:
        e = cron_scheduler_audit_event(kind, {}, 10)
        assert e["kind"] == kind


def test_views_stats_and_main():
    cs = CronScheduler()
    cs.schedule("a", "* * * * *", 1)
    cs.schedule("b", "0 * * * *", 2)
    cs.pause("b", 3)
    stats = cs.stats()
    assert stats["schedules"] == 2
    assert stats["active"] == 1 and stats["paused"] == 1
    assert stats["cancelled"] == 0
    assert stats["last_seq"] == 3
    assert cs.schedule_ids() == ("a", "b")
    with pytest.raises(UnknownCronError):
        cs.status("nope")
    result = subprocess.run(
        [sys.executable, str(MODULE)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert "cron-scheduler OK" in result.stdout
