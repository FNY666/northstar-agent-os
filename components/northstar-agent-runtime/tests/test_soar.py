"""Tests for the SOAR decision ledger (Simulated)."""

import ast
import subprocess
import sys
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "soar.py"
PIN = "sha256:" + "ab" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("soar", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["soar"] = module
    spec.loader.exec_module(module)
    return module


soar = _load()


# 1. version/schema pins + vocabulary pins
def test_version_and_schema_pins():
    assert soar.SOAR_VERSION == "soar.v1"
    assert soar.SCHEMA_PIN == "northstar.soar.v1"
    assert soar.STEPS == (
        "isolate-host",
        "block-ip",
        "disable-account",
        "quarantine-file",
        "collect-logs",
        "revoke-token",
        "notify-analyst",
        "escalate",
        "patch",
        "reboot",
    )
    assert soar.TRIGGERS == (
        "alert-firing",
        "case-created",
        "threat-intel-match",
        "manual",
        "scheduled",
    )
    assert soar.OUTCOMES == ("success", "failed", "skipped")
    assert soar.RETIRE_REASONS == ("manual", "superseded", "deprecated", "policy-change")
    assert soar.AUDIT_KINDS == (
        "playbook-registered",
        "playbook-retired",
        "executed",
        "rejected",
    )


# 2. stdlib-only AST check
def test_stdlib_only():
    tree = ast.parse(MOD.read_text())
    allowed = {
        "hashlib",
        "json",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
        "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert node.module is None or node.module.split(".")[0] in allowed, node.module


# 3. playbook roundtrip + verify + frozen-ness
def test_playbook_roundtrip():
    s = soar.SOAR()
    rec = s.playbook("pb-1", 1, steps=("isolate-host", "block-ip"), trigger="alert-firing")
    assert rec.playbook_id == "pb-1"
    assert rec.trigger == "alert-firing"
    assert rec.steps == ("isolate-host", "block-ip")
    assert rec.verify()
    d = rec.as_dict()
    assert d["schema"] == soar.SCHEMA_PIN
    with pytest.raises(Exception):
        rec.playbook_id = "other"  # type: ignore


# 4. playbook bad-input table + seq-burn + rejected-row accounting
def test_playbook_bad_inputs():
    s = soar.SOAR()
    seq = 1
    n_rejected = 0
    bad = [
        ("", ("isolate-host",), "manual"),  # empty id
        (123, ("isolate-host",), "manual"),  # non-str id
        ("pb-a", (), "manual"),  # empty steps
        ("pb-a", "isolate-host", "manual"),  # steps not a tuple
        ("pb-a", ("nuke-everything",), "manual"),  # unknown step
        ("pb-a", ("isolate-host", "isolate-host"), "manual"),  # duplicate step
        ("pb-a", ("isolate-host",), "alien-signal"),  # bad trigger
    ]
    for pb_id, steps, trigger in bad:
        with pytest.raises(soar.SoARError):
            s.playbook(pb_id, seq, steps=steps, trigger=trigger)
        n_rejected += 1
        seq += 1
    # duplicate refusal
    s.playbook("pb-dup", seq, steps=("isolate-host",), trigger="manual")
    seq += 1
    with pytest.raises(soar.DuplicatePlaybookError):
        s.playbook("pb-dup", seq, steps=("isolate-host",), trigger="manual")
    n_rejected += 1
    rows = s.audit_log(0)
    rejected = [r for r in rows if r["kind"] == "rejected"]
    assert len(rejected) == n_rejected
    assert all(r["schema"] == "audit.ndjson/1" for r in rows)


# 5. retire terminality + id never recycled
def test_retire_terminality():
    s = soar.SOAR()
    s.playbook("pb-r", 1, steps=("escalate",), trigger="manual")
    rec = s.retire_playbook("pb-r", 2, reason="deprecated")
    assert rec.verify()
    assert s.is_retired("pb-r", 0)
    with pytest.raises(soar.RetiredPlaybookError):
        s.retire_playbook("pb-r", 3)
    with pytest.raises(soar.RetiredPlaybookError):
        s.playbook("pb-r", 4, steps=("escalate",), trigger="manual")
    with pytest.raises(soar.RetiredPlaybookError):
        s.execute("pb-r", "case-x", 5)
    with pytest.raises(soar.UnknownPlaybookError):
        s.retire_playbook("pb-nope", 6)
    with pytest.raises(soar.BadReasonError):
        s.retire_playbook("pb-r", 7, reason="vibes")
    assert s.retired_ids(0) == ("pb-r",)


# 6. execute roundtrip + minted ids + verify
def test_execute_roundtrip():
    s = soar.SOAR()
    s.playbook("pb-e", 1, steps=("isolate-host", "block-ip"), trigger="case-created")
    exe = s.execute(
        "pb-e", "case-1", 2,
        step_outcomes=(("isolate-host", "success"), ("block-ip", "failed")),
        duration_sec=300,
    )
    assert exe.execution_id == "exe-1"
    assert exe.verify()
    assert exe.duration_sec == 300
    exe2 = s.execute("pb-e", "case-1", 3)
    assert exe2.execution_id == "exe-2"
    assert exe2.step_outcomes == ()
    assert s.executions_for_case("case-1", 0) == ("exe-1", "exe-2")
    assert s.executions_for_playbook("pb-e", 0) == ("exe-1", "exe-2")
    with pytest.raises(soar.UnknownExecutionError):
        s.execution_record("exe-99", 0)


# 7. execute bad-input table + seq-burn
def test_execute_bad_inputs():
    s = soar.SOAR()
    s.playbook("pb-x", 1, steps=("isolate-host", "reboot"), trigger="manual")
    seq = 2
    n_rejected = 0
    cases = [
        ("pb-nope", "case-1", 2, (), 0),  # unknown playbook
        ("pb-x", "", 2, (), 0),  # empty case id
        ("pb-x", "case-1", 2, "not-a-tuple", 0),  # outcomes not a tuple
        ("pb-x", "case-1", 2, (("reboot",),), 0),  # malformed pair
        ("pb-x", "case-1", 2, (("nuke-everything", "success"),), 0),  # step not in STEPS
        ("pb-x", "case-1", 2, (("block-ip", "success"),), 0),  # step not in this playbook
        ("pb-x", "case-1", 2, (("reboot", "reboot", "success"),), 0),  # 3-tuple pair
        ("pb-x", "case-1", 2, (("reboot", "success"), ("reboot", "failed")), 0),  # duplicate step
        ("pb-x", "case-1", 2, (("reboot", "maybe"),), 0),  # bad outcome
        ("pb-x", "case-1", 2, (), -1),  # negative duration
        ("pb-x", "case-1", 2, (), True),  # bool duration
        ("pb-x", "case-1", 2, (), "30"),  # str duration
    ]
    for pb, case, _, outcomes, dur in cases:
        with pytest.raises(soar.SoARError):
            s.execute(pb, case, seq, step_outcomes=outcomes, duration_sec=dur)
        n_rejected += 1
        seq += 1
    rows = s.audit_log(0)
    rejected = [r for r in rows if r["kind"] == "rejected"]
    assert len(rejected) == n_rejected


# 8. measure math + verify + tamper breaks verify
def test_measure_math():
    s = soar.SOAR()
    s.playbook("pb-m", 1, steps=("isolate-host", "block-ip", "notify-analyst"), trigger="scheduled")
    s.execute(
        "pb-m", "case-9", 2,
        step_outcomes=(("isolate-host", "success"), ("block-ip", "failed")),
        duration_sec=120,
    )
    s.execute(
        "pb-m", "case-9", 3,
        step_outcomes=(("notify-analyst", "skipped"),),
        duration_sec=60,
    )
    report = s.measure("case-9", 0)
    assert report.n_executions == 2
    assert report.total_steps == 3
    assert report.successes == 1
    assert report.failures == 1
    assert report.skips == 1
    assert report.declared_duration_sec == 180
    assert report.verify()
    object.__setattr__(report, "successes", 99)
    assert not report.verify()


# 9. measure pure-read semantics + unknown case as data
def test_measure_read_purity():
    s = soar.SOAR()
    s.playbook("pb-p", 1, steps=("escalate",), trigger="manual")
    s.execute("pb-p", "case-p", 2, duration_sec=10)
    before = len(s.audit_log(0))
    r1 = s.measure("case-p", 0)
    r2 = s.measure("case-p", 0)
    assert r1 == r2
    assert len(s.audit_log(0)) == before
    empty = s.measure("case-empty", 0)
    assert empty.n_executions == 0 and empty.total_steps == 0
    assert empty.declared_duration_sec == 0
    assert empty.verify()
    with pytest.raises(soar.SeqOrderError):
        s.measure("case-p", -1)


# 10. seq discipline: rewinds raise bare with no consumption
def test_seq_discipline():
    s = soar.SOAR()
    s.playbook("pb-s", 1, steps=("patch",), trigger="manual")
    with pytest.raises(soar.SeqOrderError):
        s.playbook("pb-s2", 1, steps=("patch",), trigger="manual")  # rewind
    with pytest.raises(soar.SeqOrderError):
        s.playbook("pb-s3", True, steps=("patch",), trigger="manual")
    with pytest.raises(soar.SeqOrderError):
        s.playbook("pb-s3", "2", steps=("patch",), trigger="manual")
    rows = s.audit_log(0)
    assert not [r for r in rows if r["kind"] == "rejected"]
    s.execute("pb-s", "case-s", 2)  # seq still free
    assert s.execution_ids(0) == ("exe-1",)


# 11. audit shapes + leak ban + bad kind
def test_audit_shapes_and_leak_ban():
    s = soar.SOAR()
    row = soar.soar_audit_event("playbook-registered", 1, playbook_id="pb-a")
    assert row["schema"] == "audit.ndjson/1"
    assert row["kind"] == "playbook-registered"
    assert row["seq"] == 1
    with pytest.raises(soar.AuditKindError):
        soar.soar_audit_event("bogus-kind", 1)
    with pytest.raises(soar.AuditKindError):
        soar.soar_audit_event("executed", 1, payload="x")
    with pytest.raises(soar.AuditKindError):
        soar.soar_audit_event("executed", 1, script="rm -rf")
    with pytest.raises(soar.SeqOrderError):
        soar.soar_audit_event("executed", -1)


# 12. stats + views
def test_stats_and_views():
    s = soar.SOAR()
    s.playbook("pb-v", 1, steps=("patch",), trigger="manual")
    s.playbook("pb-w", 2, steps=("reboot",), trigger="manual")
    s.execute("pb-v", "case-v", 3, duration_sec=5)
    st = s.stats(0)
    assert st["playbooks"] == 2
    assert st["executions"] == 1
    assert st["cases"] == 1
    assert st["retired"] == 0
    assert st["audit_rows"] == 3
    assert s.playbook_ids(0) == ("pb-v", "pb-w")
    assert s.playbook_record("pb-v", 0).trigger == "manual"
    assert s.executions_for_case("case-none", 0) == ()
    with pytest.raises(soar.UnknownPlaybookError):
        s.executions_for_playbook("pb-nope", 0)
    with pytest.raises(soar.UnknownPlaybookError):
        s.playbook_record("pb-nope", 0)


# 13. cross-instance digest determinism
def test_cross_instance_determinism():
    a = soar.SOAR()
    b = soar.SOAR()
    ra = a.playbook("pb-det", 1, steps=("patch", "reboot"), trigger="scheduled")
    rb = b.playbook("pb-det", 1, steps=("patch", "reboot"), trigger="scheduled")
    assert ra.digest == rb.digest
    ea = a.execute("pb-det", "case-det", 2, step_outcomes=(("patch", "success"),), duration_sec=7)
    eb = b.execute("pb-det", "case-det", 2, step_outcomes=(("patch", "success"),), duration_sec=7)
    assert ea.digest == eb.digest
    ma = a.measure("case-det", 0)
    mb = b.measure("case-det", 0)
    assert ma.digest == mb.digest


# 14. frozen-ness + concurrency smoke
def test_frozen_and_concurrency():
    import threading

    s = soar.SOAR()
    s.playbook("pb-c", 1, steps=("escalate",), trigger="manual")
    exe = s.execute("pb-c", "case-c", 2)
    rec = s.playbook_record("pb-c", 0)
    for frozen in (rec, exe):
        with pytest.raises(Exception):
            frozen.digest = "x"  # type: ignore
    errors = []

    def reader():
        try:
            for _ in range(50):
                s.measure("case-c", 0)
                s.stats(0)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors


# 15. main() subprocess check + standalone /tmp import
def test_main_subprocess():
    result = subprocess.run(
        [sys.executable, str(MOD)], capture_output=True, text=True, cwd="/tmp"
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "soar OK: playbook, execute, measure, retire, pins, audit"
