"""Tests for crisis_management.py: declare / coordinate / report / standdown."""

import ast
import hashlib
import subprocess
import sys
from pathlib import Path

import pytest

import crisis_management as cm

HERE = Path(__file__).resolve().parent
MODULE = Path(__file__).resolve().parent.parent / "crisis_management.py"


def digest(seed: str) -> str:
    return "sha256:" + hashlib.sha256(seed.encode()).hexdigest()


def fresh(seq_start=1, crisis_id="CR-001", severity="severe"):
    ledger = cm.CrisisManagement()
    ledger.declare(crisis_id, severity, seq_start)
    return ledger


def test_version_and_schema_pins():
    assert cm.CRISIS_MANAGEMENT_VERSION == "crisis-management.v1"
    assert cm.CRISIS_MANAGEMENT_SCHEMA == "northstar.crisis-management.v1"


def test_stdlib_only():
    tree = ast.parse(MODULE.read_text())
    allowed = {
        "hashlib",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
        "canonical_json",
        "json",
        "sys",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


def test_declare_roundtrip_verify_and_frozen():
    ledger = fresh()
    record = ledger.declaration_record("CR-001", 2)
    assert record.crisis_id == "CR-001"
    assert record.severity == "severe"
    assert record.verify()
    assert ledger.crisis_ids(3) == ("CR-001",)
    with pytest.raises(Exception):
        record.severity = "minor"  # frozen dataclass


def test_declare_duplicate_and_bad_inputs_consume_seq():
    ledger = fresh()
    with pytest.raises(cm.DuplicateCrisisError):
        ledger.declare("CR-001", "major", 2)
    with pytest.raises(cm.BadSeverityError):
        ledger.declare("CR-002", "URGENT", 3)
    with pytest.raises(cm.BadCrisisError):
        ledger.declare("  ", "minor", 4)
    with pytest.raises(cm.BadCrisisError):
        ledger.declare(123, "minor", 5)  # type: ignore[arg-type]
    with pytest.raises(cm.BadDigestError):
        ledger.declare("CR-003", "minor", 6, declared_by_digest="raw text")
    rejected = [e for e in ledger.audit_log(7) if e["kind"] == cm.KIND_REJECTED]
    assert len(rejected) == 5
    assert ledger.stats(8)["declarations"] == 1


def test_declare_malformed_seq_and_rewind_raise_bare():
    ledger = fresh()
    for bad_seq in (True, "x", -1):
        with pytest.raises(cm.SeqOrderError):
            ledger.declare("CR-BAD", "minor", bad_seq)
    # rewind: seq not strictly greater -> bare raise, nothing consumed
    with pytest.raises(cm.SeqOrderError):
        ledger.declare("CR-002", "minor", 1)
    assert len(ledger.audit_log(2)) == 1  # only the successful declare


def test_coordinate_roundtrip_and_vocabulary():
    ledger = fresh()
    c1 = ledger.coordinate("CR-001", "activate-war-room", 2)
    c2 = ledger.coordinate(
        "CR-001", "notify-executives", 3, note_digest=digest("n")
    )
    assert c1.coordination_id != c2.coordination_id
    assert c1.verify() and c2.verify()
    history = ledger.coordination_history("CR-001", 4)
    assert [c.action for c in history] == [
        "activate-war-room",
        "notify-executives",
    ]
    # full action vocabulary accepted
    seq = 4
    for action in sorted(cm._ACTIONS):
        if action in ("activate-war-room", "notify-executives"):
            continue
        seq += 1
        rec = ledger.coordinate("CR-001", action, seq)
        assert rec.verify()


def test_coordinate_bad_inputs_consume_seq():
    ledger = fresh()
    with pytest.raises(cm.BadActionError):
        ledger.coordinate("CR-001", "call-the-president", 2)
    with pytest.raises(cm.UnknownCrisisError):
        ledger.coordinate("CR-NOPE", "freeze-changes", 3)
    with pytest.raises(cm.BadDigestError):
        ledger.coordinate("CR-001", "freeze-changes", 4, note_digest="nope")
    rejected = [e for e in ledger.audit_log(5) if e["kind"] == cm.KIND_REJECTED]
    assert len(rejected) == 3
    assert ledger.coordination_history("CR-001", 6) == ()


def test_report_roundtrip_and_status_vocabulary():
    ledger = fresh()
    r1 = ledger.report("CR-001", 2, report_status="ongoing")
    r2 = ledger.report(
        "CR-001", 3, report_status="stabilizing", situation_digest=digest("s")
    )
    assert r1.report_id != r2.report_id
    assert r1.verify() and r2.verify()
    reports = ledger.situation_reports("CR-001", 4)
    assert [r.report_status for r in reports] == ["ongoing", "stabilizing"]
    for status, seq in (("contained", 5), ("under-review", 6)):
        rec = ledger.report("CR-001", seq, report_status=status)
        assert rec.verify()
    with pytest.raises(cm.BadStatusError):
        ledger.report("CR-001", 7, report_status="all-good")


def test_report_unknown_crisis_and_post_standdown():
    ledger = fresh()
    with pytest.raises(cm.UnknownCrisisError):
        ledger.report("CR-NOPE", 2)
    ledger.standdown("CR-001", 3)
    with pytest.raises(cm.StoodDownCrisisError):
        ledger.report("CR-001", 4, report_status="ongoing")
    with pytest.raises(cm.StoodDownCrisisError):
        ledger.coordinate("CR-001", "engage-legal", 5)


def test_standdown_roundtrip_outcomes_and_verify():
    outcomes = ("resolved", "mitigated", "false-alarm", "superseded")
    for i, outcome in enumerate(outcomes):
        ledger = fresh(seq_start=1, crisis_id=f"CR-{100 + i}")
        rec = ledger.standdown(
            f"CR-{100 + i}", 2, outcome=outcome, note_digest=digest("n")
        )
        assert rec.verify()
        assert rec.outcome == outcome
        got = ledger.standdown_record(f"CR-{100 + i}", 3)
        assert got.outcome == outcome
    ledger.declare("CR-104", "minor", 3)
    with pytest.raises(cm.BadOutcomeError):
        ledger.standdown("CR-104", 4, outcome="whatever")


def test_standdown_terminality_id_never_recycled():
    ledger = fresh()
    ledger.coordinate("CR-001", "restore-service", 2)
    ledger.standdown("CR-001", 3, outcome="resolved")
    with pytest.raises(cm.StoodDownCrisisError):
        ledger.standdown("CR-001", 4)
    with pytest.raises(cm.StoodDownCrisisError):
        ledger.declare("CR-001", "minor", 5)
    status = ledger.status("CR-001", 6)
    assert status.stood_down and status.outcome == "resolved"
    assert status.coordination_count == 1


def test_view_read_purity_and_status_snapshot():
    ledger = fresh()
    ledger.coordinate("CR-001", "engage-pr", 2)
    ledger.report("CR-001", 3, report_status="stabilizing")
    status = ledger.status("CR-001", 4)
    assert status.declared and status.severity == "severe"
    assert status.coordination_count == 1
    assert status.report_count == 1
    assert status.latest_status == "stabilizing"
    assert not status.stood_down
    # same seq twice, no audit rows, nothing consumed
    again = ledger.status("CR-001", 4)
    assert again == status
    kinds = [e["kind"] for e in ledger.audit_log(4)]
    assert kinds == [
        cm.KIND_DECLARED,
        cm.KIND_COORDINATED,
        cm.KIND_REPORTED,
    ]
    with pytest.raises(cm.UnknownCrisisError):
        ledger.status("CR-NOPE", 4)


def test_audit_shapes_leak_ban_and_bad_kind():
    ledger = fresh()
    ledger.coordinate("CR-001", "freeze-changes", 2)
    events = ledger.audit_log(3)
    declared = events[0]
    assert declared["schema"] == "audit.ndjson/1"
    assert declared["kind"] == cm.KIND_DECLARED
    assert declared["seq"] == 1
    assert "record_digest" in declared["detail"]
    # every banned raw-text key is refused by the builder
    for banned in sorted(cm._BANNED_AUDIT_KEYS):
        with pytest.raises(cm.AuditKindError):
            cm.crisis_management_audit_event(
                cm.KIND_DECLARED, 3, **{banned: "raw"}
            )
    with pytest.raises(cm.AuditKindError):
        cm.crisis_management_audit_event("crisis-management.bogus", 3)
    # no banned raw-text key in any booked audit detail (exact-key check)
    for event in ledger.audit_log(4):
        for banned in cm._BANNED_AUDIT_KEYS:
            assert banned not in event["detail"]


def test_cross_instance_digest_determinism_and_tamper():
    a = cm.CrisisManagement()
    b = cm.CrisisManagement()
    ra = a.declare("CR-X", "major", 1, declared_by_digest=digest("cto"))
    rb = b.declare("CR-X", "major", 1, declared_by_digest=digest("cto"))
    assert ra.digest == rb.digest and ra.verify()
    ca = a.coordinate("CR-X", "evacuate-site", 2)
    cb = b.coordinate("CR-X", "evacuate-site", 2)
    assert ca.digest == cb.digest
    # tamper breaks verify
    object.__setattr__(ra, "severity", "minor")
    assert not ra.verify()
    sa = a.standdown("CR-X", 3, outcome="mitigated")
    assert sa.verify()


def test_main_subprocess_and_thread_safety_smoke():
    proc = subprocess.run(
        [sys.executable, str(MODULE)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert "crisis-management OK: declare, coordinate, report, standdown" in (
        proc.stdout
    )
    import threading

    ledger = fresh()
    errors = []

    def reader(n):
        try:
            ledger.status("CR-001", 4 + (n % 3))
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=reader, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
