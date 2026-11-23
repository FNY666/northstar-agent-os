"""Tests for the ai-accountability assignment decision ledger, Simulated."""

import ast
import dataclasses
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "ai_accountability.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("ai_accountability", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["ai_accountability"] = module
    spec.loader.exec_module(module)
    return module


aa = _load()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert aa.AI_ACCOUNTABILITY_VERSION == "ai-accountability.v1"
    assert aa.SCHEMA_PIN == "northstar.ai-accountability.v1"
    assert aa.ACCOUNTABILITY_KINDS == (
        "development",
        "deployment",
        "operation",
        "data-governance",
        "evaluation",
        "oversight",
        "incident-response",
        "monitoring",
    )
    assert aa.ACCOUNTABILITY_STATUSES == (
        "assigned",
        "accepted",
        "contested",
        "vacant",
    )
    assert aa.VERIFY_VERDICTS == ("verified", "tampered")
    assert aa.POSTURES == (
        "unassigned",
        "accountability-gap",
        "contested",
        "pending",
        "covered",
    )
    assert aa.RETIRE_REASONS == ("manual", "superseded", "decommissioned", "false-start")
    assert aa.EMIT_KINDS == ("assigned", "retired", "rejected")


# 2. stdlib-only AST check
def test_stdlib_only_ast():
    assert aa.stdlib_only()
    tree = ast.parse(MOD.read_text())
    allowed = {
        "hashlib",
        "json",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
        "ast",
        "pathlib",
        "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed
        elif isinstance(node, ast.ImportFrom):
            assert node.module is None or node.module.split(".")[0] in allowed


# 3. assign roundtrip: minted ids, verify(), frozen-ness
def test_assign_roundtrip():
    ledger = aa.AIAccountability()
    rec = ledger.assign(
        "sys-1",
        1,
        accountable_party="deploy-team",
        accountability_kind="deployment",
        status="accepted",
        assignment_digest=PIN,
    )
    assert rec.assignment_id == "asg-1"
    assert rec.system_id == "sys-1"
    assert rec.accountable_party == "deploy-team"
    assert rec.seq == 1
    assert rec.accountability_kind == "deployment"
    assert rec.status == "accepted"
    assert rec.assignment_digest == PIN
    assert rec.verify()
    assert dataclasses.is_dataclass(rec)
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.assignment_id = "x"  # type: ignore[misc]
    rec2 = ledger.assign(
        "sys-1",
        2,
        accountable_party="ops-team",
        accountability_kind="monitoring",
        status="assigned",
    )
    assert rec2.assignment_id == "asg-2"
    assert rec2.verify()


# 4. assign bad inputs: seq-burn + rejected rows
def test_assign_bad_inputs():
    ledger = aa.AIAccountability()
    bad_calls = [
        lambda s: ledger.assign("", s, accountable_party="p"),
        lambda s: ledger.assign("sys", s, accountable_party=""),
        lambda s: ledger.assign("sys", s, accountable_party="  "),
        lambda s: ledger.assign("sys", s, accountable_party=123),
        lambda s: ledger.assign("sys", s, accountable_party="p", accountability_kind="bogus-kind"),
        lambda s: ledger.assign("sys", s, accountable_party="p", status="bogus-status"),
        lambda s: ledger.assign("sys", s, accountable_party="p", assignment_digest="not-a-digest"),
        lambda s: ledger.assign("sys", s, accountable_party="p", assignment_digest="sha256:" + "zz" * 32),
        lambda s: ledger.assign(123, s, accountable_party="p"),
        lambda s: ledger.assign(True, s, accountable_party="p"),
    ]
    for i, call in enumerate(bad_calls):
        seq = i + 1
        with pytest.raises(aa.AIAccountabilityError):
            call(seq)
    rows = ledger.audit_log(99)
    rejected = [r for r in rows if r["kind"] == "rejected"]
    assert len(rejected) == len(bad_calls)
    assert all(r["seq"] == s for r, s in zip(rejected, range(1, len(bad_calls) + 1)))
    # ledger still usable after burns
    rec = ledger.assign("sys", 11, accountable_party="p", status="accepted")
    assert rec.verify()


# 5. full accountability-kind vocabulary acceptance
def test_full_kind_vocabulary():
    ledger = aa.AIAccountability()
    for i, kind in enumerate(aa.ACCOUNTABILITY_KINDS):
        rec = ledger.assign(
            f"sys-{i}",
            i + 1,
            accountable_party=f"party-{i}",
            accountability_kind=kind,
            status="accepted",
        )
        assert rec.accountability_kind == kind
        assert rec.verify()
    assert len(ledger.assignment_ids(99)) == len(aa.ACCOUNTABILITY_KINDS)


# 6. full status vocabulary acceptance
def test_full_status_vocabulary():
    ledger = aa.AIAccountability()
    for i, status in enumerate(aa.ACCOUNTABILITY_STATUSES):
        rec = ledger.assign(
            f"sys-{i}",
            i + 1,
            accountable_party=f"party-{i}",
            status=status,
        )
        assert rec.status == status
        assert rec.verify()


# 7. verify semantics: roundtrip, tamper-as-data, unknown, read purity
def test_verify_semantics():
    ledger = aa.AIAccountability()
    rec = ledger.assign("sys-1", 1, accountable_party="team-a", status="accepted")
    rep = ledger.verify(rec.assignment_id, 2)
    assert rep.record_id == rec.assignment_id
    assert rep.verdict == "verified"
    assert rep.integrity_ok is True
    assert rep.verify()
    # tamper is reported as data, never raised
    object.__setattr__(rec, "status", "tampered-status")
    rep2 = ledger.verify(rec.assignment_id, 3)
    assert rep2.verdict == "tampered"
    assert rep2.integrity_ok is False
    assert rep2.verify()
    # unknown record refuses
    with pytest.raises(aa.UnknownRecordError):
        ledger.verify("asg-999", 4)
    # read purity: same seq twice, no audit rows
    n0 = len(ledger.audit_log(5))
    ledger.verify(rec.assignment_id, 6)
    ledger.verify(rec.assignment_id, 6)
    assert len(ledger.audit_log(7)) == n0


# 8. evaluate posture math incl. precedence + tallies + unknown refusal
def test_evaluate_posture_math():
    ledger = aa.AIAccountability()
    # all accepted -> covered
    ledger.assign("s-covered", 1, accountable_party="p1", status="accepted")
    ledger.assign("s-covered", 2, accountable_party="p2", status="accepted")
    ev = ledger.evaluate("s-covered", 3)
    assert ev.posture == "covered"
    assert ev.n_assignments == 2 and ev.n_accepted == 2
    # assigned-not-accepted -> pending
    ledger.assign("s-pending", 4, accountable_party="p1", status="assigned")
    ev = ledger.evaluate("s-pending", 5)
    assert ev.posture == "pending"
    assert ev.n_assigned == 1
    # contested outranks assigned
    ledger.assign("s-pending", 6, accountable_party="p2", status="contested")
    ev = ledger.evaluate("s-pending", 7)
    assert ev.posture == "contested"
    assert ev.n_contested == 1
    # vacant outranks contested: accountability-gap
    ledger.assign("s-gap", 8, accountable_party="p1", status="contested")
    ledger.assign("s-gap", 9, accountable_party="p2", status="vacant")
    ev = ledger.evaluate("s-gap", 10)
    assert ev.posture == "accountability-gap"
    assert ev.n_vacant == 1
    # integrity_ok flips as data on tamper
    rec = ledger.assign("s-tamper", 11, accountable_party="p1", status="accepted")
    ev_ok = ledger.evaluate("s-tamper", 12)
    assert ev_ok.integrity_ok is True
    object.__setattr__(rec, "status", "vacant")
    ev_bad = ledger.evaluate("s-tamper", 13)
    assert ev_bad.integrity_ok is False
    assert ev_bad.posture == "accountability-gap"
    assert ev_bad.verify()
    # unknown system refuses
    with pytest.raises(aa.UnknownSystemError):
        ledger.evaluate("nope", 14)


# 9. retire terminality
def test_retire_terminality():
    ledger = aa.AIAccountability()
    ledger.assign("sys-1", 1, accountable_party="p1", status="accepted")
    # bad reason burns
    with pytest.raises(aa.BadReasonError):
        ledger.retire("sys-1", 2, reason="bogus")
    # unknown system refuses
    with pytest.raises(aa.UnknownSystemError):
        ledger.retire("nope", 3)
    ret = ledger.retire("sys-1", 4, reason="decommissioned")
    assert ret.verify()
    assert ledger.retired_ids(5) == ("sys-1",)
    # double retire refuses, id never recycled
    with pytest.raises(aa.RetiredSystemError):
        ledger.retire("sys-1", 6)
    # post-retire mutation refused, reads still work
    with pytest.raises(aa.RetiredSystemError):
        ledger.assign("sys-1", 7, accountable_party="p2", status="accepted")
    assert ledger.evaluate("sys-1", 8).posture == "covered"
    assert len(ledger.assignments_for("sys-1", 9)) == 1


# 10. seq discipline
def test_seq_discipline():
    ledger = aa.AIAccountability()
    # rewind raises bare without consuming or booking
    ledger.assign("sys-1", 1, accountable_party="p1", status="accepted")
    with pytest.raises(aa.SeqOrderError):
        ledger.assign("sys-2", 1, accountable_party="p2", status="accepted")
    with pytest.raises(aa.SeqOrderError):
        ledger.assign("sys-2", 0, accountable_party="p2", status="accepted")
    rejected = [r for r in ledger.audit_log(2) if r["kind"] == "rejected"]
    assert rejected == []
    # malformed seqs on reads
    for bad in (True, 1.5, "2", None, -1):
        with pytest.raises(aa.SeqOrderError):
            ledger.evaluate("sys-1", bad)
    # failed mutation consumes seq: next good call must use higher seq
    with pytest.raises(aa.BadKindError):
        ledger.assign("sys-1", 2, accountable_party="p1", accountability_kind="bogus")
    rec = ledger.assign("sys-1", 3, accountable_party="p1", status="accepted")
    assert rec.assignment_id == "asg-2"
    stats = ledger.stats(3)
    assert stats["seq"] == 3
    assert stats["n_assignments"] == 2


# 11. audit shapes + leak ban
def test_audit_shapes_and_leak_ban():
    ledger = aa.AIAccountability()
    rec = ledger.assign(
        "sys-1",
        1,
        accountable_party="deploy-team",
        accountability_kind="deployment",
        status="accepted",
    )
    rows = ledger.audit_log(2)
    assert rows[0]["schema"] == "audit.ndjson/1"
    assert rows[0]["module"] == "ai-accountability"
    assert rows[0]["version"] == "ai-accountability.v1"
    assert rows[0]["kind"] == "assigned"
    assert rows[0]["seq"] == 1
    details = rows[0]["details"]
    assert details["assignment_id"] == rec.assignment_id
    assert details["status"] == "accepted"
    # banned raw keys are refused at the builder level
    for banned in (
        "contract",
        "signature",
        "identity",
        "role",
        "agreement",
        "charter",
        "liability",
        "evidence",
        "findings",
        "report",
        "transcript",
        "weights",
    ):
        with pytest.raises(aa.AIAccountabilityError):
            aa.ai_accountability_audit_event("assigned", 2, **{banned: "raw"})
    # bad kind and bad seq raise
    with pytest.raises(aa.AuditKindError):
        aa.ai_accountability_audit_event("bogus", 2)
    with pytest.raises(aa.SeqOrderError):
        aa.ai_accountability_audit_event("assigned", True)
    # pinned vocab values pass through as declared data
    row = aa.ai_accountability_audit_event(
        "assigned", 2, accountability_kind="deployment", status="accepted"
    )
    assert row["details"]["accountability_kind"] == "deployment"
    # retire row shape
    ledger.retire("sys-1", 3)
    rows = ledger.audit_log(4)
    assert rows[-1]["kind"] == "retired"


# 12. cross-instance determinism + views/unknown lookups
def test_determinism_views_and_unknown_lookups():
    def build():
        l = aa.AIAccountability()
        l.assign("sys-1", 1, accountable_party="team-a",
                 accountability_kind="development", status="accepted",
                 assignment_digest=PIN)
        l.assign("sys-1", 2, accountable_party="team-b",
                 accountability_kind="monitoring", status="assigned",
                 assignment_digest=PIN2)
        return l

    l1, l2 = build(), build()
    assert l1.assignment_ids(3) == l2.assignment_ids(3)
    for aid in l1.assignment_ids(3):
        assert l1.assignment_record(aid, 4).digest == l2.assignment_record(aid, 4).digest
    assert l1.system_ids(5) == ("sys-1",)
    assert len(l1.assignments_for("sys-1", 6)) == 2
    assert l1.assignments_for("nobody", 7) == ()
    assert l1.retired_ids(8) == ()
    with pytest.raises(aa.UnknownAssignmentError):
        l1.assignment_record("asg-999", 9)
    stats = l1.stats(10)
    assert stats["n_systems"] == 1 and stats["n_assignments"] == 2
    assert stats["n_audit_rows"] == 2


# 13. frozen-ness of all records
def test_records_are_frozen():
    ledger = aa.AIAccountability()
    rec = ledger.assign("sys-1", 1, accountable_party="p1", status="accepted")
    rep = ledger.verify(rec.assignment_id, 2)
    ev = ledger.evaluate("sys-1", 3)
    ret = ledger.retire("sys-1", 4)
    for frozen in (rec, rep, ev, ret):
        with pytest.raises(dataclasses.FrozenInstanceError):
            frozen.digest = "x"  # type: ignore[misc]


# 14. thread read smoke
def test_thread_read_smoke():
    ledger = aa.AIAccountability()
    for i in range(20):
        ledger.assign(f"sys-{i % 4}", i + 1, accountable_party=f"p-{i}",
                      status="accepted")
    errors = []

    def read_loop():
        try:
            for _ in range(50):
                ledger.evaluate("sys-0", 21)
                ledger.assignment_ids(22)
                ledger.stats(23)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=read_loop) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors


# 15. main() subprocess check
def test_main_subprocess():
    proc = subprocess.run(
        [sys.executable, str(MOD)],
        capture_output=True,
        text=True,
        cwd=MOD.parent,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == (
        "ai-accountability OK: assign, verify, evaluate, retire, pins, audit"
    )
