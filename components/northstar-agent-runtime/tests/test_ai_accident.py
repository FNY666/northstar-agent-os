"""Tests for the ai-accident report/investigation decision ledger, Simulated."""

import ast
import dataclasses
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "ai_accident.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("ai_accident", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["ai_accident"] = module
    spec.loader.exec_module(module)
    return module


aa = _load()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert aa.AI_ACCIDENT_VERSION == "ai-accident.v1"
    assert aa.SCHEMA_PIN == "northstar.ai-accident.v1"
    assert aa.ACCIDENT_KINDS == (
        "deployment-failure",
        "model-degradation",
        "harmful-output",
        "safety-bypass",
        "autonomy-breach",
        "resource-escalation",
        "data-corruption",
        "infrastructure-outage",
    )
    assert aa.INVESTIGATION_FINDINGS == (
        "under-investigation",
        "root-cause-found",
        "contained",
        "resolved",
        "unresolved",
        "false-alarm",
        "inconclusive",
    )
    assert aa.VERIFY_VERDICTS == ("verified", "tampered")
    assert aa.POSTURES == (
        "no-accidents",
        "open-incident",
        "under-investigation",
        "contained",
        "resolved",
    )
    assert aa.RETIRE_REASONS == ("manual", "superseded", "decommissioned", "false-start")
    assert aa.AUDIT_KINDS == ("reported", "investigated", "retired", "rejected")


# 2. stdlib-only AST check
def test_stdlib_only_ast():
    assert aa.stdlib_only() is True
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
            if node.module:
                assert node.module.split(".")[0] in allowed


# 3. report roundtrip + verify() + frozen-ness
def test_report_roundtrip_verify_frozen():
    ledger = aa.AIAccident()
    rec = ledger.report(
        "sys-1", 1, accident_kind="harmful-output", severity=70, report_digest=PIN
    )
    assert rec.accident_id == "acc-1"
    assert rec.system_id == "sys-1"
    assert rec.accident_kind == "harmful-output"
    assert rec.severity == 70
    assert rec.report_digest == PIN
    assert rec.verify() is True
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.severity = 0  # type: ignore
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.digest = "x"  # type: ignore
    # minted ids keep increasing across systems
    rec2 = ledger.report("sys-2", 2, accident_kind="data-corruption")
    assert rec2.accident_id == "acc-2"
    assert rec2.verify() is True


# 4. report bad-input table + seq-burn + rejected-row accounting + rewind bare
def test_report_bad_inputs_seq_burn():
    ledger = aa.AIAccident()
    base_rows = len(ledger.audit_log(0))
    bads = [
        lambda s: ledger.report("", s, accident_kind="harmful-output"),
        lambda s: ledger.report("sys-1", s, accident_kind="not-a-kind"),
        lambda s: ledger.report("sys-1", s, accident_kind="harmful-output", severity=-1),
        lambda s: ledger.report("sys-1", s, accident_kind="harmful-output", severity=101),
        lambda s: ledger.report("sys-1", s, accident_kind="harmful-output", severity=True),
        lambda s: ledger.report("sys-1", s, accident_kind="harmful-output", report_digest="bogus"),
        lambda s: ledger.report("  ", s),
    ]
    for i, bad in enumerate(bads, start=1):
        with pytest.raises(aa.AIAccidentError):
            bad(i)
    rows = ledger.audit_log(0)
    rejected = [r for r in rows[base_rows:] if r["kind"] == "rejected"]
    assert len(rejected) == len(bads)
    for r in rejected:
        assert r["schema"] == "audit.ndjson/1"
        assert r["module"] == "ai-accident"
    # rewind raises bare with zero rows (no burn)
    before = len(ledger.audit_log(0))
    with pytest.raises(aa.SeqOrderError):
        ledger.report("sys-1", 3)
    assert len(ledger.audit_log(0)) == before
    # malformed seqs never burn either
    for malformed in (0.5, "3", None, -3):
        with pytest.raises(aa.SeqOrderError):
            ledger.report("sys-1", malformed)
    assert len(ledger.audit_log(0)) == before


# 5. full 8-accident-kind vocabulary acceptance
def test_full_accident_kind_vocabulary():
    ledger = aa.AIAccident()
    for i, kind in enumerate(aa.ACCIDENT_KINDS, start=1):
        rec = ledger.report("sys-k", i, accident_kind=kind)
        assert rec.accident_kind == kind
        assert rec.verify() is True
    assert ledger.accident_ids(0) == [f"acc-{i}" for i in range(1, 9)]


# 6. investigate roundtrip + minted ids + unknown-accident refusal
def test_investigate_roundtrip_and_unknown():
    ledger = aa.AIAccident()
    rec = ledger.report("sys-1", 1, accident_kind="safety-bypass", severity=90)
    inv = ledger.investigate(rec.accident_id, 2, finding="root-cause-found", investigation_digest=PIN2)
    assert inv.investigation_id == "inv-1"
    assert inv.accident_id == rec.accident_id
    assert inv.system_id == "sys-1"
    assert inv.finding == "root-cause-found"
    assert inv.verify() is True
    inv2 = ledger.investigate(rec.accident_id, 3, finding="contained")
    assert inv2.investigation_id == "inv-2"
    with pytest.raises(aa.UnknownAccidentError):
        ledger.investigate("acc-999", 4, finding="resolved")
    rows = [r for r in ledger.audit_log(0) if r["kind"] == "rejected"]
    assert len(rows) == 1
    assert rows[0]["details"]["rejected_kind"] == "UnknownAccidentError"


# 7. investigate bad-input table + retired refusal + seq-burn
def test_investigate_bad_inputs():
    ledger = aa.AIAccident()
    rec = ledger.report("sys-1", 1, accident_kind="model-degradation")
    bads = [
        lambda s: ledger.investigate("", s),
        lambda s: ledger.investigate(rec.accident_id, s, finding="bogus"),
        lambda s: ledger.investigate(rec.accident_id, s, investigation_digest="bogus"),
        lambda s: ledger.investigate(123, s),
    ]
    for i, bad in enumerate(bads, start=2):
        with pytest.raises(aa.AIAccidentError):
            bad(i)
    rows = [r for r in ledger.audit_log(0) if r["kind"] == "rejected"]
    assert len(rows) == 4
    # retired-system refusal
    ledger.retire("sys-1", 6)
    with pytest.raises(aa.RetiredSystemError):
        ledger.investigate(rec.accident_id, 7, finding="resolved")
    rows = [r for r in ledger.audit_log(0) if r["kind"] == "rejected"]
    assert len(rows) == 5
    assert rows[-1]["details"]["rejected_kind"] == "RetiredSystemError"


# 8. verify semantics: roundtrip, tamper-as-data, unknown, read purity
def test_verify_semantics():
    ledger = aa.AIAccident()
    rec = ledger.report("sys-1", 1, accident_kind="autonomy-breach")
    inv = ledger.investigate(rec.accident_id, 2, finding="under-investigation")
    before = len(ledger.audit_log(0))
    rep = ledger.verify(rec.accident_id, 3)
    assert rep.verdict == "verified"
    assert rep.integrity_ok is True
    assert rep.verify() is True
    rep2 = ledger.verify(inv.investigation_id, 4)
    assert rep2.verdict == "verified"
    # read purity: same seq twice, no audit rows, no seq consumption
    ledger.verify(rec.accident_id, 4)
    assert len(ledger.audit_log(0)) == before
    assert ledger.stats(0)["seq"] == 2
    # unknown record refuses
    with pytest.raises(aa.UnknownRecordError):
        ledger.verify("inv-999", 5)
    # tamper flips verdict as data (never raises)
    import copy

    tampered = copy.copy(rec)
    object.__setattr__(tampered, "severity", 99)
    assert tampered.verify() is False
    ledger._accidents[rec.accident_id] = tampered
    rep3 = ledger.verify(rec.accident_id, 6)
    assert rep3.verdict == "tampered"
    assert rep3.integrity_ok is False


# 9. evaluate posture math: all 5 postures + precedence
def test_evaluate_posture_math():
    # no-accidents: system registered via a report that was retracted? use empty ledger -> unknown
    ledger = aa.AIAccident()
    rec = ledger.report("sys-1", 1, accident_kind="harmful-output")
    ev = ledger.evaluate("sys-1", 2)
    assert ev.posture == "open-incident"  # reported, no investigation
    assert ev.n_accidents == 1
    assert ev.n_open == 1
    assert ev.verify() is True
    # under-investigation outranks open only after investigation booked
    ledger.investigate(rec.accident_id, 3, finding="under-investigation")
    ev = ledger.evaluate("sys-1", 4)
    assert ev.posture == "under-investigation"
    assert ev.n_investigations == 1
    assert ev.n_investigating == 1
    # contained
    ledger.investigate(rec.accident_id, 5, finding="contained")
    ev = ledger.evaluate("sys-1", 6)
    assert ev.posture == "contained"
    assert ev.n_contained == 1
    # resolved: all resolved
    ledger.investigate(rec.accident_id, 7, finding="resolved")
    ev = ledger.evaluate("sys-1", 8)
    assert ev.posture == "resolved"
    assert ev.n_resolved == 1
    # open-incident precedence over investigating/contained across accidents
    rec2 = ledger.report("sys-1", 9, accident_kind="data-corruption")
    ev = ledger.evaluate("sys-1", 10)
    assert ev.posture == "open-incident"
    assert ev.n_open == 1
    # unknown system refuses
    with pytest.raises(aa.UnknownSystemError):
        ledger.evaluate("nope", 11)


# 10. evaluate read purity + tamper flips integrity_ok + tallies
def test_evaluate_read_purity_and_integrity():
    ledger = aa.AIAccident()
    rec = ledger.report("sys-1", 1, accident_kind="infrastructure-outage", severity=50)
    ledger.investigate(rec.accident_id, 2, finding="root-cause-found")
    before = len(ledger.audit_log(0))
    ev1 = ledger.evaluate("sys-1", 3)
    ev2 = ledger.evaluate("sys-1", 3)
    assert ev1.posture == ev2.posture == "contained"
    assert ev1.digest == ev2.digest
    assert len(ledger.audit_log(0)) == before  # no audit rows from reads
    assert ev1.integrity_ok is True
    # tamper an accident record -> integrity flips as data
    import copy

    tampered = copy.copy(rec)
    object.__setattr__(tampered, "severity", 1)
    ledger._accidents[rec.accident_id] = tampered
    ev3 = ledger.evaluate("sys-1", 4)
    assert ev3.integrity_ok is False
    assert ev3.posture == "contained"  # posture math still works


# 11. retire terminality + id non-recycling + post-retire reads + bad reason
def test_retire_terminality():
    ledger = aa.AIAccident()
    rec = ledger.report("sys-1", 1, accident_kind="resource-escalation")
    ret = ledger.retire("sys-1", 2, reason="decommissioned")
    assert ret.system_id == "sys-1"
    assert ret.reason == "decommissioned"
    assert ret.verify() is True
    assert ledger.retired_ids(0) == ["sys-1"]
    # post-retire mutations refused, reads still work
    with pytest.raises(aa.RetiredSystemError):
        ledger.report("sys-1", 3, accident_kind="harmful-output")
    with pytest.raises(aa.RetiredSystemError):
        ledger.investigate(rec.accident_id, 4, finding="resolved")
    with pytest.raises(aa.RetiredSystemError):
        ledger.retire("sys-1", 5)
    ev = ledger.evaluate("sys-1", 6)
    assert ev.posture == "open-incident"
    assert ledger.accident_record(rec.accident_id, 0).accident_id == rec.accident_id
    # bad reason burns
    ledger2 = aa.AIAccident()
    ledger2.report("s2", 1)
    with pytest.raises(aa.BadReasonError):
        ledger2.retire("s2", 2, reason="bogus")
    rows = [r for r in ledger2.audit_log(0) if r["kind"] == "rejected"]
    assert len(rows) == 1
    assert rows[0]["details"]["rejected_kind"] == "BadReasonError"


# 12. seq discipline: rewind bare, malformed seqs, failed-mutation-consumes-seq
def test_seq_discipline():
    ledger = aa.AIAccident()
    # rewind on a fresh ledger raises bare with zero rows
    with pytest.raises(aa.SeqOrderError):
        ledger.report("sys-1", 0)
    assert len(ledger.audit_log(0)) == 0
    ledger.report("sys-1", 1)
    with pytest.raises(aa.SeqOrderError):
        ledger.report("sys-1", 1)
    assert len(ledger.audit_log(0)) == 1  # only the "reported" row; rewind wrote none
    # malformed seqs raise bare on reads too (no rows ever written by reads)
    for malformed in (True, 1.5, "2", None, -1):
        with pytest.raises(aa.SeqOrderError):
            ledger.evaluate("sys-1", malformed)
    # failed mutation consumes seq: next valid call must exceed it
    with pytest.raises(aa.BadAccidentKindError):
        ledger.report("sys-1", 5, accident_kind="bogus")
    assert ledger.stats(0)["seq"] == 5
    with pytest.raises(aa.SeqOrderError):
        ledger.report("sys-1", 5)
    rec = ledger.report("sys-1", 6)
    assert rec.accident_id == "acc-2"


# 13. audit shapes + leak ban + bad-kind + pinned data passthrough
def test_audit_shapes_and_leak_ban():
    ledger = aa.AIAccident()
    rec = ledger.report("sys-1", 1, accident_kind="data-corruption", severity=10)
    ledger.investigate(rec.accident_id, 2, finding="false-alarm")
    ledger.retire("sys-1", 3)
    rows = ledger.audit_log(0)
    assert [r["kind"] for r in rows] == ["reported", "investigated", "retired"]
    for r in rows:
        assert r["schema"] == "audit.ndjson/1"
        assert r["module"] == "ai-accident"
        assert r["version"] == "ai-accident.v1"
        assert isinstance(r["details"], dict)
    # pinned vocab values remain emittable as declared data
    assert rows[0]["details"]["accident_kind"] == "data-corruption"
    assert rows[1]["details"]["finding"] == "false-alarm"
    assert rows[2]["details"]["reason"] == "manual"
    # banned raw keys raise at the builder level
    for banned in ("incident_log", "telemetry", "weights", "transcript", "evidence"):
        with pytest.raises(aa.AIAccidentError):
            aa.ai_accident_audit_event("reported", 9, **{banned: "raw"})
    # digest pins of banned material are fine
    row = aa.ai_accident_audit_event("reported", 9, incident_log_digest=PIN)
    assert row["details"]["incident_log_digest"] == PIN
    # bad kind raises
    with pytest.raises(aa.AuditKindError):
        aa.ai_accident_audit_event("bogus", 9)


# 14. cross-instance digest determinism + views/stats + 8-thread read smoke
def test_determinism_views_and_thread_smoke():
    def build():
        ledger = aa.AIAccident()
        rec = ledger.report("sys-1", 1, accident_kind="safety-bypass", severity=80, report_digest=PIN)
        inv = ledger.investigate(rec.accident_id, 2, finding="resolved", investigation_digest=PIN2)
        return ledger, rec, inv

    l1, r1, i1 = build()
    l2, r2, i2 = build()
    assert r1.digest == r2.digest
    assert i1.digest == i2.digest
    ev1 = l1.evaluate("sys-1", 3)
    ev2 = l2.evaluate("sys-1", 3)
    assert ev1.digest == ev2.digest
    # views
    assert l1.system_ids(0) == ["sys-1"]
    assert l1.accident_ids(0) == ["acc-1"]
    assert l1.investigation_ids(0) == ["inv-1"]
    assert len(l1.accidents_for("sys-1", 0)) == 1
    assert len(l1.investigations_for("acc-1", 0)) == 1
    stats = l1.stats(0)
    assert stats["n_accidents"] == 1
    assert stats["n_investigations"] == 1
    assert stats["n_audit_rows"] == 2
    # 8-thread read smoke: all read posture "resolved"
    results = []
    errors = []

    def worker():
        try:
            for _ in range(25):
                results.append(l1.evaluate("sys-1", 10).posture)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert results and all(r == "resolved" for r in results)
    # frozen-ness of all record types
    for rec in (r1, i1, ev1):
        with pytest.raises(dataclasses.FrozenInstanceError):
            rec.digest = "x"  # type: ignore


# 15. main() subprocess check
def test_main_subprocess():
    proc = subprocess.run(
        [sys.executable, str(MOD)],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=str(MOD.parent),
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == (
        "ai-accident OK: report, investigate, verify, evaluate, retire, pins, audit"
    )
