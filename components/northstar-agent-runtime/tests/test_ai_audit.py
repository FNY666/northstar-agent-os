"""Tests for the ai-audit engagement decision ledger, Simulated."""

import ast
import dataclasses
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "ai_audit.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("ai_audit", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["ai_audit"] = module
    spec.loader.exec_module(module)
    return module


aa = _load()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert aa.AI_AUDIT_VERSION == "ai-audit.v1"
    assert aa.SCHEMA_PIN == "northstar.ai-audit.v1"
    assert aa.AUDIT_KINDS == (
        "internal-review",
        "external-audit",
        "regulatory-audit",
        "model-audit",
        "data-audit",
        "deployment-audit",
        "process-audit",
        "red-team-audit",
    )
    assert aa.AUDIT_FINDINGS == (
        "clean",
        "minor-findings",
        "major-findings",
        "critical-findings",
        "inconclusive",
        "not-audited",
    )
    assert aa.VERIFY_VERDICTS == ("verified", "tampered")
    assert aa.POSTURES == (
        "unaudited",
        "critical",
        "at-risk",
        "inconclusive",
        "partial",
        "clean",
    )
    assert aa.RETIRE_REASONS == ("manual", "superseded", "decommissioned", "false-start")
    assert aa.EMIT_KINDS == ("audited", "retired", "rejected")


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


# 3. audit roundtrip
def test_audit_roundtrip():
    ledger = aa.AIAudit()
    rec = ledger.audit(
        "sys-1", 1, audit_kind="external-audit", finding="clean", audit_digest=PIN
    )
    assert rec.audit_id == "aud-1"
    assert rec.system_id == "sys-1"
    assert rec.seq == 1
    assert rec.audit_kind == "external-audit"
    assert rec.finding == "clean"
    assert rec.audit_digest == PIN
    assert rec.verify()
    assert dataclasses.is_dataclass(rec)
    with pytest.raises(dataclasses.FrozenInstanceError):
        object.__getattribute__(type(rec), "__dataclass_params__")
        rec.audit_id = "x"
    rec2 = ledger.audit("sys-1", 2, audit_kind="model-audit", finding="minor-findings")
    assert rec2.audit_id == "aud-2"
    assert rec2.verify()


# 4. audit bad inputs: seq-burn + rejected rows
def test_audit_bad_inputs():
    ledger = aa.AIAudit()
    bad_calls = [
        lambda s: ledger.audit("", s),
        lambda s: ledger.audit("sys", s, audit_kind="bogus-kind"),
        lambda s: ledger.audit("sys", s, finding="bogus-finding"),
        lambda s: ledger.audit("sys", s, audit_digest="not-a-digest"),
        lambda s: ledger.audit("sys", s, audit_digest="sha256:" + "zz" * 32),
        lambda s: ledger.audit(123, s),
        lambda s: ledger.audit(True, s),
    ]
    for i, call in enumerate(bad_calls):
        seq = i + 1
        with pytest.raises(aa.AIAuditError):
            call(seq)
    rows = ledger.audit_log(99)
    rejected = [r for r in rows if r["kind"] == "rejected"]
    assert len(rejected) == len(bad_calls)
    assert all(r["seq"] == s for r, s in zip(rejected, range(1, len(bad_calls) + 1)))
    # ledger still usable after burns
    rec = ledger.audit("sys", 8, finding="clean")
    assert rec.verify()


# 5. full audit-kind vocabulary acceptance
def test_full_audit_kind_vocabulary():
    ledger = aa.AIAudit()
    for i, kind in enumerate(aa.AUDIT_KINDS):
        rec = ledger.audit(f"sys-{i}", i + 1, audit_kind=kind, finding="clean")
        assert rec.audit_kind == kind
        assert rec.verify()
    assert len(ledger.audit_ids(99)) == len(aa.AUDIT_KINDS)


# 6. full finding vocabulary acceptance
def test_full_finding_vocabulary():
    ledger = aa.AIAudit()
    for i, finding in enumerate(aa.AUDIT_FINDINGS):
        rec = ledger.audit(f"sys-{i}", i + 1, finding=finding)
        assert rec.finding == finding
        assert rec.verify()


# 7. verify semantics: roundtrip, tamper-as-data, unknown, read purity
def test_verify_semantics():
    ledger = aa.AIAudit()
    rec = ledger.audit("sys-1", 1, finding="clean")
    rep = ledger.verify(rec.audit_id, 2)
    assert rep.record_id == rec.audit_id
    assert rep.verdict == "verified"
    assert rep.integrity_ok is True
    assert rep.verify()
    # tamper is reported as data, never raised
    object.__setattr__(rec, "finding", "tampered-finding")
    rep2 = ledger.verify(rec.audit_id, 3)
    assert rep2.verdict == "tampered"
    assert rep2.integrity_ok is False
    assert rep2.verify()
    # unknown record refuses
    with pytest.raises(aa.UnknownRecordError):
        ledger.verify("aud-999", 4)
    # read purity: same seq twice, no audit rows
    n0 = len(ledger.audit_log(5))
    ledger.verify(rec.audit_id, 6)
    ledger.verify(rec.audit_id, 6)
    assert len(ledger.audit_log(7)) == n0


# 8. evaluate posture math incl. precedence + unknown refusal
def test_evaluate_posture_math():
    ledger = aa.AIAudit()
    # not-audited only -> partial (mixed with not-audited falls to partial)
    ledger.audit("s-notaud", 1, finding="not-audited")
    assert ledger.evaluate("s-notaud", 2).posture == "partial"
    # all clean -> clean
    ledger.audit("s-clean", 3, finding="clean")
    ledger.audit("s-clean", 4, finding="clean")
    ev = ledger.evaluate("s-clean", 5)
    assert ev.posture == "clean"
    assert ev.n_audits == 2 and ev.n_clean == 2
    # minor -> partial
    ledger.audit("s-partial", 6, finding="minor-findings")
    assert ledger.evaluate("s-partial", 7).posture == "partial"
    # inconclusive outranks minor
    ledger.audit("s-partial", 8, finding="inconclusive")
    assert ledger.evaluate("s-partial", 9).posture == "inconclusive"
    # major -> at-risk (outranks inconclusive)
    ledger.audit("s-risk", 10, finding="inconclusive")
    ledger.audit("s-risk", 11, finding="major-findings")
    ev = ledger.evaluate("s-risk", 12)
    assert ev.posture == "at-risk"
    assert ev.n_inconclusive == 1 and ev.n_major == 1
    # critical outranks major
    ledger.audit("s-risk", 13, finding="critical-findings")
    assert ledger.evaluate("s-risk", 14).posture == "critical"
    # integrity_ok flips as data on tamper
    rec = ledger.audit("s-tamper", 15, finding="clean")
    ev_ok = ledger.evaluate("s-tamper", 16)
    assert ev_ok.integrity_ok is True
    object.__setattr__(rec, "finding", "critical-findings")
    ev_bad = ledger.evaluate("s-tamper", 17)
    assert ev_bad.integrity_ok is False
    assert ev_bad.posture == "critical"
    assert ev_bad.verify()
    # unknown system refuses
    with pytest.raises(aa.UnknownSystemError):
        ledger.evaluate("nope", 18)


# 9. retire terminality
def test_retire_terminality():
    ledger = aa.AIAudit()
    ledger.audit("sys-1", 1, finding="clean")
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
        ledger.audit("sys-1", 7, finding="clean")
    assert ledger.evaluate("sys-1", 8).posture == "clean"
    assert len(ledger.audits_for("sys-1", 9)) == 1


# 10. seq discipline
def test_seq_discipline():
    ledger = aa.AIAudit()
    # rewind raises bare without consuming or booking
    ledger.audit("sys-1", 1, finding="clean")
    with pytest.raises(aa.SeqOrderError):
        ledger.audit("sys-2", 1, finding="clean")
    with pytest.raises(aa.SeqOrderError):
        ledger.audit("sys-2", 0, finding="clean")
    rejected = [r for r in ledger.audit_log(2) if r["kind"] == "rejected"]
    assert rejected == []
    # malformed seqs on reads
    for bad in (True, 1.5, "2", None, -1):
        with pytest.raises(aa.SeqOrderError):
            ledger.evaluate("sys-1", bad)
    # failed mutation consumes seq: next good call must use higher seq
    with pytest.raises(aa.BadAuditKindError):
        ledger.audit("sys-1", 2, audit_kind="bogus")
    rec = ledger.audit("sys-1", 3, finding="clean")
    assert rec.audit_id == "aud-2"
    stats = ledger.stats(3)
    assert stats["seq"] == 3
    assert stats["n_audits"] == 2


# 11. audit shapes + leak ban
def test_audit_shapes_and_leak_ban():
    ledger = aa.AIAudit()
    rec = ledger.audit("sys-1", 1, audit_kind="external-audit", finding="minor-findings")
    rows = ledger.audit_log(2)
    assert rows[0]["schema"] == "audit.ndjson/1"
    assert rows[0]["module"] == "ai-audit"
    assert rows[0]["version"] == "ai-audit.v1"
    assert rows[0]["kind"] == "audited"
    assert rows[0]["seq"] == 1
    details = rows[0]["details"]
    assert details["audit_id"] == rec.audit_id
    assert details["finding"] == "minor-findings"
    # banned raw keys are refused at the builder level
    for banned in ("evidence", "findings", "report", "transcript", "weights", "workpapers"):
        with pytest.raises(aa.AIAuditError):
            aa.ai_audit_audit_event("audited", 2, **{banned: "raw"})
    # bad kind and bad seq raise
    with pytest.raises(aa.AuditKindError):
        aa.ai_audit_audit_event("bogus", 2)
    with pytest.raises(aa.SeqOrderError):
        aa.ai_audit_audit_event("audited", True)
    # pinned vocab values pass through as declared data
    row = aa.ai_audit_audit_event(
        "audited", 2, audit_kind="external-audit", finding="minor-findings"
    )
    assert row["details"]["audit_kind"] == "external-audit"
    # retire row shape
    ledger.retire("sys-1", 3)
    rows = ledger.audit_log(4)
    assert rows[-1]["kind"] == "retired"


# 12. cross-instance determinism + views/unknown lookups
def test_determinism_views_and_unknown_lookups():
    def build():
        l = aa.AIAudit()
        l.audit("sys-1", 1, audit_kind="model-audit", finding="clean", audit_digest=PIN)
        l.audit("sys-1", 2, audit_kind="data-audit", finding="minor-findings", audit_digest=PIN2)
        return l

    l1, l2 = build(), build()
    assert l1.audit_ids(3) == l2.audit_ids(3)
    for aid in l1.audit_ids(3):
        assert l1.audit_record(aid, 4).digest == l2.audit_record(aid, 4).digest
    assert l1.system_ids(5) == ("sys-1",)
    assert len(l1.audits_for("sys-1", 6)) == 2
    assert l1.audits_for("nobody", 7) == ()
    assert l1.retired_ids(8) == ()
    with pytest.raises(aa.UnknownAuditError):
        l1.audit_record("aud-999", 9)
    stats = l1.stats(10)
    assert stats["n_systems"] == 1 and stats["n_audits"] == 2
    assert stats["n_audit_rows"] == 2


# 13. frozen-ness of all records
def test_records_are_frozen():
    ledger = aa.AIAudit()
    rec = ledger.audit("sys-1", 1, finding="clean")
    rep = ledger.verify(rec.audit_id, 2)
    ev = ledger.evaluate("sys-1", 3)
    ret = ledger.retire("sys-1", 4)
    for frozen in (rec, rep, ev, ret):
        with pytest.raises(dataclasses.FrozenInstanceError):
            frozen.digest = "x"  # type: ignore[misc]


# 14. thread read smoke
def test_thread_read_smoke():
    ledger = aa.AIAudit()
    for i in range(20):
        ledger.audit(f"sys-{i % 4}", i + 1, finding="clean")
    errors = []

    def read_loop():
        try:
            for _ in range(50):
                ledger.evaluate("sys-0", 21)
                ledger.audit_ids(22)
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
    assert proc.stdout.strip() == "ai-audit OK: audit, verify, evaluate, retire, pins, audit"
