"""Tests for ai_governance.py: 15 tests, house style."""

import ast
import dataclasses
import subprocess
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import ai_governance as ag

D = "sha256:" + "ab" * 32


def _mod():
    return ag.AIGovernance()


# 1. version / schema / vocabulary pins -------------------------------------

def test_pins_and_vocabulary():
    assert ag.AI_GOVERNANCE_VERSION == "ai-governance.v1"
    assert ag.AI_GOVERNANCE_SCHEMA == "northstar.ai-governance.v1"
    assert ag.AUDIT_SCHEMA == "audit.ndjson/1"
    assert len(ag.CONTROL_KINDS) == 8
    assert len(ag.STATUSES) == 4
    assert len(ag.AUDIT_KINDS) == 8
    assert len(ag.FINDINGS) == 4
    assert ag.KIND_CONTROL_DECLARED == "control-declared"
    assert ag.KIND_AUDITED == "audited"
    assert ag.KIND_RETIRED == "retired"
    assert ag.KIND_REJECTED == "rejected"


# 2. stdlib-only AST check ----------------------------------------------------

def test_stdlib_only_ast():
    assert ag.stdlib_only()
    tree = ast.parse(Path(ag.__file__).read_text())
    stdlib = set(sys.stdlib_module_names)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in stdlib
        elif isinstance(node, ast.ImportFrom):
            assert node.module is None or \
                node.module.split(".")[0] in stdlib or \
                node.module.split(".")[0] == "canonical_json"


# 3. govern roundtrip ----------------------------------------------------------

def test_govern_roundtrip_verify_frozen():
    g = _mod()
    rec = g.govern("sys-1", 1, control_kind=ag.CONTROL_KILL_SWITCH,
                   status=ag.STATUS_SATISFIED, control_digest=D)
    assert rec.control_id == "ctl-1"
    assert rec.system_id == "sys-1"
    assert rec.verify()
    assert rec.as_dict()["digest"] == rec.digest
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.status = ag.STATUS_GAP  # type: ignore[misc]
    rec2 = g.govern("sys-1", 2)
    assert rec2.control_id == "ctl-2"


# 4. govern bad-input table + seq burn -----------------------------------------

def test_govern_bad_input_table_seq_burn():
    g = _mod()
    bad = [
        ("", 1, ag.CONTROL_MONITORING, ag.STATUS_GAP, "", ag.BadSystemError),
        ("s 1", 1, ag.CONTROL_MONITORING, ag.STATUS_GAP, "", ag.BadSystemError),
        ("x" * 257, 1, ag.CONTROL_MONITORING, ag.STATUS_GAP, "",
         ag.BadSystemError),
        ("sys-2", 1, "not-a-kind", ag.STATUS_GAP, "",
         ag.BadControlKindError),
        ("sys-2", 1, ag.CONTROL_MONITORING, "not-a-status", "",
         ag.BadStatusError),
        ("sys-2", 1, ag.CONTROL_MONITORING, ag.STATUS_GAP, "bad-digest",
         ag.BadDigestError),
    ]
    seq = 1
    for sys_id, _s, kind, status, dgst, err in bad:
        with pytest.raises(ag.AIGovernanceError):
            g.govern(sys_id, seq, control_kind=kind, status=status,
                     control_digest=dgst)
        seq += 1
    rows = g.audit_log(seq)
    rejected = [r for r in rows if r["kind"] == ag.KIND_REJECTED]
    assert len(rejected) == len(bad)
    # burn worked: next accepted seq must strictly increase
    rec = g.govern("ok-sys", seq, control_kind=ag.CONTROL_MONITORING)
    assert rec.seq == seq


# 5. full control-kind vocabulary ----------------------------------------------

def test_full_control_kind_vocabulary():
    g = _mod()
    seq = 0
    for kind in ag.CONTROL_KINDS:
        seq += 1
        rec = g.govern("sys-v", seq, control_kind=kind)
        assert rec.control_kind == kind and rec.verify()
    seq += 1
    rec = g.govern("sys-w", seq, status=ag.STATUS_WAIVER)
    assert rec.status == ag.STATUS_WAIVER and rec.verify()


# 6. audit roundtrip -------------------------------------------------------------

def test_audit_roundtrip_verify():
    g = _mod()
    g.govern("sys-a", 1)
    adt = g.audit("sys-a", 2, audit_kind=ag.AUDIT_DATA_AUDIT,
                  finding=ag.FINDING_PARTIAL, audit_digest=D)
    assert adt.audit_id == "adt-1"
    assert adt.verify()
    assert adt.as_dict()["finding"] == ag.FINDING_PARTIAL
    with pytest.raises(dataclasses.FrozenInstanceError):
        adt.finding = ag.FINDING_PASS  # type: ignore[misc]


# 7. audit refusal table --------------------------------------------------------

def test_audit_refusal_table():
    g = _mod()
    g.govern("sys-b", 1)
    g.retire("sys-b", 2)
    g.govern("sys-c2", 5)
    cases = [
        ("ghost", 6, ag.AUDIT_MODEL_AUDIT, ag.FINDING_PASS, "",
         ag.UnknownSystemError),
        ("sys-b", 7, ag.AUDIT_MODEL_AUDIT, ag.FINDING_PASS, "",
         ag.RetiredSystemError),
        ("sys-c2", 8, "bad-kind", ag.FINDING_PASS, "",
         ag.BadAuditKindError),
        ("sys-c2", 9, ag.AUDIT_MODEL_AUDIT, "bad-finding", "",
         ag.BadFindingError),
        ("sys-c2", 10, ag.AUDIT_MODEL_AUDIT, ag.FINDING_PASS, "zzz",
         ag.BadDigestError),
    ]
    for sys_id, seq, kind, finding, dgst, err in cases:
        with pytest.raises(ag.AIGovernanceError):
            g.audit(sys_id, seq, audit_kind=kind, finding=finding,
                    audit_digest=dgst)
    rows = g.audit_log(11)
    assert sum(1 for r in rows if r["kind"] == ag.KIND_REJECTED) >= 5
    # failed mutations burned their seqs: next valid seq must increase
    adt = g.audit("sys-c2", 12)
    assert adt.seq == 12


# 8. verify read purity ----------------------------------------------------------

def test_verify_read_purity_and_unknown():
    g = _mod()
    g.govern("sys-v", 1)
    g.audit("sys-v", 2)
    n_before = len(g.audit_log(3))
    v1 = g.verify("adt-1", 4)
    v2 = g.verify("adt-1", 4)  # same seq twice: pure read
    assert v1.verdict == "verified" and v2.verdict == "verified"
    assert v1.digest == v2.digest
    assert len(g.audit_log(5)) == n_before  # no new audit rows
    assert v1.verify()
    with pytest.raises(ag.UnknownAuditError):
        g.verify("adt-999", 6)


# 9. tamper reported as data ------------------------------------------------------

def test_tamper_flips_integrity_as_data():
    g = _mod()
    g.govern("sys-t", 1)
    adt = g.audit("sys-t", 2)
    object.__setattr__(adt, "finding", ag.FINDING_FAIL)  # tamper
    vfy = g.verify("adt-1", 3)
    assert vfy.verdict == "tampered"
    assert not vfy.integrity_ok
    assert vfy.verify()  # the report itself still pins cleanly
    rep = g.report(4, "sys-t")
    assert not rep.integrity_ok


# 10. retire terminality -----------------------------------------------------------

def test_retire_terminality():
    g = _mod()
    g.govern("sys-r", 1)
    g.audit("sys-r", 2)
    with pytest.raises(ag.BadReasonError):
        g.retire("sys-r", 3, reason="nope")
    rec = g.retire("sys-r", 4, reason=ag.REASON_DECOMMISSIONED)
    assert rec.verify()
    assert g.retired_ids(5) == ("sys-r",)
    # double retire refused
    with pytest.raises(ag.RetiredSystemError):
        g.retire("sys-r", 6)
    # retired ids never recycled
    with pytest.raises(ag.RetiredSystemError):
        g.govern("sys-r", 7)
    # reads still work post-retire
    assert g.controls_for("sys-r", 8) == ("ctl-1",)
    assert g.audits_for("sys-r", 9) == ("adt-1",)
    assert g.report(10, "sys-r").posture == "compliant"
    with pytest.raises(ag.UnknownSystemError):
        g.retire("ghost", 11)


# 11. seq discipline -----------------------------------------------------------------

def test_seq_discipline():
    g = _mod()
    # rewind raises bare without consuming
    g.govern("sys-s", 5)
    n_before = len(g.audit_log(6))
    with pytest.raises(ag.SeqOrderError):
        g.govern("sys-s2", 5)
    assert len(g.audit_log(7)) == n_before
    # malformed seqs
    for bad in (True, "1", 1.5, None, -1):
        with pytest.raises(ag.SeqOrderError):
            g.govern("sys-s3", bad)
    # failed mutation consumes its seq (claim-then-burn)
    with pytest.raises(ag.BadControlKindError):
        g.govern("sys-s4", 8, control_kind="bogus")
    rec = g.govern("sys-s5", 9)
    assert rec.seq == 9


# 12. audit event shapes + leak ban ------------------------------------------------------

def test_audit_event_shapes_and_leak_ban():
    ev = ag.ai_governance_audit_event(ag.KIND_AUDITED, 1, audit_id="adt-1")
    assert ev["schema"] == ag.AUDIT_SCHEMA
    assert ev["audit_seq"] == 1
    with pytest.raises(ag.AuditKindError):
        ag.ai_governance_audit_event("bogus-kind", 2)
    with pytest.raises(ag.AuditKindError):
        ag.ai_governance_audit_event(ag.KIND_AUDITED, 3, evidence="raw")
    with pytest.raises(ag.AuditKindError):
        ag.ai_governance_audit_event(ag.KIND_CONTROL_DECLARED, 4,
                                     transcript="x")
    g = _mod()
    g.govern("sys-l", 1, control_kind=ag.CONTROL_ACCESS_CONTROL)
    g.audit("sys-l", 2, finding=ag.FINDING_PASS)
    rows = g.audit_log(3)
    assert rows[0]["kind"] == ag.KIND_CONTROL_DECLARED
    assert rows[1]["kind"] == ag.KIND_AUDITED
    assert all("evidence" not in r["detail"] for r in rows)


# 13. report posture math ---------------------------------------------------------

def test_report_posture_math():
    g = _mod()
    g.govern("s1", 1)
    assert g.report(2, "s1").posture == "unaudited"
    g.audit("s1", 3, finding=ag.FINDING_PASS)
    assert g.report(4, "s1").posture == "compliant"
    g.audit("s1", 5, finding=ag.FINDING_PARTIAL)
    assert g.report(6, "s1").posture == "partial"
    g.audit("s1", 7, finding=ag.FINDING_INCONCLUSIVE)
    assert g.report(8, "s1").posture == "inconclusive"
    g.audit("s1", 9, finding=ag.FINDING_FAIL)
    rep = g.report(10, "s1")
    assert rep.posture == "non-compliant"  # fail outranks everything
    assert rep.fail_count == 1 and rep.pass_count == 1
    assert rep.audit_count == 4 and rep.verify()
    # gaps counted from control statuses
    g.govern("s2", 11, status=ag.STATUS_GAP)
    rep2 = g.report(12, "s2")
    assert rep2.gap_count == 1 and rep2.posture == "unaudited"
    # whole-ledger scope
    whole = g.report(13)
    assert whole.system_id == "" and whole.audit_count == 4
    with pytest.raises(ag.UnknownSystemError):
        g.report(14, "ghost")


# 14. cross-instance digest determinism --------------------------------------------

def test_cross_instance_digest_determinism():
    def build():
        g = ag.AIGovernance()
        g.govern("sys-d", 1, control_kind=ag.CONTROL_MONITORING,
                 status=ag.STATUS_SATISFIED, control_digest=D)
        g.audit("sys-d", 2, audit_kind=ag.AUDIT_COMPLIANCE_REVIEW,
                finding=ag.FINDING_PASS, audit_digest=D)
        return g

    g1, g2 = build(), build()
    assert g1.audit_record("adt-1", 3).digest == \
        g2.audit_record("adt-1", 3).digest
    assert g1.control_record("ctl-1", 3).digest == \
        g2.control_record("ctl-1", 3).digest
    assert g1.report(4, "sys-d").digest == g2.report(4, "sys-d").digest


# 15. main() subprocess check + read smoke -------------------------------------------

def test_main_subprocess_and_read_smoke():
    proc = subprocess.run(
        [sys.executable, ag.__file__], capture_output=True, text=True,
        timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert "ai-governance OK" in proc.stdout
    g = _mod()
    g.govern("sys-x", 1)
    g.audit("sys-x", 2)
    errs = []

    def read():
        try:
            for _ in range(50):
                g.verify("adt-1", 3)
                g.report(4, "sys-x")
                g.stats(5)
        except Exception as exc:  # pragma: no cover
            errs.append(exc)

    threads = [threading.Thread(target=read) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errs
