"""Tests for ai_policy.py: 15 tests, house style."""

import ast
import dataclasses
import subprocess
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import ai_policy as ap

D = "sha256:" + "ab" * 32


def _mod():
    return ap.AIPolicy()


# 1. version / schema / vocabulary pins ---------------------------------------

def test_pins_and_vocabulary():
    assert ap.AI_POLICY_VERSION == "ai-policy.v1"
    assert ap.AI_POLICY_SCHEMA == "northstar.ai-policy.v1"
    assert ap.AUDIT_SCHEMA == "audit.ndjson/1"
    assert len(ap.POLICY_KINDS) == 8
    assert len(ap.STATUSES) == 4
    assert len(ap.ENFORCEMENT_KINDS) == 8
    assert len(ap.VERDICTS) == 4
    assert ap.KIND_POLICY_DECLARED == "policy-declared"
    assert ap.KIND_ENFORCED == "enforced"
    assert ap.KIND_RETIRED == "retired"
    assert ap.KIND_REJECTED == "rejected"


# 2. stdlib-only AST check ----------------------------------------------------

def test_stdlib_only_ast():
    assert ap.stdlib_only()
    tree = ast.parse(Path(ap.__file__).read_text())
    stdlib = set(sys.stdlib_module_names)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in stdlib
        elif isinstance(node, ast.ImportFrom):
            assert node.module is None or \
                node.module.split(".")[0] in stdlib or \
                node.module.split(".")[0] == "canonical_json"


# 3. declare roundtrip ----------------------------------------------------------

def test_declare_roundtrip_verify_frozen():
    p = _mod()
    rec = p.declare("sys-1", 1, policy_kind=ap.POLICY_SAFETY,
                    status=ap.STATUS_ACTIVE, policy_digest=D)
    assert rec.policy_id == "pol-1"
    assert rec.system_id == "sys-1"
    assert rec.verify()
    assert rec.as_dict()["digest"] == rec.digest
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.status = ap.STATUS_DRAFT  # type: ignore[misc]
    rec2 = p.declare("sys-1", 2)
    assert rec2.policy_id == "pol-2"


# 4. declare bad-input table + seq burn ------------------------------------------

def test_declare_bad_input_table_seq_burn():
    p = _mod()
    bad = [
        ("", 1, ap.POLICY_USAGE, ap.STATUS_DRAFT, "", ap.BadSystemError),
        ("s 1", 1, ap.POLICY_USAGE, ap.STATUS_DRAFT, "", ap.BadSystemError),
        ("x" * 257, 1, ap.POLICY_USAGE, ap.STATUS_DRAFT, "",
         ap.BadSystemError),
        ("sys-2", 1, "not-a-kind", ap.STATUS_DRAFT, "",
         ap.BadPolicyKindError),
        ("sys-2", 1, ap.POLICY_USAGE, "not-a-status", "",
         ap.BadStatusError),
        ("sys-2", 1, ap.POLICY_USAGE, ap.STATUS_DRAFT, "bad-digest",
         ap.BadDigestError),
    ]
    seq = 1
    for sys_id, _s, kind, status, dgst, err in bad:
        with pytest.raises(ap.AIPolicyError):
            p.declare(sys_id, seq, policy_kind=kind, status=status,
                      policy_digest=dgst)
        seq += 1
    rows = p.audit_log(seq)
    rejected = [r for r in rows if r["kind"] == ap.KIND_REJECTED]
    assert len(rejected) == len(bad)
    # burn worked: next accepted seq must strictly increase
    rec = p.declare("ok-sys", seq, policy_kind=ap.POLICY_USAGE)
    assert rec.seq == seq


# 5. full policy-kind + status vocabulary ------------------------------------------

def test_full_policy_kind_and_status_vocabulary():
    p = _mod()
    seq = 0
    for kind in ap.POLICY_KINDS:
        seq += 1
        rec = p.declare("sys-v", seq, policy_kind=kind)
        assert rec.policy_kind == kind and rec.verify()
    for status in ap.STATUSES:
        seq += 1
        rec = p.declare("sys-w", seq, status=status)
        assert rec.status == status and rec.verify()


# 6. enforce roundtrip ---------------------------------------------------------------

def test_enforce_roundtrip_verify_frozen():
    p = _mod()
    p.declare("sys-a", 1)
    enf = p.enforce("sys-a", 2,
                    enforcement_kind=ap.ENFORCE_DATA_AUDIT,
                    verdict=ap.VERDICT_COMPLIANT,
                    enforcement_digest=D)
    assert enf.enforcement_id == "enf-1"
    assert enf.verify()
    assert enf.as_dict()["verdict"] == ap.VERDICT_COMPLIANT
    with pytest.raises(dataclasses.FrozenInstanceError):
        enf.verdict = ap.VERDICT_VIOLATION  # type: ignore[misc]


# 7. enforce refusal table ---------------------------------------------------------------

def test_enforce_refusal_table():
    p = _mod()
    p.declare("sys-b", 1)
    p.retire("sys-b", 2)
    p.declare("sys-c2", 5)
    cases = [
        ("ghost", 6, ap.ENFORCE_RUNTIME_GATE, ap.VERDICT_COMPLIANT, "",
         ap.UnknownSystemError),
        ("sys-b", 7, ap.ENFORCE_RUNTIME_GATE, ap.VERDICT_COMPLIANT, "",
         ap.RetiredSystemError),
        ("sys-c2", 8, "bad-kind", ap.VERDICT_COMPLIANT, "",
         ap.BadEnforcementKindError),
        ("sys-c2", 9, ap.ENFORCE_RUNTIME_GATE, "bad-verdict", "",
         ap.BadVerdictError),
        ("sys-c2", 10, ap.ENFORCE_RUNTIME_GATE, ap.VERDICT_COMPLIANT,
         "zzz", ap.BadDigestError),
    ]
    for sys_id, seq, kind, verdict, dgst, err in cases:
        with pytest.raises(ap.AIPolicyError):
            p.enforce(sys_id, seq, enforcement_kind=kind,
                      verdict=verdict, enforcement_digest=dgst)
    rows = p.audit_log(11)
    assert sum(1 for r in rows if r["kind"] == ap.KIND_REJECTED) >= 5
    # failed mutations burned their seqs: next valid seq must increase
    enf = p.enforce("sys-c2", 12)
    assert enf.seq == 12


# 8. full enforcement-kind vocabulary --------------------------------------------------

def test_full_enforcement_kind_vocabulary():
    p = _mod()
    p.declare("sys-k", 1)
    seq = 1
    for kind in ap.ENFORCEMENT_KINDS:
        seq += 1
        enf = p.enforce("sys-k", seq, enforcement_kind=kind,
                        verdict=ap.VERDICT_WAIVED)
        assert enf.enforcement_kind == kind and enf.verify()
    seq += 1
    enf = p.enforce("sys-k", seq, verdict=ap.VERDICT_INCONCLUSIVE)
    assert enf.verdict == ap.VERDICT_INCONCLUSIVE and enf.verify()


# 9. verify semantics: tamper as data + read purity + unknown ----------------------------

def test_verify_semantics_tamper_read_purity():
    p = _mod()
    p.declare("sys-t", 1)
    enf = p.enforce("sys-t", 2)
    n_before = len(p.audit_log(3))
    v1 = p.verify("enf-1", 4)
    v2 = p.verify("enf-1", 4)  # same seq twice: pure read
    assert v1.verdict == "verified" and v2.verdict == "verified"
    assert v1.digest == v2.digest
    assert len(p.audit_log(5)) == n_before  # no new audit rows
    assert v1.verify()
    with pytest.raises(ap.UnknownEnforcementError):
        p.verify("enf-999", 6)
    # tamper reported as data, never raised
    object.__setattr__(enf, "verdict", ap.VERDICT_VIOLATION)  # tamper
    vfy = p.verify("enf-1", 7)
    assert vfy.verdict == "tampered"
    assert not vfy.integrity_ok
    assert vfy.verify()  # the report itself still pins cleanly
    rep = p.report(8, "sys-t")
    assert not rep.integrity_ok


# 10. report posture math ----------------------------------------------------------------

def test_report_posture_math():
    p = _mod()
    p.declare("s1", 1)
    assert p.report(2, "s1").posture == "unevaluated"
    p.enforce("s1", 3, verdict=ap.VERDICT_COMPLIANT)
    assert p.report(4, "s1").posture == "enforced"
    p.enforce("s1", 5, verdict=ap.VERDICT_WAIVED)
    assert p.report(6, "s1").posture == "partially-enforced"
    p.enforce("s1", 7, verdict=ap.VERDICT_INCONCLUSIVE)
    assert p.report(8, "s1").posture == "contested"
    p.enforce("s1", 9, verdict=ap.VERDICT_VIOLATION)
    rep = p.report(10, "s1")
    assert rep.posture == "non-compliant"  # violation outranks everything
    assert rep.violation_count == 1 and rep.compliant_count == 1
    assert rep.waived_count == 1
    assert rep.enforcement_count == 4 and rep.verify()
    # suspended statuses counted among policies
    p.declare("s2", 11, status=ap.STATUS_SUSPENDED)
    rep2 = p.report(12, "s2")
    assert rep2.policy_count == 1 and rep2.posture == "unevaluated"
    # whole-ledger scope
    whole = p.report(13)
    assert whole.system_id == "" and whole.enforcement_count == 4
    with pytest.raises(ap.UnknownSystemError):
        p.report(14, "ghost")


# 11. report read purity + retire terminality ----------------------------------------------

def test_report_read_purity_and_retire_terminality():
    p = _mod()
    p.declare("sys-r", 1)
    p.enforce("sys-r", 2)
    n_before = len(p.audit_log(3))
    r1 = p.report(4, "sys-r")
    r2 = p.report(4, "sys-r")  # same seq twice: pure read
    assert r1.digest == r2.digest
    assert len(p.audit_log(5)) == n_before  # no new audit rows
    with pytest.raises(ap.BadReasonError):
        p.retire("sys-r", 6, reason="nope")
    rec = p.retire("sys-r", 7, reason=ap.REASON_DECOMMISSIONED)
    assert rec.verify()
    assert p.retired_ids(8) == ("sys-r",)
    # double retire refused
    with pytest.raises(ap.RetiredSystemError):
        p.retire("sys-r", 9)
    # retired ids never recycled
    with pytest.raises(ap.RetiredSystemError):
        p.declare("sys-r", 10)
    with pytest.raises(ap.RetiredSystemError):
        p.enforce("sys-r", 11)
    # reads still work post-retire
    assert p.policies_for("sys-r", 12) == ("pol-1",)
    assert p.enforcements_for("sys-r", 13) == ("enf-1",)
    assert p.report(14, "sys-r").posture == "enforced"
    with pytest.raises(ap.UnknownSystemError):
        p.retire("ghost", 15)


# 12. seq discipline --------------------------------------------------------------------------

def test_seq_discipline():
    p = _mod()
    # rewind raises bare without consuming
    p.declare("sys-s", 5)
    n_before = len(p.audit_log(6))
    with pytest.raises(ap.SeqOrderError):
        p.declare("sys-s2", 5)
    assert len(p.audit_log(7)) == n_before
    # malformed seqs
    for bad in (True, "1", 1.5, None, -1):
        with pytest.raises(ap.SeqOrderError):
            p.declare("sys-s3", bad)
    # failed mutation consumes its seq (claim-then-burn)
    with pytest.raises(ap.BadPolicyKindError):
        p.declare("sys-s4", 8, policy_kind="bogus")
    rec = p.declare("sys-s5", 9)
    assert rec.seq == 9


# 13. audit event shapes + leak ban ------------------------------------------------------------

def test_audit_event_shapes_and_leak_ban():
    ev = ap.ai_policy_audit_event(ap.KIND_ENFORCED, 1, enforcement_id="enf-1")
    assert ev["schema"] == ap.AUDIT_SCHEMA
    assert ev["audit_seq"] == 1
    with pytest.raises(ap.AuditKindError):
        ap.ai_policy_audit_event("bogus-kind", 2)
    with pytest.raises(ap.AuditKindError):
        ap.ai_policy_audit_event(ap.KIND_ENFORCED, 3, policy_text="raw")
    with pytest.raises(ap.AuditKindError):
        ap.ai_policy_audit_event(ap.KIND_POLICY_DECLARED, 4, evidence="x")
    p = _mod()
    p.declare("sys-l", 1, policy_kind=ap.POLICY_ACCESS)
    p.enforce("sys-l", 2, verdict=ap.VERDICT_COMPLIANT)
    rows = p.audit_log(3)
    assert rows[0]["kind"] == ap.KIND_POLICY_DECLARED
    assert rows[1]["kind"] == ap.KIND_ENFORCED
    assert all("policy_text" not in r["detail"] for r in rows)


# 14. cross-instance digest determinism -------------------------------------------------------

def test_cross_instance_digest_determinism():
    def build():
        p = ap.AIPolicy()
        p.declare("sys-d", 1, policy_kind=ap.POLICY_MONITORING,
                  status=ap.STATUS_ACTIVE, policy_digest=D)
        p.enforce("sys-d", 2,
                  enforcement_kind=ap.ENFORCE_USAGE_REVIEW,
                  verdict=ap.VERDICT_COMPLIANT,
                  enforcement_digest=D)
        return p

    p1, p2 = build(), build()
    assert p1.enforcement_record("enf-1", 3).digest == \
        p2.enforcement_record("enf-1", 3).digest
    assert p1.policy_record("pol-1", 3).digest == \
        p2.policy_record("pol-1", 3).digest
    assert p1.report(4, "sys-d").digest == p2.report(4, "sys-d").digest


# 15. main() subprocess check + read smoke ------------------------------------------------------

def test_main_subprocess_and_read_smoke():
    proc = subprocess.run(
        [sys.executable, ap.__file__], capture_output=True, text=True,
        timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert "ai-policy OK" in proc.stdout
    p = _mod()
    p.declare("sys-x", 1)
    p.enforce("sys-x", 2)
    errs = []

    def read():
        try:
            for _ in range(50):
                p.verify("enf-1", 3)
                p.report(4, "sys-x")
                p.stats(5)
        except Exception as exc:  # pragma: no cover
            errs.append(exc)

    threads = [threading.Thread(target=read) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errs
