"""Tests for the ai_liability decision ledger (Simulated).

House contract: frozen records, caller int seqs strictly increasing
with claim-then-burn, no wall-clock, RLock-guarded, fail-closed
taxonomy, stdlib-only AST-verified, sha256: digest pins, audit.ndjson/1.
"""
from __future__ import annotations

import ast
import hashlib
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import ai_liability
from ai_liability import (
    AI_LIABILITY_SCHEMA,
    AI_LIABILITY_VERSION,
    ASSIGNEE_DEVELOPER,
    ASSIGNEE_DEPLOYER,
    ASSIGNEE_DISTRIBUTOR,
    ASSIGNEE_KINDS,
    ASSIGNEE_MANUFACTURER,
    ASSIGNEE_OPERATOR,
    ASSIGNEE_UNASSIGNED,
    ASSIGNEE_USER,
    AILiability,
    AILiabilityError,
    AuditKindError,
    BadAssigneeKindError,
    BadBasisError,
    BadDigestError,
    BadFindingError,
    BadLiabilityKindError,
    BadReasonError,
    BadSeverityError,
    BadSystemError,
    BASES,
    BASIS_CONTRACTUAL,
    BASIS_FAULT_BASED,
    BASIS_STATUTORY,
    BASIS_STRICT_LIABILITY,
    FINDINGS,
    FINDING_INCONCLUSIVE,
    FINDING_LIABLE,
    FINDING_NOT_ASSESSED,
    FINDING_NOT_LIABLE,
    FINDING_SHARED_LIABILITY,
    KIND_DEVELOPER_LIABILITY,
    KIND_OPERATOR_LIABILITY,
    KIND_PRODUCT_LIABILITY,
    KIND_STATUTORY_LIABILITY,
    LIABILITY_KINDS,
    POSTURES,
    POSTURE_CLEARED,
    POSTURE_CONTESTED,
    POSTURE_LIABILITY_OPEN,
    POSTURE_UNASSESSED,
    POSTURE_UNEVALUATED,
    REASON_SETTLED,
    RETIRE_REASONS,
    RetiredSystemError,
    SeqOrderError,
    UnknownAssessmentError,
    UnknownAssignmentError,
    UnknownSystemError,
    ai_liability_audit_event,
    stdlib_only,
)


def _good_digest() -> str:
    return "sha256:" + "ab" * 32


# ---------------------------------------------------------------------------
# 1. pins
# ---------------------------------------------------------------------------

def test_version_and_schema_pins() -> None:
    assert AI_LIABILITY_VERSION == "ai-liability.v1"
    assert AI_LIABILITY_SCHEMA == "northstar.ai-liability.v1"
    assert len(LIABILITY_KINDS) == 8
    assert len(FINDINGS) == 5
    assert len(ASSIGNEE_KINDS) == 8
    assert len(BASES) == 4
    assert len(POSTURES) == 5
    assert len(RETIRE_REASONS) == 4
    assert POSTURE_UNEVALUATED in POSTURES


# ---------------------------------------------------------------------------
# 2. stdlib-only AST check
# ---------------------------------------------------------------------------

def test_stdlib_only() -> None:
    assert stdlib_only()
    src = Path(ai_liability.__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    allowed = set(getattr(sys, "stdlib_module_names", ())) | {"canonical_json"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed
        elif isinstance(node, ast.ImportFrom):
            assert node.module is None or node.module.split(".")[0] in allowed


# ---------------------------------------------------------------------------
# 3. assess roundtrip + verify + frozen-ness
# ---------------------------------------------------------------------------

def test_assess_roundtrip_verify_frozen() -> None:
    ledger = AILiability()
    rec = ledger.assess("sys-1", 1,
                        liability_kind=KIND_PRODUCT_LIABILITY,
                        finding=FINDING_LIABLE, severity=80,
                        assessment_digest=_good_digest())
    assert rec.assessment_id == "asm-1"
    assert rec.system_id == "sys-1"
    assert rec.schema == AI_LIABILITY_SCHEMA
    assert rec.version == AI_LIABILITY_VERSION
    assert rec.verify()
    with pytest.raises(Exception):
        rec.finding = FINDING_NOT_LIABLE  # frozen dataclass


# ---------------------------------------------------------------------------
# 4. assess bad-input table + seq-burn + rejected-row accounting
# ---------------------------------------------------------------------------

def test_assess_bad_inputs_burn_seq() -> None:
    ledger = AILiability()
    bad_calls = [
        lambda: ledger.assess("", 1),
        lambda: ledger.assess("sys x", 2),
        lambda: ledger.assess("sys-1", 3, liability_kind="not-a-kind"),
        lambda: ledger.assess("sys-1", 4, finding="not-a-finding"),
        lambda: ledger.assess("sys-1", 5, severity=-1),
        lambda: ledger.assess("sys-1", 6, severity=101),
        lambda: ledger.assess("sys-1", 7, severity=True),
        lambda: ledger.assess("sys-1", 8, assessment_digest="sha256:zzz"),
        lambda: ledger.assess("sys-1", 9, assessment_digest=123),
    ]
    errors = (BadSystemError, BadLiabilityKindError, BadFindingError,
              BadSeverityError, BadDigestError)
    for fn in bad_calls:
        with pytest.raises(errors):
            fn()
    # retired-system refusal also burns
    ledger.assess("sys-r", 10)
    ledger.retire("sys-r", 11)
    with pytest.raises(RetiredSystemError):
        ledger.assess("sys-r", 12)
    # every failed mutation consumed its seq and booked a rejected row
    rows = [e for e in ledger.audit_log(100) if e["kind"] == "rejected"]
    assert len(rows) == 10
    assert ledger.stats(100)["seq"] == 12
    # seq rewind raises bare: no burn, no audit row
    with pytest.raises(SeqOrderError):
        ledger.assess("sys-1", 1)
    assert len([e for e in ledger.audit_log(100)
                if e["kind"] == "rejected"]) == 10


# ---------------------------------------------------------------------------
# 5. full 8-kind liability vocabulary acceptance
# ---------------------------------------------------------------------------

def test_all_liability_kinds_accepted() -> None:
    ledger = AILiability()
    for i, kind in enumerate(LIABILITY_KINDS):
        rec = ledger.assess(f"sys-{i}", i + 1, liability_kind=kind)
        assert rec.liability_kind == kind and rec.verify()
    assert ledger.stats(100)["assessments"] == 8


# ---------------------------------------------------------------------------
# 6. full 5-finding vocabulary + severity bounds
# ---------------------------------------------------------------------------

def test_all_findings_and_severity_bounds() -> None:
    ledger = AILiability()
    for i, finding in enumerate(FINDINGS):
        rec = ledger.assess("sys-1", i + 1, finding=finding,
                            severity=100 - i * 25)
        assert rec.finding == finding and rec.verify()
    # severity bounds 0 and 100 accepted
    ledger.assess("sys-2", 6, severity=0)
    ledger.assess("sys-3", 7, severity=100)
    assert ledger.stats(100)["assessments"] == 7


# ---------------------------------------------------------------------------
# 7. assign roundtrip + assessment linkage + verify
# ---------------------------------------------------------------------------

def test_assign_roundtrip_and_linkage() -> None:
    ledger = AILiability()
    rec = ledger.assess("sys-1", 1, finding=FINDING_LIABLE)
    asg = ledger.assign(rec.assessment_id, 2,
                        assignee_kind=ASSIGNEE_MANUFACTURER,
                        basis=BASIS_STRICT_LIABILITY,
                        assignment_digest=_good_digest())
    assert asg.assignment_id == "asg-1"
    assert asg.assessment_id == "asm-1"
    assert asg.system_id == "sys-1"
    assert asg.schema == AI_LIABILITY_SCHEMA
    assert asg.version == AI_LIABILITY_VERSION
    assert asg.verify()
    with pytest.raises(Exception):
        asg.basis = BASIS_CONTRACTUAL  # frozen dataclass


# ---------------------------------------------------------------------------
# 8. assign refusals burn seq
# ---------------------------------------------------------------------------

def test_assign_refusals_burn_seq() -> None:
    ledger = AILiability()
    rec = ledger.assess("sys-1", 1, finding=FINDING_LIABLE)
    with pytest.raises(UnknownAssessmentError):
        ledger.assign("asm-999", 2)
    with pytest.raises(BadAssigneeKindError):
        ledger.assign("asm-1", 3, assignee_kind="not-a-party")
    with pytest.raises(BadBasisError):
        ledger.assign("asm-1", 4, basis="vigilante-justice")
    with pytest.raises(BadDigestError):
        ledger.assign("asm-1", 5, assignment_digest="bogus")
    with pytest.raises(UnknownAssessmentError):
        ledger.assign("", 6)
    # retired system: assessment stays readable but assign refuses
    ledger.retire("sys-1", 7)
    with pytest.raises(RetiredSystemError):
        ledger.assign("asm-1", 8)
    rows = [e for e in ledger.audit_log(100) if e["kind"] == "rejected"]
    assert len(rows) == 6
    assert ledger.stats(100)["seq"] == 8
    assert rec.verify()  # pre-retire assessment still verifies


# ---------------------------------------------------------------------------
# 9. full 8x4 assignee x basis vocabulary acceptance
# ---------------------------------------------------------------------------

def test_all_assignee_basis_combinations() -> None:
    ledger = AILiability()
    rec = ledger.assess("sys-1", 1, finding=FINDING_SHARED_LIABILITY)
    n = 0
    for assignee in ASSIGNEE_KINDS:
        for basis in BASES:
            n += 1
            asg = ledger.assign("asm-1", n + 1, assignee_kind=assignee,
                                basis=basis)
            assert asg.assignee_kind == assignee
            assert asg.basis == basis and asg.verify()
    assert ledger.stats(100)["assignments"] == 32


# ---------------------------------------------------------------------------
# 10. verify semantics + read purity
# ---------------------------------------------------------------------------

def test_verify_semantics_and_read_purity() -> None:
    ledger = AILiability()
    ledger.assess("sys-1", 1, finding=FINDING_LIABLE)
    ledger.assign("asm-1", 2, assignee_kind=ASSIGNEE_DEVELOPER)
    before = len(ledger.audit_log(100))
    seq0 = ledger.stats(100)["seq"]
    v1 = ledger.verify("asm-1", 50)
    v2 = ledger.verify("asm-1", 50)  # same read-seq twice is fine
    assert v1.verdict == "verified" and v1.integrity_ok
    assert v1.digest == v2.digest and v1.verify()
    v3 = ledger.verify("asg-1", 60)
    assert v3.verdict == "verified" and v3.verify()
    # unknown record refused fail-closed
    with pytest.raises(UnknownAssignmentError):
        ledger.verify("asg-999", 61)
    assert ledger.stats(100)["seq"] == seq0  # reads never consume
    assert len(ledger.audit_log(100)) == before  # reads emit no rows


# ---------------------------------------------------------------------------
# 11. evaluate posture math (all reachable postures + precedence)
# ---------------------------------------------------------------------------

def test_evaluate_posture_math() -> None:
    ledger = AILiability()
    # liability-open: liable outranks everything
    ledger.assess("s-open", 1, finding=FINDING_INCONCLUSIVE)
    ledger.assess("s-open", 2, finding=FINDING_LIABLE)
    evl = ledger.evaluate("s-open", 3)
    assert evl.posture == POSTURE_LIABILITY_OPEN and evl.verify()
    assert evl.assessment_count == 2 and evl.liable_count == 1
    assert evl.inconclusive_count == 1 and evl.integrity_ok
    # shared-liability also opens liability
    ledger.assess("s-shared", 4, finding=FINDING_SHARED_LIABILITY)
    assert ledger.evaluate("s-shared", 5).posture == POSTURE_LIABILITY_OPEN
    # contested: any inconclusive outranks unassessed
    ledger.assess("s-con", 6, finding=FINDING_NOT_ASSESSED)
    ledger.assess("s-con", 7, finding=FINDING_INCONCLUSIVE)
    assert ledger.evaluate("s-con", 8).posture == POSTURE_CONTESTED
    # unassessed: any not-assessed, nothing worse
    ledger.assess("s-una", 9, finding=FINDING_NOT_LIABLE)
    ledger.assess("s-una", 10, finding=FINDING_NOT_ASSESSED)
    evl2 = ledger.evaluate("s-una", 11)
    assert evl2.posture == POSTURE_UNASSESSED
    assert evl2.not_liable_count == 1 and evl2.not_assessed_count == 1
    # cleared: all not-liable
    ledger.assess("s-clr", 12, finding=FINDING_NOT_LIABLE)
    ledger.assess("s-clr", 13, finding=FINDING_NOT_LIABLE)
    evl3 = ledger.evaluate("s-clr", 14)
    assert evl3.posture == POSTURE_CLEARED
    assert evl3.not_liable_count == 2 and evl3.verify()
    # assignments tallied alongside assessments
    ledger.assign("asm-7", 15, assignee_kind=ASSIGNEE_USER,
                  basis=BASIS_CONTRACTUAL)
    evl4 = ledger.evaluate("s-una", 16)
    assert evl4.assignment_count == 1
    assert evl4.assignment_ids == ("asg-1",)
    # unknown system refused fail-closed
    with pytest.raises(UnknownSystemError):
        ledger.evaluate("ghost", 17)


# ---------------------------------------------------------------------------
# 12. retire terminality + id non-recycling + post-retire reads
# ---------------------------------------------------------------------------

def test_retire_terminality() -> None:
    ledger = AILiability()
    ledger.assess("sys-1", 1, finding=FINDING_LIABLE)
    ledger.assign("asm-1", 2, assignee_kind=ASSIGNEE_DEPLOYER)
    with pytest.raises(BadReasonError):
        ledger.retire("sys-1", 3, reason="bogus")
    ret = ledger.retire("sys-1", 4, reason=REASON_SETTLED)
    assert ret.verify()
    assert "sys-1" in ledger.retired_ids(100)
    with pytest.raises(RetiredSystemError):
        ledger.assess("sys-1", 5)
    with pytest.raises(RetiredSystemError):
        ledger.assign("asm-1", 6)
    with pytest.raises(RetiredSystemError):
        ledger.retire("sys-1", 7)  # double-retire refused, id never recycled
    # post-retire reads still work
    evl = ledger.evaluate("sys-1", 8)
    assert evl.posture == POSTURE_LIABILITY_OPEN
    v = ledger.verify("asm-1", 9)
    assert v.verdict == "verified"
    v2 = ledger.verify("asg-1", 9)
    assert v2.verdict == "verified"
    assert ledger.assessments_for("sys-1", 9) == ("asm-1",)
    assert ledger.assignments_for("sys-1", 9) == ("asg-1",)
    with pytest.raises(UnknownSystemError):
        ledger.retire("ghost", 10)


# ---------------------------------------------------------------------------
# 13. seq discipline: rewind bare, malformed seqs, failed burn
# ---------------------------------------------------------------------------

def test_seq_discipline() -> None:
    ledger = AILiability()
    for bad in (True, -1, "1", 1.5, None):
        with pytest.raises(SeqOrderError):
            ledger.assess("sys-1", bad)
        with pytest.raises(SeqOrderError):
            ledger.assign("asm-1", bad)
        with pytest.raises(SeqOrderError):
            ledger.evaluate("sys-1", bad)
        with pytest.raises(SeqOrderError):
            ledger.verify("asm-1", bad)
    assert ledger.stats(100)["seq"] == -1  # malformed seqs burn nothing
    ledger.assess("sys-1", 1)
    with pytest.raises(SeqOrderError):
        ledger.assess("sys-1", 1)  # rewind: bare, no row
    assert ledger.stats(100)["seq"] == 1
    with pytest.raises(SeqOrderError):
        ledger.assess("sys-1", 0)  # older than genesis of this instance
    rows = [e for e in ledger.audit_log(100) if e["kind"] == "rejected"]
    assert rows == []


# ---------------------------------------------------------------------------
# 14. audit shapes + leak ban + bad-kind
# ---------------------------------------------------------------------------

def test_audit_shapes_and_leak_ban() -> None:
    ledger = AILiability()
    ledger.assess("sys-1", 1, liability_kind=KIND_OPERATOR_LIABILITY,
                  finding=FINDING_LIABLE, severity=90)
    ledger.assign("asm-1", 2, assignee_kind=ASSIGNEE_OPERATOR,
                  basis=BASIS_STATUTORY)
    ledger.retire("sys-1", 3)
    events = ledger.audit_log(100)
    kinds = [e["kind"] for e in events]
    assert kinds == ["assessed", "assigned", "retired"]
    for e in events:
        assert e["schema"] == "audit.ndjson/1"
        assert e["version"] == AI_LIABILITY_VERSION
        assert e["detail"]["system_id"] == "sys-1"
    # banned raw-material keys never cross the audit boundary
    with pytest.raises(AuditKindError):
        ai_liability_audit_event("assessed", 4, damages="$1M")
    with pytest.raises(AuditKindError):
        ai_liability_audit_event("assigned", 4, lawsuit="case 42")
    with pytest.raises(AuditKindError):
        ai_liability_audit_event("bogus", 4)
    ev = ai_liability_audit_event("assessed", 4, assessment_id="asm-1")
    assert ev["kind"] == "assessed" and ev["audit_seq"] == 4


# ---------------------------------------------------------------------------
# 15. determinism + tamper + threads + main subprocess
# ---------------------------------------------------------------------------

def test_determinism_tamper_threads_main() -> None:
    def build() -> AILiability:
        ledger = AILiability()
        ledger.assess("sys-1", 1,
                      liability_kind=KIND_DEVELOPER_LIABILITY,
                      finding=FINDING_NOT_LIABLE,
                      assessment_digest=_good_digest())
        ledger.assign("asm-1", 2, assignee_kind=ASSIGNEE_DISTRIBUTOR,
                      basis=BASIS_FAULT_BASED)
        return ledger

    a, b = build(), build()
    ra = a.assessment_record("asm-1", 10)
    rb = b.assessment_record("asm-1", 10)
    assert ra.digest == rb.digest
    ga = a.assignment_record("asg-1", 10)
    gb = b.assignment_record("asg-1", 10)
    assert ga.digest == gb.digest
    # tamper flips verify() as data (never raises)
    object.__setattr__(ra, "finding", FINDING_INCONCLUSIVE)
    assert ra.verify() is False
    v = a.verify("asm-1", 11)
    assert v.verdict == "tampered" and v.integrity_ok is False
    evl = a.evaluate("sys-1", 12)
    assert evl.integrity_ok is False
    assert evl.posture == POSTURE_CONTESTED  # tamper is data
    assert evl.verify()

    errors: list = []

    def reader() -> None:
        try:
            for _ in range(50):
                assert a.evaluate("sys-1", 99).integrity_ok is False
                assert a.verify("asg-1", 99).verdict == "verified"
                assert a.stats(99)["assessments"] == 1
        except Exception as exc:  # pragma: no cover - must not happen
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors

    mod_dir = Path(ai_liability.__file__).parent
    proc = subprocess.run(
        [sys.executable, "ai_liability.py"],
        cwd=str(mod_dir), capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert "ai-liability OK" in proc.stdout
