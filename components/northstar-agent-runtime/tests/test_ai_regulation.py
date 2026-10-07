"""Tests for the ai_regulation decision ledger (15 tests)."""

import ast
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import ai_regulation as m

RUNTIME_DIR = Path(__file__).resolve().parent.parent


def _good_digest() -> str:
    return "sha256:" + "ab" * 32


# 1. version / schema / vocabulary pins
def test_pins_and_vocabularies():
    assert m.AI_REGULATION_VERSION == "ai-regulation.v1"
    assert m.AI_REGULATION_SCHEMA == "northstar.ai-regulation.v1"
    assert m.AUDIT_SCHEMA == "audit.ndjson/1"
    assert len(m.REGULATIONS) == 8 and len(set(m.REGULATIONS)) == 8
    assert len(m.RISK_TIERS) == 4 and len(set(m.RISK_TIERS)) == 4
    assert len(m.ACTIONS) == 8 and len(set(m.ACTIONS)) == 8
    assert len(m.RETIRE_REASONS) == 3
    assert len(m.POSTURES) == 4 and len(set(m.POSTURES)) == 4
    assert m.KIND_ASSESSED in ("assessed",) or True
    kinds = {m.KIND_ASSESSED, m.KIND_ENFORCED, m.KIND_RETIRED,
             m.KIND_REJECTED}
    assert kinds == {"assessed", "enforced", "retired", "rejected"}


# 2. stdlib-only AST check
def test_stdlib_only():
    allowed = set(getattr(sys, "stdlib_module_names", ()))
    allowed |= {"canonical_json"}
    tree = ast.parse(Path(m.__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed
        elif isinstance(node, ast.ImportFrom):
            assert node.module is None or \
                node.module.split(".")[0] in allowed
    assert m.stdlib_only()


# 3. assess roundtrip + asm-N minting + verify() + frozen-ness
def test_assess_roundtrip():
    r = m.AIRegulation()
    rec = r.assess("sys-a", 1, regulation=m.REG_NIST_AI_RMF,
                   risk_tier=m.TIER_LIMITED_RISK,
                   assessment_digest=_good_digest())
    assert rec.assessment_id == "asm-1"
    assert rec.system_id == "sys-a"
    assert rec.regulation == m.REG_NIST_AI_RMF
    assert rec.risk_tier == m.TIER_LIMITED_RISK
    assert rec.seq == 1
    assert rec.schema == m.AI_REGULATION_SCHEMA
    assert rec.version == m.AI_REGULATION_VERSION
    assert rec.verify()
    d = rec.as_dict()
    assert d["assessment_id"] == "asm-1" and d["seq"] == 1
    with pytest.raises(Exception):
        rec.risk_tier = "x"  # frozen dataclass
    rec2 = r.assess("sys-a", 2)
    assert rec2.assessment_id == "asm-2"
    rec3 = r.assess("sys-b", 3)
    assert rec3.assessment_id == "asm-3"


# 4. assess bad-input table + seq-burn + rejected-row accounting
def test_assess_bad_inputs():
    r = m.AIRegulation()
    before = len(r.audit_log(0))
    cases = [
        lambda s: r.assess("", s),                              # empty id
        lambda s: r.assess("a" * 257, s),                       # too long
        lambda s: r.assess("has space", s),                      # whitespace
        lambda s: r.assess(123, s),                             # non-str id
        lambda s: r.assess("s1", s, regulation="nope"),          # bad reg
        lambda s: r.assess("s1", s, risk_tier="nope"),           # bad tier
        lambda s: r.assess("s1", s, assessment_digest="zzz"),    # bad digest
        lambda s: r.assess("s1", s, assessment_digest=42),       # non-str
    ]
    for i, fn in enumerate(cases, start=1):
        with pytest.raises(m.AIRegulationError):
            fn(i)
        assert len(r.audit_log(0)) == before + i  # each failure burns + logs
        assert r.stats(0)["seq"] == i  # burned seq
    # rewind is bare: no consumption, no row
    n0 = len(r.audit_log(0))
    with pytest.raises(m.SeqOrderError):
        r.assess("s1", 8)
    assert len(r.audit_log(0)) == n0
    # malformed seqs raise bare, no rows
    for bad in (True, "1", 1.5, None, -1):
        with pytest.raises(m.SeqOrderError):
            r.assess("s1", bad)
    assert len(r.audit_log(0)) == n0
    # retired system refused (fail-closed before vocab checks)
    r.assess("s2", 9)
    r.retire("s2", 10)
    with pytest.raises(m.RetiredSystemError):
        r.assess("s2", 11)
    rows = r.audit_log(0)
    assert rows[-1]["kind"] == "rejected"
    assert rows[-1]["schema"] == m.AUDIT_SCHEMA


# 5. full 8-regulation vocabulary acceptance
def test_all_regulations_accepted():
    r = m.AIRegulation()
    for i, reg in enumerate(m.REGULATIONS, start=1):
        rec = r.assess(f"sys-{i}", i, regulation=reg)
        assert rec.regulation == reg and rec.verify()
    assert r.stats(0)["assessments"] == 8


# 6. full 4-risk-tier vocabulary acceptance
def test_all_risk_tiers_accepted():
    r = m.AIRegulation()
    for i, tier in enumerate(m.RISK_TIERS, start=1):
        rec = r.assess(f"sys-{i}", i, risk_tier=tier)
        assert rec.risk_tier == tier and rec.verify()


# 7. enforce roundtrip + enf-N minting + verify()
def test_enforce_roundtrip():
    r = m.AIRegulation()
    r.assess("sys-a", 1)
    rec = r.enforce("sys-a", 2, action=m.ACTION_CORRECTIVE_ORDER,
                    enforcement_digest=_good_digest())
    assert rec.enforcement_id == "enf-1"
    assert rec.system_id == "sys-a"
    assert rec.action == m.ACTION_CORRECTIVE_ORDER
    assert rec.seq == 2
    assert rec.verify()
    assert rec.as_dict()["enforcement_id"] == "enf-1"
    rec2 = r.enforce("sys-a", 3)
    assert rec2.enforcement_id == "enf-2"


# 8. enforce bad-input table + unknown-system refusal + seq-burn
def test_enforce_bad_inputs():
    r = m.AIRegulation()
    before = len(r.audit_log(0))
    with pytest.raises(m.UnknownSystemError):  # unknown system fail-closed
        r.enforce("ghost", 1)
    assert len(r.audit_log(0)) == before + 1
    r.assess("sys-a", 2)
    cases = [
        lambda s: r.enforce("sys-a", s, action="ban"),             # bad action
        lambda s: r.enforce("sys-a", s, enforcement_digest="zzz"),  # bad digest
        lambda s: r.enforce("", s),                               # empty id
    ]
    for i, fn in enumerate(cases, start=3):
        with pytest.raises(m.AIRegulationError):
            fn(i)
    assert len(r.audit_log(0)) == before + 1 + 1 + 3
    r.retire("sys-a", 6)
    with pytest.raises(m.RetiredSystemError):
        r.enforce("sys-a", 7)
    assert r.audit_log(0)[-1]["kind"] == "rejected"


# 9. full 8-action vocabulary acceptance
def test_all_actions_accepted():
    r = m.AIRegulation()
    r.assess("sys-a", 1)
    for i, action in enumerate(m.ACTIONS, start=2):
        rec = r.enforce("sys-a", i, action=action)
        assert rec.action == action and rec.verify()


# 10. verify semantics + read purity + unknown refusal
def test_verify_semantics():
    r = m.AIRegulation()
    r.assess("sys-a", 1)
    r.enforce("sys-a", 2, action=m.ACTION_NO_ACTION)
    v1 = r.verify("asm-1", 3)
    assert v1.verdict == "verified" and v1.integrity_ok and v1.verify()
    v2 = r.verify("enf-1", 3)  # same seq twice: pure read, no consumption
    assert v2.verdict == "verified"
    assert len(r.audit_log(0)) == 2  # no audit rows for reads
    assert r.stats(0)["seq"] == 2
    with pytest.raises(m.UnknownRecordError):
        r.verify("asm-999", 3)
    # tamper is reported as data, never raised
    rec = r.assessment_record("asm-1", 0)
    object.__setattr__(rec, "risk_tier", m.TIER_MINIMAL_RISK)
    assert not rec.verify()
    v3 = r.verify("asm-1", 3)
    assert v3.verdict == "tampered" and not v3.integrity_ok
    assert v3.verify()
    # report flips integrity_ok as data
    rep = r.report(3, "sys-a")
    assert not rep.integrity_ok and rep.verify()


# 11. report posture math + precedence + read purity + unknown refusal
def test_report_posture_math():
    r = m.AIRegulation()
    with pytest.raises(m.UnknownSystemError):
        r.report(1, "ghost")
    assert r.report(1).posture == "unassessed"
    r.assess("s1", 2)                       # assessed, no enforcement
    assert r.report(3, "s1").posture == "compliant"
    r.enforce("s1", 4, action=m.ACTION_WARNING)   # measure -> under-enforcement
    rep = r.report(5, "s1")
    assert rep.posture == "under-enforcement"
    assert rep.assessment_count == 1 and rep.enforcement_count == 1
    assert rep.measure_count == 1 and rep.restricted_count == 0
    assert rep.verify()
    r.enforce("s1", 6, action=m.ACTION_FINE)     # restrictive outranks
    assert r.report(7, "s1").posture == "restricted"
    r.assess("s2", 8)
    r.enforce("s2", 9, action=m.ACTION_NO_ACTION)
    assert r.report(10, "s2").posture == "compliant"
    whole = r.report(11)  # whole-ledger scope
    assert whole.posture == "restricted" and whole.system_id == ""
    assert whole.assessment_count == 2 and whole.enforcement_count == 3
    assert whole.verify()
    # read purity: same seq twice, no rows, no consumption (seq stays 9)
    n0 = len(r.audit_log(0))
    r.report(11)
    assert len(r.audit_log(0)) == n0 and r.stats(0)["seq"] == 9
    for bad in (True, "x", -1):
        with pytest.raises(m.SeqOrderError):
            r.report(bad)


# 12. retire terminality + id non-recycling + bad reason + post-retire reads
def test_retire_terminality():
    r = m.AIRegulation()
    r.assess("sys-a", 1)
    r.enforce("sys-a", 2, action=m.ACTION_NO_ACTION)
    with pytest.raises(m.UnknownSystemError):
        r.retire("ghost", 3)
    with pytest.raises(m.BadReasonError):
        r.retire("sys-a", 4, reason="nope")
    ret = r.retire("sys-a", 5, reason=m.REASON_DECOMMISSIONED)
    assert ret.verify() and ret.reason == m.REASON_DECOMMISSIONED
    assert r.retired_ids(0) == ("sys-a",)
    with pytest.raises(m.RetiredSystemError):  # double retire refused
        r.retire("sys-a", 6)
    with pytest.raises(m.RetiredSystemError):  # id never recycled
        r.assess("sys-a", 7)
    with pytest.raises(m.RetiredSystemError):
        r.enforce("sys-a", 8)
    # reads still work post-retire
    assert r.assessment_record("asm-1", 0).system_id == "sys-a"
    assert r.verify("enf-1", 0).verdict == "verified"
    assert r.report(9, "sys-a").posture == "compliant"
    assert len(r.audit_log(0)) > 0
    assert r.audit_log(0)[-1]["kind"] == "rejected"


# 13. seq discipline
def test_seq_discipline():
    r = m.AIRegulation()
    # genesis rewind is bare: zero rows
    n0 = len(r.audit_log(0))
    with pytest.raises(m.SeqOrderError):
        r.assess("s1", 0)
    assert len(r.audit_log(0)) == n0 and r.stats(0)["seq"] == 0
    r.assess("s1", 5)
    with pytest.raises(m.SeqOrderError):  # rewind: no row, no consumption
        r.assess("s1", 5)
    assert len(r.audit_log(0)) == 1 and r.stats(0)["seq"] == 5
    # failed mutation consumes seq + books rejected row
    with pytest.raises(m.BadRegulationError):
        r.assess("s1", 6, regulation="nope")
    assert r.stats(0)["seq"] == 6
    assert r.audit_log(0)[-1]["kind"] == "rejected"
    assert r.audit_log(0)[-1]["detail"]["rejected_kind"] == "BadRegulationError"
    # malformed seqs on reads
    for bad in (True, "6", 1.5, None):
        with pytest.raises(m.SeqOrderError):
            r.report(bad)


# 14. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    r = m.AIRegulation()
    r.assess("sys-a", 1)
    r.enforce("sys-a", 2, action=m.ACTION_WARNING)
    r.retire("sys-a", 3)
    rows = r.audit_log(0)
    assert [row["kind"] for row in rows] == ["assessed", "enforced", "retired"]
    for row in rows:
        assert row["schema"] == m.AUDIT_SCHEMA
        assert row["version"] == m.AI_REGULATION_VERSION
        assert isinstance(row["audit_seq"], int)
    # every banned key refused at the builder
    for key in m._BANNED_DETAIL_KEYS:
        with pytest.raises(m.AuditKindError):
            m.ai_regulation_audit_event("assessed", 9, **{key: "x"})
    # pinned vocab values remain emittable as declared data
    row = m.ai_regulation_audit_event("assessed", 9, regulation=m.REG_EU_AI_ACT,
                                      risk_tier=m.TIER_HIGH_RISK)
    assert row["detail"]["regulation"] == m.REG_EU_AI_ACT
    with pytest.raises(m.AuditKindError):
        m.ai_regulation_audit_event("bogus-kind", 9)
    with pytest.raises(m.SeqOrderError):
        m.ai_regulation_audit_event("assessed", -1)


# 15. cross-instance determinism + tamper + read smoke + main()
def test_determinism_tamper_threads_main():
    a = m.AIRegulation()
    b = m.AIRegulation()
    ra = a.assess("sys", 1, assessment_digest=_good_digest())
    rb = b.assess("sys", 1, assessment_digest=_good_digest())
    assert ra.digest == rb.digest  # deterministic across instances
    ea = a.enforce("sys", 2)
    eb = b.enforce("sys", 2)
    assert ea.digest == eb.digest
    object.__setattr__(ra, "regulation", m.REG_ISO_42001)  # tamper
    assert not ra.verify() and rb.verify()
    assert a.verify("asm-1", 2).verdict == "tampered"
    assert a.report(2, "sys").integrity_ok is False
    # views/stats
    assert a.assessments_for("sys", 0)[0].assessment_id == "asm-1"
    assert a.enforcements_for("sys", 0)[0].enforcement_id == "enf-1"
    assert a.system_ids(0) == ("sys",)
    assert a.assessment_ids(0) == ("asm-1",)
    assert a.enforcement_ids(0) == ("enf-1",)
    st = a.stats(0)
    assert st["assessments"] == 1 and st["enforcements"] == 1
    with pytest.raises(m.UnknownRecordError):
        a.assessment_record("asm-999", 0)
    assert a.assessments_for("nobody", 0) == ()
    # 8-thread read smoke
    errs = []
    def reader():
        try:
            for _ in range(50):
                a.report(3, "sys")
                a.verify("enf-1", 3)
        except Exception as exc:  # noqa: BLE001
            errs.append(exc)
    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errs
    # frozen records
    with pytest.raises(Exception):
        ea.action = "x"
    # main() subprocess check
    proc = subprocess.run([sys.executable, "-m", "ai_regulation"],
                          cwd=RUNTIME_DIR, capture_output=True, text=True,
                          timeout=30)
    assert proc.returncode == 0, proc.stderr
    assert "ai-regulation OK" in proc.stdout
