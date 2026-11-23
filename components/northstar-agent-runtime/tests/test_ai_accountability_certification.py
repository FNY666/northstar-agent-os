"""Tests for ai_accountability_certification.py (15 tests)."""

import ast
import sys
import threading
import types
from pathlib import Path

import pytest

_MODULE_PATH = Path(__file__).parent.parent / "ai_accountability_certification.py"


def _load_module():
    """Load ai_accountability_certification standalone via the house pattern."""
    src = _MODULE_PATH.read_text()
    mod = types.ModuleType("ai_accountability_certification")
    mod.__file__ = str(_MODULE_PATH)
    sys.modules["ai_accountability_certification"] = mod
    code = compile(src, str(_MODULE_PATH), "exec")
    exec(code, mod.__dict__)
    return mod


@pytest.fixture()
def m():
    return _load_module()


@pytest.fixture()
def pin():
    return "sha256:" + "0" * 64


def test_1_pins_and_vocabularies(m):
    assert m.AI_ACCOUNTABILITY_CERTIFICATION_VERSION == "ai-accountability-certification.v1"
    assert m.AI_ACCOUNTABILITY_CERTIFICATION_SCHEMA == "northstar.ai-accountability-certification.v1"
    assert m.AUDIT_SCHEMA == "audit.ndjson/1"
    assert len(m.CERT_KINDS) == 8
    assert len(set(m.CERT_KINDS)) == 8
    assert len(m.OUTCOMES) == 4
    assert len(set(m.OUTCOMES)) == 4
    assert len(m.POSTURES) == 5
    assert m.KIND_ACCOUNTABILITY_CHARTER_REVIEW in m.CERT_KINDS
    assert m.OUTCOME_ACCOUNTABLY_CERTIFIED in m.OUTCOMES
    assert len(m.REASONS) == 4
    assert set(m._KINDS) == {"certified", "retired", "rejected"}


def test_2_stdlib_only(m):
    assert m.stdlib_only()
    tree = ast.parse(_MODULE_PATH.read_text())
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                imports.add(a.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module.split(".")[0])
    assert imports <= {"hashlib", "re", "threading", "dataclasses",
                       "typing", "canonical_json", "__future__", "json"}


def test_3_certify_roundtrip_and_frozen(m, pin):
    ac = m.AIAccountabilityCertification()
    rec = ac.certify("sys-1", m.KIND_ACCOUNTABILITY_CHARTER_REVIEW,
                     m.OUTCOME_ACCOUNTABLY_CERTIFIED, 1, pin)
    assert rec.certification_id == "acf-1"
    assert rec.verify("acf-1", "sys-1", m.KIND_ACCOUNTABILITY_CHARTER_REVIEW,
                      m.OUTCOME_ACCOUNTABLY_CERTIFIED, pin)
    assert not rec.verify("acf-1", "sys-1", m.KIND_ACCOUNTABILITY_CHARTER_REVIEW,
                          m.OUTCOME_SUSPENDED, pin)
    with pytest.raises(Exception):
        rec.seq = 999  # frozen dataclass
    # defaults: empty digest allowed
    rec2 = ac.certify("sys-1", m.KIND_PRE_DEPLOYMENT_ACCOUNTABILITY,
                      m.OUTCOME_CONDITIONAL, 2)
    assert rec2.certification_id == "acf-2"
    assert rec2.cert_digest == ""


def test_4_certify_bad_inputs_burn_seq(m, pin):
    ac = m.AIAccountabilityCertification()
    before = len(ac.audit_log())
    bad = [
        lambda s: ac.certify("", m.KIND_ACCOUNTABILITY_CHARTER_REVIEW,
                             m.OUTCOME_ACCOUNTABLY_CERTIFIED, s),      # empty id
        lambda s: ac.certify("bad id", m.KIND_ACCOUNTABILITY_CHARTER_REVIEW,
                             m.OUTCOME_ACCOUNTABLY_CERTIFIED, s),      # whitespace
        lambda s: ac.certify("sys", "bogus-kind",
                             m.OUTCOME_ACCOUNTABLY_CERTIFIED, s),      # bad kind
        lambda s: ac.certify("sys", m.KIND_ACCOUNTABILITY_CHARTER_REVIEW,
                             "bogus-outcome", s),                       # bad outcome
        lambda s: ac.certify("sys", m.KIND_ACCOUNTABILITY_CHARTER_REVIEW,
                             m.OUTCOME_ACCOUNTABLY_CERTIFIED, s,
                             "not-a-pin"),                             # bad digest
        lambda s: ac.certify(True, m.KIND_ACCOUNTABILITY_CHARTER_REVIEW,
                             m.OUTCOME_ACCOUNTABLY_CERTIFIED, s),      # bool id
    ]
    seq = 0
    for fn in bad:
        seq += 1
        with pytest.raises(m.AIAccountabilityCertificationError):
            fn(seq)
    rejected = [r for r in ac.audit_log()[before:]
                if r["kind"] == "rejected"]
    assert len(rejected) == len(bad)
    assert all(r["seq"] == i + 1 for i, r in enumerate(rejected))
    # bare rewind consumes nothing
    with pytest.raises(m.SeqOrderError):
        ac.certify("sys-1", m.KIND_ACCOUNTABILITY_CHARTER_REVIEW,
                   m.OUTCOME_ACCOUNTABLY_CERTIFIED, 1)
    assert len(ac.audit_log()) == before + len(bad)


def test_5_full_cert_kind_vocabulary(m, pin):
    ac = m.AIAccountabilityCertification()
    for i, kind in enumerate(m.CERT_KINDS, start=1):
        rec = ac.certify("sys-k", kind, m.OUTCOME_ACCOUNTABLY_CERTIFIED, i, pin)
        assert rec.cert_kind == kind
    assert ac.stats()["certifications"] == 8


def test_6_full_outcome_vocabulary_and_tallies(m, pin):
    ac = m.AIAccountabilityCertification()
    for i, outcome in enumerate(m.OUTCOMES, start=1):
        ac.certify("sys-o", m.KIND_INCIDENT_ESCALATION_CLEARANCE, outcome, i, pin)
    ev = ac.evaluate("sys-o", 99)
    assert ev.n_certifications == 4
    assert ev.n_certified == 1
    assert ev.n_conditional == 1
    assert ev.n_suspended == 1
    assert ev.n_revoked == 1
    assert ev.integrity_ok


def test_7_verify_semantics_and_read_purity(m, pin):
    ac = m.AIAccountabilityCertification()
    ac.certify("sys-1", m.KIND_ACCOUNTABILITY_CHARTER_REVIEW,
               m.OUTCOME_ACCOUNTABLY_CERTIFIED, 1, pin)
    vr = ac.verify("acf-1", 2)
    assert vr.verdict == "verified"
    assert vr.verify("acf-1", "verified")
    # read purity: same-seq twice, no audit rows, seq not consumed
    n_rows = len(ac.audit_log())
    vr2 = ac.verify("acf-1", 2)
    assert vr2.verdict == "verified"
    assert len(ac.audit_log()) == n_rows
    # malformed read seq
    with pytest.raises(m.SeqOrderError):
        ac.verify("acf-1", True)
    # unknown certification
    with pytest.raises(m.UnknownCertificationError):
        ac.verify("acf-999", 3)


def test_8_tamper_is_data_not_raised(m, pin):
    ac = m.AIAccountabilityCertification()
    ac.certify("sys-1", m.KIND_ACCOUNTABILITY_CHARTER_REVIEW,
               m.OUTCOME_ACCOUNTABLY_CERTIFIED, 1, pin)
    rec = ac.certification_record("acf-1", 2)
    object.__setattr__(rec, "outcome", m.OUTCOME_REVOKED)  # tamper
    vr = ac.verify("acf-1", 3)  # tamper reported, never raised
    assert vr.verdict == "tampered"
    ev = ac.evaluate("sys-1", 4)
    assert ev.integrity_ok is False
    assert ev.posture == m.POSTURE_REVOKED


def test_9_evaluate_posture_precedence(m, pin):
    ac = m.AIAccountabilityCertification()
    # single transparently-certified -> transparently-certified
    ac.certify("a", m.KIND_ACCOUNTABILITY_CHARTER_REVIEW, m.OUTCOME_ACCOUNTABLY_CERTIFIED, 1)
    assert ac.evaluate("a", 2).posture == m.POSTURE_ACCOUNTABLY_CERTIFIED
    # conditional outranks certified
    ac.certify("b", m.KIND_ACCOUNTABILITY_CHARTER_REVIEW, m.OUTCOME_ACCOUNTABLY_CERTIFIED, 3)
    ac.certify("b", m.KIND_INCIDENT_ESCALATION_CLEARANCE, m.OUTCOME_CONDITIONAL, 4)
    assert ac.evaluate("b", 5).posture == m.POSTURE_CONDITIONAL
    # suspended outranks conditional
    ac.certify("c", m.KIND_ACCOUNTABILITY_CHARTER_REVIEW, m.OUTCOME_CONDITIONAL, 6)
    ac.certify("c", m.KIND_INCIDENT_ESCALATION_CLEARANCE, m.OUTCOME_SUSPENDED, 7)
    assert ac.evaluate("c", 8).posture == m.POSTURE_SUSPENDED
    # revoked outranks everything
    ac.certify("d", m.KIND_ACCOUNTABILITY_CHARTER_REVIEW, m.OUTCOME_ACCOUNTABLY_CERTIFIED, 9)
    ac.certify("d", m.KIND_INCIDENT_ESCALATION_CLEARANCE, m.OUTCOME_REVOKED, 10, pin)
    ev = ac.evaluate("d", 11)
    assert ev.posture == m.POSTURE_REVOKED
    assert ev.verify("d", m.POSTURE_REVOKED)
    assert not ev.verify("d", m.POSTURE_SUSPENDED)


def test_10_evaluate_unknown_system_and_purity(m):
    ac = m.AIAccountabilityCertification()
    with pytest.raises(m.UnknownSystemError):
        ac.evaluate("nope", 1)
    with pytest.raises(m.UnknownCertificationError):
        ac.certification_record("acf-1", 1)
    with pytest.raises(m.SeqOrderError):
        ac.evaluate("nope", -1)


def test_11_retire_terminality(m, pin):
    ac = m.AIAccountabilityCertification()
    ac.certify("sys-1", m.KIND_ACCOUNTABILITY_CHARTER_REVIEW,
               m.OUTCOME_ACCOUNTABLY_CERTIFIED, 1, pin)
    rr = ac.retire("sys-1", 2)
    assert rr.verify("sys-1", m.REASON_MANUAL)
    assert "sys-1" in ac.retired_ids(3)
    with pytest.raises(m.DoubleRetireError):
        ac.retire("sys-1", 4)
    with pytest.raises(m.BadReasonError):
        ac.retire("sys-2", 5, "bogus-reason")
    # post-retire mutations refused (burn seq + rejected row)
    with pytest.raises(m.RetiredSystemError):
        ac.certify("sys-1", m.KIND_INCIDENT_ESCALATION_CLEARANCE,
                   m.OUTCOME_ACCOUNTABLY_CERTIFIED, 6)
    assert ac.audit_log()[-1]["kind"] == "rejected"
    # reads still work
    assert ac.evaluate("sys-1", 7).posture == m.POSTURE_ACCOUNTABLY_CERTIFIED
    assert ac.certification_record("acf-1", 8).system_id == "sys-1"
    # ids never recycled: new certify on another system continues acf-N
    rec = ac.certify("sys-3", m.KIND_RESPONSIBILITY_ASSIGNMENT_SIGNOFF,
                     m.OUTCOME_ACCOUNTABLY_CERTIFIED, 9)
    assert rec.certification_id == "acf-2"


def test_12_seq_discipline(m):
    ac = m.AIAccountabilityCertification()
    # genesis: seq must be >= 0; first claim of 0 ok; malformed bare
    with pytest.raises(m.SeqOrderError):
        ac.certify("s", m.KIND_ACCOUNTABILITY_CHARTER_REVIEW,
                   m.OUTCOME_ACCOUNTABLY_CERTIFIED, -1)  # malformed, bare
    assert len(ac.audit_log()) == 0
    rec = ac.certify("s", m.KIND_ACCOUNTABILITY_CHARTER_REVIEW,
                     m.OUTCOME_ACCOUNTABLY_CERTIFIED, 0)
    assert rec.seq == 0
    # malformed seq shapes never consume
    rows_before = len(ac.audit_log())
    for bad in (True, 1.5, "3"):
        with pytest.raises(m.SeqOrderError):
            ac.certify("s", m.KIND_ACCOUNTABILITY_CHARTER_REVIEW,
                       m.OUTCOME_ACCOUNTABLY_CERTIFIED, bad)
    assert len(ac.audit_log()) == rows_before
    # genuine rewind raises bare (not a failed mutation -> no rejected row)
    rows_before_rewind = len(ac.audit_log())
    with pytest.raises(m.SeqOrderError):
        ac.certify("s", m.KIND_ACCOUNTABILITY_CHARTER_REVIEW,
                   m.OUTCOME_ACCOUNTABLY_CERTIFIED, 0)
    assert len(ac.audit_log()) == rows_before_rewind
    # failed mutation consumes seq and books rejected
    with pytest.raises(m.BadCertKindError):
        ac.certify("s", "nope", m.OUTCOME_ACCOUNTABLY_CERTIFIED, 5)
    assert ac.audit_log()[-1] == {
        "schema": "audit.ndjson/1",
        "module": "ai-accountability-certification.v1",
        "kind": "rejected",
        "seq": 5,
        "detail": {"system_id": "s"},
    }
    # gap seqs allowed
    ac.certify("s", m.KIND_INCIDENT_ESCALATION_CLEARANCE,
               m.OUTCOME_ACCOUNTABLY_CERTIFIED, 100)


def test_13_audit_shapes_and_leak_ban(m, pin):
    ac = m.AIAccountabilityCertification()
    ac.certify("sys-1", m.KIND_ACCOUNTABILITY_CHARTER_REVIEW,
               m.OUTCOME_ACCOUNTABLY_CERTIFIED, 1, pin)
    rows = ac.audit_log()
    assert rows[0]["schema"] == "audit.ndjson/1"
    assert rows[0]["module"] == "ai-accountability-certification.v1"
    assert rows[0]["kind"] == "certified"
    assert rows[0]["detail"]["cert_kind"] == m.KIND_ACCOUNTABILITY_CHARTER_REVIEW
    assert rows[0]["detail"]["outcome"] == m.OUTCOME_ACCOUNTABLY_CERTIFIED
    # raw material banned at audit boundary
    with pytest.raises(m.AuditKindError):
        m.ai_accountability_certification_audit_event(
            "certified", {"accountability_charter": "raw text"}, 9)
    with pytest.raises(m.AuditKindError):
        m.ai_accountability_certification_audit_event(
            "certified", {"responsibility_assignment": "..."}, 9)
    with pytest.raises(m.AuditKindError):
        m.ai_accountability_certification_audit_event(
            "certified", {"escalation_record": "..."}, 9)
    with pytest.raises(m.AuditKindError):
        m.ai_accountability_certification_audit_event(
            "certified", {"incident_report": "..."}, 9)
    # pinned vocab values remain emittable
    ok = m.ai_accountability_certification_audit_event(
        "certified",
        {"cert_kind": m.KIND_ACCOUNTABILITY_CHARTER_REVIEW,
         "outcome": m.OUTCOME_ACCOUNTABLY_CERTIFIED,
         "cert_digest": pin}, 9)
    assert ok["kind"] == "certified"
    with pytest.raises(m.AuditKindError):
        m.ai_accountability_certification_audit_event("bogus", {}, 9)
    # retire row shape
    ac.retire("sys-1", 2)
    assert ac.audit_log()[-1]["kind"] == "retired"


def test_14_views_stats_determinism_and_threads(m, pin):
    ac = m.AIAccountabilityCertification()
    ac.certify("sys-1", m.KIND_ACCOUNTABILITY_CHARTER_REVIEW,
               m.OUTCOME_ACCOUNTABLY_CERTIFIED, 1, pin)
    ac.certify("sys-1", m.KIND_INCIDENT_ESCALATION_CLEARANCE,
               m.OUTCOME_CONDITIONAL, 2, pin)
    ac.certify("sys-2", m.KIND_HUMAN_OVERSIGHT_READINESS,
               m.OUTCOME_ACCOUNTABLY_CERTIFIED, 3, pin)
    assert ac.certifications_for("sys-1", 4) == ("acf-1", "acf-2")
    assert ac.system_ids(5) == ("sys-1", "sys-2")
    with pytest.raises(m.UnknownSystemError):
        ac.certifications_for("ghost", 6)
    st = ac.stats()
    assert st == {"systems": 2, "certifications": 3, "retired": 0,
                  "audit_rows": 3}
    # cross-instance digest determinism
    other = m.AIAccountabilityCertification()
    other.certify("sys-1", m.KIND_ACCOUNTABILITY_CHARTER_REVIEW,
                  m.OUTCOME_ACCOUNTABLY_CERTIFIED, 1, pin)
    assert (other.certification_record("acf-1", 9).digest ==
            ac.certification_record("acf-1", 9).digest)
    # 8-thread read smoke
    errors = []

    def reader():
        try:
            for _ in range(50):
                ac.evaluate("sys-1", 10)
                ac.verify("acf-1", 11)
                ac.system_ids(12)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors


def test_15_main_self_check_subprocess():
    import subprocess
    proc = subprocess.run(
        [sys.executable, str(_MODULE_PATH)],
        capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert ("ai-accountability-certification OK: certify, verify, evaluate, "
            "retire, pins, audit") in proc.stdout
