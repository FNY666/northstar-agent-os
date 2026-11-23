"""Tests for the ISO 27001 certification-lifecycle ledger, Simulated."""

import ast
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "iso27001.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("iso27001", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["iso27001"] = module
    spec.loader.exec_module(module)
    return module


iso = _load()


# 1. version/schema pins
def test_version_and_schema_pins():
    assert iso.ISO27001_VERSION == "iso27001.v1"
    assert iso.SCHEMA_PIN == "northstar.iso27001.v1"
    assert iso.STAGES == ("stage-1", "stage-2")
    assert iso.ASSESSMENT_OUTCOMES == ("pass", "minor-nc", "major-nc", "fail")
    assert iso.SURVEILLANCE_YEARS == (1, 2)
    assert iso.SURVEILLANCE_OUTCOMES == (
        "maintain", "minor-nc", "major-nc", "suspension-recommended",
    )
    assert iso.WITHDRAW_REASONS == (
        "manual", "major-nc-unresolved", "scope-withdrawn", "fraud",
        "certificate-expired",
    )
    assert iso.AUDIT_KINDS == (
        "assessed", "certified", "surveiled", "withdrawn", "rejected",
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
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    assert imports <= allowed, imports - allowed


# 3. assess roundtrip + verify() + frozen-ness
def test_assess_roundtrip():
    m = iso.ISO27001()
    rec = m.assess("o1", "a1", "stage-2", 1, outcome="pass",
                   scope_digest=PIN, assessor_digest=PIN2)
    assert rec.verify()
    assert rec.stage == "stage-2" and rec.outcome == "pass"
    assert rec.as_dict()["schema"] == iso.SCHEMA_PIN
    fetched = m.assessment_record("o1", "a1", 0)
    assert fetched is rec
    with pytest.raises(Exception):
        rec.org_id = "other"
    rows = m.audit_log(0)
    assert rows[-1]["kind"] == "assessed"
    assert rows[-1]["details"]["assessment_id"] == "a1"


# 4. assess bad-input table + duplicate + seq-burn + rejected rows
def test_assess_bad_inputs_and_burn():
    m = iso.ISO27001()
    n_rejected = 0
    seq = 0
    cases = [
        ("", "a1", "stage-1", "pass"),          # empty org
        ("o1", "", "stage-1", "pass"),          # empty assessment id
        ("o1", "a1", "stage-9", "pass"),        # bad stage
        ("o1", "a1", "stage-1", "maybe"),       # bad outcome
        ("o1", "a1", "stage-1", "pass", "nope"),  # bad scope digest
    ]
    for case in cases:
        seq += 1
        org, aid, stage, outcome = case[:4]
        digest = case[4] if len(case) > 4 else ""
        with pytest.raises(iso.ISO27001Error):
            m.assess(org, aid, stage, seq, outcome=outcome,
                     scope_digest=digest)
        n_rejected += 1
    seq += 1
    m.assess("o1", "a1", "stage-1", seq, outcome="pass")
    seq += 1
    with pytest.raises(iso.DuplicateAssessmentError):
        m.assess("o1", "a1", "stage-2", seq, outcome="pass")
    n_rejected += 1
    rows = m.audit_log(0)
    rejected = [r for r in rows if r["kind"] == "rejected"]
    assert len(rejected) == n_rejected
    assert all(r["details"]["rejected_kind"] == "assess" for r in rejected)
    # failed mutations consumed their seqs
    assert m._seq == seq


# 5. assess full stage + outcome vocabulary
def test_assess_full_vocabulary():
    m = iso.ISO27001()
    seq = 0
    for stage in iso.STAGES:
        for outcome in iso.ASSESSMENT_OUTCOMES:
            seq += 1
            aid = f"{stage}-{outcome}"
            rec = m.assess("o1", aid, stage, seq, outcome=outcome)
            assert rec.verify()
    assert len(m.assessments_for("o1", 0)) == 8


# 6. certify roundtrip: stage-2 pass -> certify, books basis
def test_certify_roundtrip():
    m = iso.ISO27001()
    m.assess("o1", "a1", "stage-1", 1, outcome="pass")
    m.assess("o1", "a2", "stage-2", 2, outcome="minor-nc")
    m.assess("o1", "a3", "stage-2", 3, outcome="pass")
    cert = m.certify("o1", 4)
    assert cert.verify()
    assert cert.basis_assessment_id == "a3"
    assert m.is_certified("o1", 0)
    assert m.certified_ids(0) == ("o1",)
    rows = m.audit_log(0)
    assert rows[-1]["kind"] == "certified"
    assert rows[-1]["details"]["basis_assessment_id"] == "a3"


# 7. certify refusals (no pass / wrong stage / double) + seq-burn
def test_certify_refusals():
    m = iso.ISO27001()
    n_rejected = 0
    # unknown org, no assessments at all
    with pytest.raises(iso.UnknownOrgError):
        m.certify("ghost", 1)
    n_rejected += 1
    # stage-1 pass is not enough
    m.assess("o1", "a1", "stage-1", 2, outcome="pass")
    with pytest.raises(iso.NotEligibleError):
        m.certify("o1", 3)
    n_rejected += 1
    # stage-2 major-nc is not a pass
    m.assess("o2", "a1", "stage-2", 4, outcome="major-nc")
    with pytest.raises(iso.NotEligibleError):
        m.certify("o2", 5)
    n_rejected += 1
    # eligible, then double-certify refused
    m.assess("o1", "a2", "stage-2", 6, outcome="pass")
    m.certify("o1", 7)
    with pytest.raises(iso.AlreadyCertifiedError):
        m.certify("o1", 8)
    n_rejected += 1
    rows = m.audit_log(0)
    rejected = [r for r in rows if r["kind"] == "rejected"]
    assert len(rejected) == n_rejected
    assert all(r["details"]["rejected_kind"] == "certify" for r in rejected)


# 8. surveil roundtrip: year 1 + year 2, minted ids
def test_surveil_roundtrip():
    m = iso.ISO27001()
    m.assess("o1", "a1", "stage-2", 1, outcome="pass")
    m.certify("o1", 2)
    s1 = m.surveil("o1", 1, 3, outcome="maintain")
    assert s1.verify() and s1.surveillance_id == "svl-1"
    s2 = m.surveil("o1", 2, 4, outcome="minor-nc")
    assert s2.verify() and s2.surveillance_id == "svl-2"
    assert len(m.surveillances_for("o1", 0)) == 2
    rows = m.audit_log(0)
    assert rows[-1]["kind"] == "surveiled"


# 9. surveil refusals: not-certified / bad year / duplicate / bad outcome
def test_surveil_refusals():
    m = iso.ISO27001()
    m.assess("o1", "a1", "stage-2", 1, outcome="pass")
    with pytest.raises(iso.NotCertifiedError):
        m.surveil("o1", 1, 2, outcome="maintain")
    m.certify("o1", 3)
    with pytest.raises(iso.BadYearError):
        m.surveil("o1", 3, 4, outcome="maintain")
    with pytest.raises(iso.BadOutcomeError):
        m.surveil("o1", 1, 5, outcome="excellent")
    m.surveil("o1", 1, 6, outcome="maintain")
    with pytest.raises(iso.DuplicateSurveillanceError):
        m.surveil("o1", 1, 7, outcome="maintain")
    rows = m.audit_log(0)
    rejected = [r for r in rows if r["kind"] == "rejected"]
    kinds = [r["details"]["rejected_kind"] for r in rejected]
    assert kinds.count("surveil") == 4
    assert kinds.count("certify") == 0


# 10. withdraw terminality: post-withdraw mutations refused, id never recycled
def test_withdraw_terminality():
    m = iso.ISO27001()
    m.assess("o1", "a1", "stage-2", 1, outcome="pass")
    m.certify("o1", 2)
    m.surveil("o1", 1, 3, outcome="maintain")
    wd = m.withdraw("o1", 4, reason="major-nc-unresolved")
    assert wd.verify()
    assert m.withdrawn_ids(0) == ("o1",)
    assert not m.is_certified("o1", 0)
    with pytest.raises(iso.WithdrawnError):
        m.withdraw("o1", 5, reason="manual")
    with pytest.raises(iso.WithdrawnError):
        m.assess("o1", "a9", "stage-2", 6, outcome="pass")
    with pytest.raises(iso.WithdrawnError):
        m.certify("o1", 7)
    with pytest.raises(iso.WithdrawnError):
        m.surveil("o1", 2, 8, outcome="maintain")
    with pytest.raises(iso.BadReasonError):
        m2 = iso.ISO27001()
        m2.assess("o2", "a1", "stage-1", 1, outcome="pass")
        m2.withdraw("o2", 2, reason="nonsense")
    # reads still work after withdrawal
    rec = m.assessment_record("o1", "a1", 0)
    assert rec.verify()
    st = m.status(0, "o1")
    assert st.posture == "withdrawn"
    rows = m.audit_log(0)
    assert rows[3]["kind"] == "withdrawn"


# 11. seq discipline: rewind bare, malformed seqs, failed-mutation-consumes-seq
def test_seq_discipline():
    m = iso.ISO27001()
    m.assess("o1", "a1", "stage-1", 1, outcome="pass")
    # rewind raises bare, consumes nothing, books no rejected row
    with pytest.raises(iso.SeqOrderError):
        m.assess("o1", "a2", "stage-1", 1, outcome="pass")
    with pytest.raises(iso.SeqOrderError):
        m.certify("o1", 1)
    n_rows = len(m.audit_log(0))
    for bad in (True, "2", -1, 1.5, None):
        with pytest.raises(iso.SeqOrderError):
            m.assess("o1", "ax", "stage-1", bad, outcome="pass")
    assert len(m.audit_log(0)) == n_rows
    # failed mutation consumes its seq: next good seq must be higher
    with pytest.raises(iso.BadStageError):
        m.assess("o1", "a2", "stage-9", 2, outcome="pass")
    m.assess("o1", "a2", "stage-1", 3, outcome="pass")
    rows = m.audit_log(0)
    rejected = [r for r in rows if r["kind"] == "rejected"]
    assert len(rejected) == 1
    assert rejected[0]["seq"] == 2


# 12. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    ev = iso.iso27001_audit_event("assessed", 1, org_id="o1",
                                  assessment_id="a1")
    assert ev["schema"] == "audit.ndjson/1"
    assert ev["kind"] == "assessed" and ev["seq"] == 1
    for kind in iso.AUDIT_KINDS:
        row = iso.iso27001_audit_event(kind, 2)
        assert row["kind"] == kind
    with pytest.raises(iso.AuditKindError):
        iso.iso27001_audit_event("bogus", 1)
    with pytest.raises(iso.SeqOrderError):
        iso.iso27001_audit_event("assessed", -1)
    banned = ["org_name", "organization", "scope", "assessor", "auditor",
              "evidence", "findings", "nonconformity", "report", "text",
              "content", "notes", "payload", "raw", "data", "secret", "key"]
    for key in banned:
        with pytest.raises(iso.AuditKindError):
            iso.iso27001_audit_event("assessed", 1, **{key: "x"})
    # no raw material in the real audit log
    m = iso.ISO27001()
    m.assess("o1", "a1", "stage-2", 1, outcome="pass",
             scope_digest=PIN, assessor_digest=PIN2)
    m.certify("o1", 2)
    m.surveil("o1", 1, 3, outcome="maintain")
    for row in m.audit_log(0):
        for key in row["details"]:
            assert key not in banned, key
        assert "schema" not in row["details"]


# 13. cross-instance digest determinism + tamper breaks verify()
def test_digest_determinism_and_tamper():
    m1, m2 = iso.ISO27001(), iso.ISO27001()
    r1 = m1.assess("o1", "a1", "stage-2", 1, outcome="pass",
                   scope_digest=PIN, assessor_digest=PIN2)
    r2 = m2.assess("o1", "a1", "stage-2", 1, outcome="pass",
                   scope_digest=PIN, assessor_digest=PIN2)
    assert r1.digest == r2.digest
    m1.certify("o1", 2)
    m2.certify("o1", 2)
    assert m1.certification_record("o1", 0).digest == \
        m2.certification_record("o1", 0).digest
    object.__setattr__(r1, "outcome", "fail")
    assert not r1.verify()
    st = m1.status(0, "o1")
    assert not st.integrity_ok


# 14. status report math + read purity
def test_status_math_and_purity():
    m = iso.ISO27001()
    m.assess("o1", "a1", "stage-1", 1, outcome="pass")
    st = m.status(0, "o1")
    assert st.verify()
    assert st.posture == "not-certified"
    assert st.n_assessments == 1 and not st.has_passing_stage2
    assert st.n_surveillance == 0
    m.assess("o1", "a2", "stage-2", 2, outcome="pass")
    m.certify("o1", 3)
    m.surveil("o1", 1, 4, outcome="maintain")
    st2 = m.status(0, "o1")
    assert st2.posture == "certified"
    assert st2.has_passing_stage2 and st2.n_surveillance == 1
    # unknown org -> "unknown" as data, never raised
    st3 = m.status(0, "ghost")
    assert st3.posture == "unknown" and st3.n_assessments == 0
    # read purity: same seq twice, no audit rows, no seq consumption
    n_rows = len(m.audit_log(0))
    m.status(0, "o1")
    m.status(0)
    assert len(m.audit_log(0)) == n_rows
    assert m._seq == 4
    # whole-ledger aggregate
    agg = m.status(0)
    assert agg.verify() and agg.n_assessments == 2
    assert agg.n_surveillance == 1


# 15. views/stats + concurrency smoke + main() subprocess check
def test_views_stats_and_main():
    m = iso.ISO27001()
    m.assess("o1", "a1", "stage-2", 1, outcome="pass")
    m.assess("o2", "b1", "stage-1", 2, outcome="minor-nc")
    m.certify("o1", 3)
    assert m.org_ids(0) == ("o1", "o2")
    assert m.assessment_ids(0) == (("o1", "a1"), ("o2", "b1"))
    assert len(m.assessments_for("o2", 0)) == 1
    assert m.is_certified("o2", 0) is False
    stats = m.stats(0)
    assert stats == {"orgs": 2, "assessments": 2, "certified": 1,
                     "withdrawn": 0, "surveillance": 0,
                     "audit_rows": len(m.audit_log(0))}
    with pytest.raises(iso.UnknownAssessmentError):
        m.assessment_record("o1", "nope", 0)
    with pytest.raises(iso.NotCertifiedError):
        m.certification_record("o2", 0)
    with pytest.raises(iso.UnknownAssessmentError):
        m.surveillance_record("o1", 2, 0)
    # frozen records + read concurrency smoke
    rec = m.assessment_record("o1", "a1", 0)
    with pytest.raises(Exception):
        rec.outcome = "fail"
    errs = []

    def reader():
        try:
            for _ in range(50):
                m.status(0, "o1")
                m.stats(0)
        except Exception as exc:  # pragma: no cover
            errs.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errs
    proc = subprocess.run(
        [sys.executable, str(MOD)], capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == \
        "iso27001 OK: assess, certify, surveil, withdraw, pins"
