"""Tests for the notified-body conformity-assessment ledger, Simulated."""

import ast
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "notified_body.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("notified_body", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["notified_body"] = module
    spec.loader.exec_module(module)
    return module


nb = _load()


# 1. version/schema pins
def test_version_and_schema_pins():
    assert nb.NOTIFIED_BODY_VERSION == "notified-body.v1"
    assert nb.SCHEMA_PIN == "northstar.notified-body.v1"
    assert nb.MODULES == (
        "module-a", "module-b", "module-d", "module-f", "module-g",
        "module-h1",
    )
    assert nb.ASSESSMENT_OUTCOMES == ("pass", "minor-nc", "major-nc", "fail")
    assert nb.VALIDITY_YEARS == (1, 2, 3, 4, 5)
    assert nb.SURVEILLANCE_YEARS == (1, 2, 3, 4)
    assert nb.SURVEILLANCE_OUTCOMES == (
        "maintain", "minor-nc", "major-nc", "suspension-recommended",
    )
    assert nb.WITHDRAW_REASONS == (
        "manual", "major-nc-unresolved", "scope-withdrawn", "fraud",
        "certificate-expired",
    )
    assert nb.AUDIT_KINDS == (
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
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module.split(".")[0])
    assert imports <= allowed, f"non-stdlib imports: {imports - allowed}"


# 3. assess roundtrip + verify + frozen
def test_assess_roundtrip_and_verify():
    ledger = nb.NotifiedBody()
    rec = ledger.assess(
        "nb-100", "client-1", "a-1", "module-b", 1,
        outcome="pass", scope_digest=PIN, assessor_digest=PIN2,
    )
    assert rec.verify()
    assert rec.as_dict()["schema"] == "northstar.notified-body.v1"
    fetched = ledger.assessment_record("client-1", "a-1", 2)
    assert fetched == rec
    with pytest.raises(AttributeError):
        rec.outcome = "fail"  # type: ignore[misc]


# 4. duplicate + bad-input table + seq-burn + rejected rows
def test_assess_bad_inputs_and_seq_burn():
    ledger = nb.NotifiedBody()
    ledger.assess("nb-100", "client-1", "a-1", "module-b", 1)
    with pytest.raises(nb.DuplicateAssessmentError):
        ledger.assess("nb-100", "client-1", "a-1", "module-b", 2)
    bad = [
        ("", "client-1", "a-2", "module-b", 3, "pass"),          # bad body
        ("nb-100", "", "a-2", "module-b", 4, "pass"),            # bad client
        ("nb-100", "client-1", "", "module-b", 5, "pass"),       # bad id
        ("nb-100", "client-1", "a-2", "module-x", 6, "pass"),    # bad module
        ("nb-100", "client-1", "a-2", "module-b", 7, "ok"),      # bad outcome
        ("nb-100", "client-1", "a-2", "module-b", 8, "pass"),    # ok after
    ]
    rejected = 0
    for body, client, aid, mod, seq, outcome in bad:
        try:
            if outcome == "pass" and body == "nb-100" and client and aid:
                ledger.assess(body, client, aid, mod, seq, outcome=outcome)
            else:
                ledger.assess(body, client, aid, mod, seq, outcome=outcome)
        except nb.NotifiedBodyError:
            rejected += 1
    assert rejected == 5
    rows = [r for r in ledger.audit_log(9) if r["kind"] == "rejected"]
    assert len(rows) == 1 + 5
    # rewinds raise bare (no rejected row, seq not consumed)
    with pytest.raises(nb.SeqOrderError):
        ledger.assess("nb-100", "client-2", "a-9", "module-a", 8)
    assert len([r for r in ledger.audit_log(10)
                if r["kind"] == "rejected"]) == 1 + 5


# 5. full module vocabulary + certify roundtrip with minted cert id
def test_module_vocabulary_and_certify():
    ledger = nb.NotifiedBody()
    seq = 0
    for i, mod in enumerate(nb.MODULES):
        seq += 1
        rec = ledger.assess("nb-100", f"client-{mod}", f"a-{mod}", mod, seq,
                            outcome="pass")
        assert rec.module == mod
    seq += 1
    cert = ledger.certify("client-module-b", seq, validity_years=3,
                          assessor_digest=PIN)
    assert cert.verify()
    assert cert.certificate_id == "cert-1"
    assert cert.validity_years == 3
    assert cert.basis_assessment_id == "a-module-b"
    fetched = ledger.certificate_record("client-module-b", seq + 1)
    assert fetched == cert


# 6. certify refusals: unknown client / no passing basis / double
def test_certify_refusals():
    ledger = nb.NotifiedBody()
    ledger.assess("nb-100", "client-1", "a-1", "module-d", 1, outcome="fail")
    with pytest.raises(nb.UnknownClientError):
        ledger.certify("ghost", 2)
    with pytest.raises(nb.NotEligibleError):
        ledger.certify("client-1", 3)
    with pytest.raises(nb.BadValidityError):
        ledger.assess("nb-100", "client-2", "a-2", "module-f", 4,
                      outcome="pass")
        ledger.certify("client-2", 5, validity_years=7)
    cert = ledger.certify("client-2", 6)
    assert cert.certificate_id == "cert-1"
    with pytest.raises(nb.AlreadyCertifiedError):
        ledger.certify("client-2", 7)
    rows = [r for r in ledger.audit_log(8) if r["kind"] == "rejected"]
    assert len(rows) == 4  # unknown, ineligible, bad-validity, double


# 7. surveil roundtrip + minted ids + duplicate/year/outcome refusals
def test_surveil_lifecycle():
    ledger = nb.NotifiedBody()
    ledger.assess("nb-100", "client-1", "a-1", "module-b", 1, outcome="pass")
    with pytest.raises(nb.NotCertifiedError):
        ledger.surveil("client-1", 1, 2)
    ledger.certify("client-1", 3)
    s1 = ledger.surveil("client-1", 1, 4, outcome="maintain",
                        assessor_digest=PIN)
    assert s1.verify()
    assert s1.surveillance_id == "svl-1"
    with pytest.raises(nb.DuplicateSurveillanceError):
        ledger.surveil("client-1", 1, 5)
    with pytest.raises(nb.BadYearError):
        ledger.surveil("client-1", 9, 6)
    with pytest.raises(nb.BadOutcomeError):
        ledger.surveil("client-1", 2, 7, outcome="great")
    s2 = ledger.surveil("client-1", 2, 8, outcome="minor-nc")
    assert s2.surveillance_id == "svl-2"
    rows = [r for r in ledger.audit_log(9) if r["kind"] == "rejected"]
    assert len(rows) == 1 + 3


# 8. withdraw terminality + id non-recycling + bad reason
def test_withdraw_terminal():
    ledger = nb.NotifiedBody()
    ledger.assess("nb-100", "client-1", "a-1", "module-g", 1, outcome="pass")
    ledger.certify("client-1", 2)
    with pytest.raises(nb.BadReasonError):
        ledger.withdraw("client-1", 3, reason="bored")
    rec = ledger.withdraw("client-1", 4, reason="fraud")
    assert rec.verify()
    assert ledger.withdrawal_record("client-1", 5) == rec
    for seq, call in [
        (6, lambda: ledger.assess("nb-100", "client-1", "a-2",
                                  "module-g", 6)),
        (7, lambda: ledger.certify("client-1", 7)),
        (8, lambda: ledger.surveil("client-1", 1, 8)),
        (9, lambda: ledger.withdraw("client-1", 9)),
    ]:
        with pytest.raises(nb.WithdrawnError):
            call()
    st = ledger.status("client-1", 10)
    assert st.posture == "withdrawn"


# 9. status postures + read purity + unknown-as-data
def test_status_postures_and_read_purity():
    ledger = nb.NotifiedBody()
    st = ledger.status("ghost", 1)
    assert st.posture == "unknown"
    assert st.n_assessments == 0
    ledger.assess("nb-100", "client-1", "a-1", "module-h1", 2, outcome="fail")
    st = ledger.status("client-1", 3)
    assert st.posture == "not-certified"
    assert st.has_passing_assessment is False
    assert st.integrity_ok is True
    assert st.verify()
    ledger.assess("nb-100", "client-1", "a-2", "module-h1", 4, outcome="pass")
    ledger.certify("client-1", 5)
    st1 = ledger.status("client-1", 6)
    assert st1.posture == "certified"
    assert st1.n_assessments == 2
    assert st1.has_passing_assessment is True
    # pure read: same-seq reads, no seq consumed, no audit rows
    st2 = ledger.status("client-1", 6)
    assert st2 == st1
    rows = [r for r in ledger.audit_log(6)]
    assert all(r["kind"] != "status" for r in rows)


# 10. tamper breaks verify + integrity_ok flips
def test_tamper_breaks_verify():
    ledger = nb.NotifiedBody()
    rec = ledger.assess("nb-100", "client-1", "a-1", "module-b", 1,
                        outcome="pass")
    assert rec.verify()
    object.__setattr__(rec, "outcome", "fail")
    assert not rec.verify()
    st = ledger.status("client-1", 2)
    assert st.integrity_ok is False
    assert st.verify()


# 11. seq discipline: malformed seqs, bool, rewind bare
def test_seq_discipline():
    ledger = nb.NotifiedBody()
    for bad in [0, -1, True, 1.5, "2", None, [3]]:
        with pytest.raises(nb.SeqOrderError):
            ledger.assess("nb-100", "client-1", "a-1", "module-b", bad)
    ledger.assess("nb-100", "client-1", "a-1", "module-b", 1)
    with pytest.raises(nb.SeqOrderError):
        ledger.assess("nb-100", "client-1", "a-2", "module-b", 1)
    rows = [r for r in ledger.audit_log(2) if r["kind"] == "rejected"]
    assert rows == []


# 12. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    ledger = nb.NotifiedBody()
    ledger.assess("nb-100", "client-1", "a-1", "module-b", 1, outcome="pass")
    ledger.certify("client-1", 2)
    ledger.surveil("client-1", 1, 3)
    ledger.withdraw("client-1", 4, reason="manual")
    kinds = [r["kind"] for r in ledger.audit_log(5)]
    assert kinds == ["assessed", "certified", "surveiled", "withdrawn"]
    for row in ledger.audit_log(5):
        assert row["schema"] == "audit.ndjson/1"
        for key in row["details"]:
            assert key not in nb._BANNED_AUDIT_KEYS
    with pytest.raises(nb.AuditKindError):
        nb.notified_body_audit_event("nope", 1)
    with pytest.raises(nb.AuditKindError):
        nb.notified_body_audit_event("assessed", 1, evidence="raw text")
    ev = nb.notified_body_audit_event("assessed", 1, assessment_id="a-1")
    assert ev["schema"] == "audit.ndjson/1"
    # raw material never leaks into the audit log
    joined = str(ledger.audit_log(5))
    for raw in ["nb-100", "client-1"]:
        assert raw not in joined


# 13. cross-instance determinism + views + stats
def test_determinism_views_stats():
    a = nb.NotifiedBody()
    b = nb.NotifiedBody()
    ra = a.assess("nb-100", "c", "a-1", "module-d", 1, outcome="pass",
                  scope_digest=PIN, assessor_digest=PIN2)
    rb = b.assess("nb-100", "c", "a-1", "module-d", 1, outcome="pass",
                  scope_digest=PIN, assessor_digest=PIN2)
    assert ra.digest == rb.digest
    a.certify("c", 2)
    assert a.client_ids(3) == ("c",)
    assert a.assessments_for("c", 3) == ("a-1",)
    assert a.certified_ids(3) == ("c",)
    assert a.stats(3) == {
        "assessments": 1, "certificates": 1, "surveillance": 0,
        "withdrawals": 0, "rejected": 0,
    }
    with pytest.raises(nb.UnknownAssessmentError):
        a.assessment_record("c", "nope", 3)
    with pytest.raises(nb.NotCertifiedError):
        a.certificate_record("ghost", 3)
    with pytest.raises(nb.UnknownClientError):
        a.withdrawal_record("ghost", 3)


# 14. thread read smoke + frozen-ness
def test_concurrency_and_frozen():
    ledger = nb.NotifiedBody()
    ledger.assess("nb-100", "c", "a-1", "module-b", 1, outcome="pass")
    ledger.certify("c", 2)
    errors = []

    def worker():
        try:
            for _ in range(50):
                ledger.status("c", 2)
                ledger.client_ids(2)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    cert = ledger.certificate_record("c", 2)
    with pytest.raises(AttributeError):
        cert.validity_years = 1  # type: ignore[misc]
    st = ledger.status("c", 2)
    with pytest.raises(AttributeError):
        st.posture = "x"  # type: ignore[misc]


# 15. main() self-check + standalone import from /tmp
def test_main_self_check():
    result = subprocess.run(
        [sys.executable, str(MOD)],
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == (
        "notified-body OK: assess, certify, surveil, status, pins, audit"
    )
    result = subprocess.run(
        [sys.executable, "-c",
         "import importlib.util, sys; "
         "spec = importlib.util.spec_from_file_location("
         "'notified_body', r'" + str(MOD) + "'); "
         "m = importlib.util.module_from_spec(spec); "
         "sys.modules['notified_body'] = m; "
         "spec.loader.exec_module(m); "
         "ledger = m.NotifiedBody(); "
         "ledger.assess('nb-1', 'c', 'a-1', 'module-a', 1); "
         "print(ledger.status('c', 2).posture)"],
        capture_output=True, text=True, cwd="/tmp", timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "not-certified"
