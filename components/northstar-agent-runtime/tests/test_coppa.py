"""Tests for the COPPA compliance decision ledger, Simulated."""

import ast
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "coppa.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32
PIN3 = "sha256:" + "ef" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("coppa", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["coppa"] = module
    spec.loader.exec_module(module)
    return module


cp = _load()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert cp.COPPA_VERSION == "coppa.v1"
    assert cp.SCHEMA_PIN == "northstar.coppa.v1"
    assert cp.COVERAGES == (
        "child-directed",
        "actual-knowledge",
        "not-covered",
    )
    assert cp.CONSENT_METHODS == (
        "email-plus",
        "credit-card",
        "signed-consent",
        "video-conference",
        "knowledge-based",
        "parent-dashboard",
        "none",
    )
    assert cp.VERDICTS == (
        "consent-verified",
        "consent-denied",
        "pending",
        "expired",
    )
    assert cp.DELETION_REASONS == (
        "parent-request",
        "retention-expired",
        "consent-withdrawn",
        "service-closure",
        "manual",
    )
    assert set(cp.AUDIT_KINDS) == {
        "assessed", "verified", "deleted", "rejected",
    }


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


# 3. assess roundtrip + verify + frozen
def test_assess_roundtrip():
    ledger = cp.COPPA()
    record = ledger.assess("svc-1", 1, coverage="child-directed",
                           consent_method="email-plus",
                           data_minimized=True, retention_limited=True,
                           practices_digest=PIN)
    assert record.service_id == "svc-1"
    assert record.coverage == "child-directed"
    assert record.verify()
    assert ledger.assessment_record(1, "svc-1") is record
    assert record.digest.startswith("sha256:")
    with pytest.raises(Exception):
        record.coverage = "actual-knowledge"
    assert record.as_dict()["schema"] == "northstar.coppa.v1"


# 4. assess bad-input table + seq-burn + rejected rows
def test_assess_bad_inputs():
    ledger = cp.COPPA()
    seq = 0
    n_rejected = 0
    bad_cases = [
        ("", "child-directed", "email-plus", True, True, PIN, cp.BadIdError),
        ("svc-x", "bad-coverage", "email-plus", True, True, PIN, cp.BadCoverageError),
        ("svc-x", "child-directed", "bad-method", True, True, PIN, cp.BadMethodError),
        ("svc-x", "child-directed", "email-plus", "yes", True, PIN, cp.CoppaError),
        ("svc-x", "child-directed", "email-plus", True, "yes", PIN, cp.CoppaError),
        ("svc-x", "child-directed", "email-plus", True, True, "raw-text", cp.BadDigestError),
        ("svc-x", "child-directed", "email-plus", True, True, "sha256:xyz", cp.BadDigestError),
        (None, "child-directed", "email-plus", True, True, PIN, cp.BadIdError),
    ]
    for service_id, coverage, method, dm, rl, pin, exc in bad_cases:
        seq += 1
        with pytest.raises(exc):
            ledger.assess(service_id, seq, coverage=coverage,
                          consent_method=method, data_minimized=dm,
                          retention_limited=rl, practices_digest=pin)
        n_rejected += 1
    seq += 1
    ledger.assess("svc-ok", seq, coverage="not-covered",
                  consent_method="none", practices_digest=PIN)
    assert ledger._seq == seq
    rejected = [r for r in ledger.audit_log(seq)
                if r["kind"] == "rejected"]
    assert len(rejected) == n_rejected
    assert ledger.service_ids(seq) == ("svc-ok",)


# 5. duplicate assessment refused
def test_duplicate_assess_refused():
    ledger = cp.COPPA()
    ledger.assess("svc-1", 1)
    with pytest.raises(cp.DuplicateServiceError):
        ledger.assess("svc-1", 2)
    with pytest.raises(cp.UnknownServiceError):
        ledger.assessment_record(2, "nope")


# 6. full coverage/method vocabulary acceptance
def test_full_vocabulary_acceptance():
    ledger = cp.COPPA()
    seq = 0
    for i, coverage in enumerate(cp.COVERAGES):
        seq += 1
        method = cp.CONSENT_METHODS[i % len(cp.CONSENT_METHODS)]
        record = ledger.assess(f"svc-{i}", seq, coverage=coverage,
                               consent_method=method)
        assert record.verify()
    assert ledger.service_ids(seq) == tuple(f"svc-{i}" for i in range(3))


# 7. verify roundtrip + consent minting
def test_verify_roundtrip():
    ledger = cp.COPPA()
    ledger.assess("svc-1", 1)
    first = ledger.verify("svc-1", 2, verdict="consent-verified",
                          consent_digest=PIN)
    assert first.consent_id == "con-1"
    second = ledger.verify("svc-1", 3, verdict="pending",
                           consent_digest=PIN2)
    assert second.consent_id == "con-2"
    assert first.verify() and second.verify()
    assert ledger.verification_record(3, "con-1") is first
    assert ledger.consent_ids(3) == ("con-1", "con-2")
    assert first.as_dict()["verdict"] == "consent-verified"


# 8. verify refusals
def test_verify_refusals():
    ledger = cp.COPPA()
    ledger.assess("svc-1", 1)
    seq = 1
    with pytest.raises(cp.UnknownServiceError):
        ledger.verify("no-such-service", 2)
    seq += 1
    with pytest.raises(cp.BadVerdictError):
        ledger.verify("svc-1", 3, verdict="maybe")
    seq += 1
    with pytest.raises(cp.BadDigestError):
        ledger.verify("svc-1", 4, consent_digest="raw-text")
    rejected = [r for r in ledger.audit_log(4) if r["kind"] == "rejected"]
    assert len(rejected) == 3
    with pytest.raises(cp.UnknownConsentError):
        ledger.verification_record(4, "con-999")


# 9. delete roundtrip + terminality + no recycling
def test_delete_roundtrip_and_terminality():
    ledger = cp.COPPA()
    ledger.assess("svc-1", 1)
    record = ledger.delete("child-1", "svc-1", 2, reason="parent-request")
    assert record.child_data_id == "child-1"
    assert record.verify()
    assert ledger.deleted_ids(2) == ("child-1",)
    with pytest.raises(cp.RetiredDataError):
        ledger.delete("child-1", "svc-1", 3, reason="manual")
    with pytest.raises(cp.UnknownServiceError):
        ledger.delete("child-2", "no-such-service", 4)
    with pytest.raises(cp.BadReasonError):
        ledger.delete("child-3", "svc-1", 5, reason="because")
    with pytest.raises(cp.BadIdError):
        ledger.delete("", "svc-1", 6)
    assert ledger.status(6).n_deleted == 1


# 10. delete all-reason vocabulary
def test_delete_all_reasons():
    ledger = cp.COPPA()
    ledger.assess("svc-1", 1)
    seq = 1
    for i, reason in enumerate(cp.DELETION_REASONS):
        seq += 1
        record = ledger.delete(f"child-{i}", "svc-1", seq, reason=reason)
        assert record.verify()
        assert record.reason == reason
    assert len(ledger.deleted_ids(seq)) == len(cp.DELETION_REASONS)


# 11. seq discipline: rewind raises bare, malformed seqs rejected
def test_seq_discipline():
    ledger = cp.COPPA()
    ledger.assess("svc-1", 5)
    with pytest.raises(cp.SeqOrderError):
        ledger.assess("svc-2", 5)
    with pytest.raises(cp.SeqOrderError):
        ledger.assess("svc-2", 4)
    for bad in (True, False, "7", 7.0, None, -1, 0):
        with pytest.raises(cp.SeqOrderError):
            ledger.assess("svc-2", bad)
    with pytest.raises(cp.SeqOrderError):
        ledger.assess("svc-2", 6 - 1)
    assert ledger.audit_log(5) == ledger.audit_log(6)
    ledger.assess("svc-2", 6)
    assert ledger.audit_log(6)[-1]["kind"] == "assessed"
    with pytest.raises(cp.SeqOrderError):
        ledger.status(-1)


# 12. view read-purity: reads consume no seq, write no audit rows
def test_view_read_purity():
    ledger = cp.COPPA()
    ledger.assess("svc-1", 1)
    ledger.verify("svc-1", 2)
    ledger.delete("child-1", "svc-1", 3)
    before = len(ledger.audit_log(3))
    assert ledger.status(3).n_services == 1
    assert ledger.status(3).n_consents == 1
    assert ledger.status(3).n_deleted == 1
    assert ledger.service_ids(3) == ("svc-1",)
    assert ledger.consent_ids(3) == ("con-1",)
    assert ledger.deleted_ids(3) == ("child-1",)
    assert ledger.stats(3)["n_audit_rows"] == before
    assert len(ledger.audit_log(3)) == before
    assert ledger.stats(3) == {
        "n_services": 1, "n_consents": 1, "n_deleted": 1,
        "n_audit_rows": before,
    }


# 13. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    ledger = cp.COPPA()
    row = cp.coppa_audit_event("assessed", 1, service_id="svc-1")
    assert row["schema"] == "audit.ndjson/1"
    assert row["kind"] == "assessed"
    assert row["seq"] == 1
    row = cp.coppa_audit_event("verified", 2, consent_id="con-1")
    assert row["kind"] == "verified"
    row = cp.coppa_audit_event("deleted", 3, child_data_id="child-1")
    assert row["kind"] == "deleted"
    row = cp.coppa_audit_event("rejected", 4, rejected_kind="assess")
    assert row["kind"] == "rejected"
    with pytest.raises(cp.AuditKindError):
        cp.coppa_audit_event("bogus-kind", 5)
    with pytest.raises(cp.SeqOrderError):
        cp.coppa_audit_event("assessed", -1)
    for key in ("child_name", "email", "birthdate", "parent_name",
                "data", "content", "payload", "ssn"):
        with pytest.raises(cp.AuditKindError):
            cp.coppa_audit_event("assessed", 6, **{key: "raw"})
    ledger.assess("svc-1", 1)
    log = ledger.audit_log(1)
    assert all(row["schema"] == "audit.ndjson/1" for row in log)
    joined = " ".join(str(r["details"]) for r in log)
    for banned in ("'child_name'", "'birthdate'", "'email'", "'ssn'",
                   "'parent_name'"):
        assert banned not in joined


# 14. cross-instance determinism + tamper breaks verify + threads
def test_determinism_and_tamper():
    left = cp.COPPA()
    right = cp.COPPA()
    kwargs = dict(coverage="actual-knowledge",
                  consent_method="signed-consent",
                  practices_digest=PIN2)
    a = left.assess("svc-9", 1, **kwargs)
    b = right.assess("svc-9", 1, **kwargs)
    assert a.digest == b.digest
    assert left.status(1).digest == right.status(1).digest
    object.__setattr__(a, "coverage", "not-covered")
    assert not a.verify()
    assert not left.status(1).integrity_ok

    ledger = cp.COPPA()
    ledger.assess("svc-t", 1)
    errors = []

    def reader():
        try:
            for _ in range(50):
                ledger.status(3)
                ledger.service_ids(3)
        except Exception as e:  # pragma: no cover
            errors.append(e)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors


# 15. main() subprocess self-check
def test_main_subprocess():
    result = subprocess.run(
        [sys.executable, str(MOD)],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert "coppa OK" in result.stdout
