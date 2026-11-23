"""Tests for the FedRAMP authorization decision ledger (15 tests)."""

import ast
import hashlib
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).resolve().parent.parent / "fedramp.py"


def load_module():
    """Import the module standalone via importlib (frozen dataclasses
    need the module registered in sys.modules first)."""
    import importlib.util

    sys.modules.pop("fedramp", None)
    spec = importlib.util.spec_from_file_location("fedramp", str(MODULE_PATH))
    module = importlib.util.module_from_spec(spec)
    sys.modules["fedramp"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def mod():
    return load_module()


@pytest.fixture()
def g(mod):
    return mod.FedRAMP()


def good_digest(label="fedramp"):
    return "sha256:" + hashlib.sha256(label.encode()).hexdigest()


def test_version_and_schema_pins():
    mod = load_module()
    assert mod.VERSION == "fedramp.v1"
    assert mod.SCHEMA == "northstar.fedramp.v1"


def test_stdlib_only():
    tree = ast.parse(MODULE_PATH.read_text())
    allowed = {
        "hashlib", "re", "threading", "dataclasses", "typing",
        "__future__", "canonical_json", "json",
    }
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module.split(".")[0])
    assert imports <= allowed, imports - allowed


def test_register_roundtrip_verify_and_views(g, mod):
    rec = g.register("csp-acme", 1, baseline="moderate",
                     offering_digest=good_digest("offering"))
    assert rec.package_id == "csp-acme"
    assert rec.baseline == "moderate"
    assert rec.offering_pin == good_digest("offering")
    assert rec.verify()
    # tamper breaks verify (as data, never raised)
    object.__setattr__(rec, "baseline", "high")
    assert not rec.verify()
    # duplicate refused fail-closed, seq burned
    with pytest.raises(mod.DuplicatePackageError):
        g.register("csp-acme", 2, baseline="low")
    assert g.stats(3)["rejected"] == 1
    assert g.package_record("csp-acme", 4).package_id == "csp-acme"
    assert g.package_ids(5) == ("csp-acme",)
    # frozen records
    import dataclasses

    with pytest.raises(dataclasses.FrozenInstanceError):
        g.package_record("csp-acme", 6).baseline = "low"


def test_register_bad_inputs_and_vocabulary(g, mod):
    seq = 100
    for bad in (None, 1, True, b"x", "", "has space", "x" * 257):
        with pytest.raises(mod.BadIdError):
            g.register(bad, seq)
        seq += 1
    for bad_baseline in ("ultra", "MEDIUM", None, "", True):
        with pytest.raises(mod.BadBaselineError):
            g.register("pkg-b", seq, baseline=bad_baseline)
        seq += 1
    for bad_digest in ("not-a-digest", "sha256:xyz", "md5:abc", True):
        with pytest.raises(mod.BadDigestError):
            g.register("pkg-c", seq, offering_digest=bad_digest)
        seq += 1
    # 7 bad ids + 5 bad baselines + 4 bad digests = 16 rejected rows
    assert g.stats(seq)["rejected"] == 16
    # all three baselines accepted
    for i, baseline in enumerate(("low", "moderate", "high")):
        rec = g.register(f"pkg-{baseline}", seq, baseline=baseline)
        assert rec.verify()
        seq += 1
    assert g.stats(seq)["rejected"] == 16


def test_assess_roundtrip_and_minted_ids(g, mod):
    g.register("csp-a", 1)
    a1 = g.assess("csp-a", 2, assessment_type="readiness",
                 finding="compliant", assessor_digest=good_digest("3pao"))
    assert a1.assessment_id == "asm-1"
    assert a1.assessment_type == "readiness"
    assert a1.finding == "compliant"
    assert a1.verify()
    a2 = g.assess("csp-a", 3, assessment_type="sar", finding="partial")
    assert a2.assessment_id == "asm-2"
    assert a2.verify()
    assert g.assessment_record("asm-1", 4) is a1
    assert g.assessments_for("csp-a", 5) == ("asm-1", "asm-2")
    # unknown assessment lookup refused, no seq consumed, no audit row
    with pytest.raises(mod.UnknownAssessmentError):
        g.assessment_record("asm-99", 6)
    assert g.stats(7)["rejected"] == 0


def test_assess_bad_inputs_and_seq_burn(g, mod):
    g.register("csp-b", 1)
    seq = 2
    with pytest.raises(mod.UnknownPackageError):
        g.assess("pkg-nope", seq)
    seq += 1
    for bad_type in ("audit", "scan", "", None, True):
        with pytest.raises(mod.BadAssessmentTypeError):
            g.assess("csp-b", seq, assessment_type=bad_type)
        seq += 1
    for bad_finding in ("pass", "failed", "", None, True):
        with pytest.raises(mod.BadFindingError):
            g.assess("csp-b", seq, finding=bad_finding)
        seq += 1
    for bad_digest in ("nope", "sha256:zzzz", 123):
        with pytest.raises(mod.BadDigestError):
            g.assess("csp-b", seq, assessor_digest=bad_digest)
        seq += 1
    # 1 unknown + 5 bad types + 5 bad findings + 3 bad digests = 14
    assert g.stats(seq)["rejected"] == 14
    # seq discipline intact: next good seq still claims fine
    rec = g.assess("csp-b", seq, assessment_type="sar")
    assert rec.assessment_id == "asm-1"
    assert g.stats(seq + 1)["rejected"] == 14


def test_assessment_vocabulary_all_accepted(g, mod):
    g.register("csp-v", 1)
    seq = 2
    for atype in ("readiness", "sap", "sar", "penetration-test"):
        rec = g.assess("csp-v", seq, assessment_type=atype,
                       finding="compliant")
        assert rec.verify()
        seq += 1
    g.register("csp-v2", seq)
    seq += 1
    for finding in ("compliant", "non-compliant", "partial"):
        rec = g.assess("csp-v2", seq, finding=finding)
        assert rec.verify()
        seq += 1
    assert g.stats(seq)["assessments"] == 7
    assert g.stats(seq)["rejected"] == 0


def test_authorize_roundtrip(g, mod):
    g.register("csp-c", 1, baseline="high")
    g.assess("csp-c", 2, assessment_type="readiness")
    sar = g.assess("csp-c", 3, assessment_type="sar")
    ath = g.authorize("csp-c", 4, authorization_type="jab-p-ato",
                      authorizer_digest=good_digest("ao"))
    assert ath.authorization_id == "ath-1"
    assert ath.authorization_type == "jab-p-ato"
    assert ath.verify()
    # authorization grounds itself on the latest booked sar assessment
    assert ath.assessment_id == sar.assessment_id
    assert ath.assessment_id == sar.assessment_id
    assert g.is_authorized("csp-c", 5)
    assert g.authorized_ids(6) == ("csp-c",)
    assert g.authorization_record("csp-c", 7) is ath
    assert g.stats(8)["rejected"] == 0


def test_authorize_requires_sar_assessment(g, mod):
    g.register("csp-d", 1)
    g.assess("csp-d", 2, assessment_type="readiness")
    g.assess("csp-d", 3, assessment_type="penetration-test")
    with pytest.raises(mod.AuthorizationDeniedError):
        g.authorize("csp-d", 4)
    assert g.stats(5)["rejected"] == 1
    assert not g.is_authorized("csp-d", 6)
    # now book the sar and authorization succeeds
    sar = g.assess("csp-d", 7, assessment_type="sar")
    ath = g.authorize("csp-d", 8)
    assert ath.assessment_id == sar.assessment_id
    assert g.is_authorized("csp-d", 9)
    # latest sar grounds the authorization when several exist
    g.assess("csp-d", 10, assessment_type="sap")
    assert g.stats(11)["rejected"] == 1


def test_authorize_bad_inputs_and_double_authorize(g, mod):
    g.register("csp-e", 1)
    g.assess("csp-e", 2, assessment_type="sar")
    seq = 3
    with pytest.raises(mod.UnknownPackageError):
        g.authorize("pkg-nope", seq)
    seq += 1
    for bad_type in ("ato", "cert", "", None, True):
        with pytest.raises(mod.BadAuthorizationTypeError):
            g.authorize("csp-e", seq, authorization_type=bad_type)
        seq += 1
    for bad_digest in ("nope", "sha256:zz", 7):
        with pytest.raises(mod.BadDigestError):
            g.authorize("csp-e", seq, authorizer_digest=bad_digest)
        seq += 1
    # 1 unknown + 5 bad types + 3 bad digests = 9 rejected rows
    assert g.stats(seq)["rejected"] == 9
    g.authorize("csp-e", seq, authorization_type="fedramp-ready")
    seq += 1
    # one ATO per package: second authorization refused fail-closed
    with pytest.raises(mod.AlreadyAuthorizedError):
        g.authorize("csp-e", seq, authorization_type="agency-ato")
    assert g.stats(seq + 1)["rejected"] == 10
    assert g.is_authorized("csp-e", seq + 2)


def test_monitor_chain_and_outcomes_as_data(g, mod):
    g.register("csp-f", 1)
    g.assess("csp-f", 2, assessment_type="sar")
    g.authorize("csp-f", 3)
    seq = 4
    for outcome in ("on-track", "poam-open", "poam-closed", "at-risk"):
        rec = g.monitor("csp-f", seq, outcome=outcome,
                        conmon_digest=good_digest(f"conmon-{seq}"))
        assert rec.verify()
        seq += 1
    assert g.monitors_for("csp-f", seq) == ("mon-1", "mon-2", "mon-3",
                                            "mon-4")
    assert g.stats(seq)["monitors"] == 4
    assert g.stats(seq)["rejected"] == 0
    # outcomes booked as data; no verdict raised
    log = g.audit_log(seq + 1)
    outcomes = [row["detail"]["outcome"] for row in log
                if row["kind"] == "fedramp.monitored"]
    assert outcomes == ["on-track", "poam-open", "poam-closed", "at-risk"]


def test_monitor_refusals_and_seq_burn(g, mod):
    g.register("csp-g", 1)
    g.register("csp-h", 2)
    g.assess("csp-h", 3, assessment_type="sar")
    g.authorize("csp-h", 4)
    seq = 5
    # no authorization on csp-g: ConMon refused fail-closed
    with pytest.raises(mod.AuthorizationDeniedError):
        g.monitor("csp-g", seq)
    seq += 1
    with pytest.raises(mod.UnknownPackageError):
        g.monitor("pkg-nope", seq)
    seq += 1
    for bad_outcome in ("good", "blocked", "", None, True):
        with pytest.raises(mod.BadOutcomeError):
            g.monitor("csp-h", seq, outcome=bad_outcome)
        seq += 1
    for bad_digest in ("nope", "sha256:xx", 9):
        with pytest.raises(mod.BadDigestError):
            g.monitor("csp-h", seq, conmon_digest=bad_digest)
        seq += 1
    # 1 no-auth + 1 unknown + 5 bad outcomes + 3 bad digests = 10
    assert g.stats(seq)["rejected"] == 10
    rec = g.monitor("csp-h", seq, outcome="on-track")
    assert rec.monitor_id == "mon-1"
    assert g.stats(seq + 1)["rejected"] == 10


def test_revoke_terminality_and_no_recycling(g, mod):
    g.register("csp-i", 1)
    g.register("csp-j", 2)
    g.assess("csp-i", 3, assessment_type="sar")
    g.authorize("csp-i", 4)
    rev = g.revoke("csp-i", 5, reason="assessment-failed")
    assert rev.reason == "assessment-failed"
    assert rev.verify()
    assert not g.is_authorized("csp-i", 6)
    assert g.revoked_ids(7) == ("csp-i",)
    seq = 8
    # bad reason on a live package
    with pytest.raises(mod.BadReasonError):
        g.revoke("csp-j", seq, reason="nope")
    seq += 1
    # post-revoke mutations all refused fail-closed
    with pytest.raises(mod.RevokedPackageError):
        g.assess("csp-i", seq)
    seq += 1
    with pytest.raises(mod.RevokedPackageError):
        g.monitor("csp-i", seq)
    seq += 1
    with pytest.raises(mod.RevokedPackageError):
        g.authorize("csp-i", seq)
    seq += 1
    # retired id never recycled
    with pytest.raises(mod.RetiredPackageError):
        g.register("csp-i", seq)
    seq += 1
    # double revoke refused
    with pytest.raises(mod.DoubleRevokeError):
        g.revoke("csp-i", seq)
    seq += 1
    # unknown package revoke refused
    with pytest.raises(mod.UnknownPackageError):
        g.revoke("pkg-nope", seq)
    seq += 1
    assert g.stats(seq)["rejected"] == 7
    # reads still work post-revoke
    assert g.package_record("csp-i", seq).package_id == "csp-i"
    assert g.authorization_record("csp-i", seq + 1).package_id == "csp-i"


def test_seq_discipline_views_are_pure_reads(g, mod):
    g.register("csp-k", 1)
    # rewind raises bare: no rejected row, seq not consumed
    with pytest.raises(mod.SeqOrderError):
        g.assess("csp-k", 1)
    assert g.stats(2)["rejected"] == 0
    # malformed seqs on views raise bare, no audit rows
    for bad_seq in ("x", True, -1, None, 2.5):
        with pytest.raises(mod.SeqOrderError):
            g.audit_log(bad_seq)
    assert g.stats(2)["rejected"] == 0
    # failed mutation consumes its seq and books a rejected row
    with pytest.raises(mod.BadAssessmentTypeError):
        g.assess("csp-k", 3, assessment_type="bogus")
    assert g.stats(4)["rejected"] == 1
    a1 = g.assess("csp-k", 4, assessment_type="sar")
    assert a1.assessment_id == "asm-1"
    # views validate seq shape, consume nothing, write no audit rows
    assert g.package_ids(5) == ("csp-k",)
    assert g.package_record("csp-k", 5).package_id == "csp-k"
    rows = g.audit_log(5)
    assert len(rows) == 3  # register, rejected, assess
    assert [r["kind"] for r in rows] == [
        "fedramp.package-registered", "fedramp.rejected", "fedramp.assessed"]
    assert g.stats(6)["rejected"] == 1


def test_audit_shapes_leak_ban_bad_kind_and_main(mod, g):
    g.register("csp-l", 1, offering_digest=good_digest("offering"))
    g.assess("csp-l", 2, assessment_type="sar")
    g.authorize("csp-l", 3)
    g.monitor("csp-l", 4, outcome="on-track")
    rows = g.audit_log(5)
    assert len(rows) == 4
    for row in rows:
        assert row["audit_version"] == "audit.ndjson/1"
        assert row["schema"] == "northstar.fedramp.v1"
        assert row["version"] == "fedramp.v1"
        assert row["kind"].startswith("fedramp.")
        # raw content never crosses the audit boundary
        banned = {"content", "text", "payload", "raw", "evidence",
                  "offering", "description", "notes", "note", "message",
                  "plan", "rationale", "title", "summary", "finding_text",
                  "assessor", "authorizer", "custodian"}
        assert not banned.intersection(row["detail"].keys()), row
    # builder-level leak ban and bad-kind
    with pytest.raises(mod.AuditKindError):
        mod.fedramp_audit_event("assessed", {"evidence": "raw"}, 6)
    with pytest.raises(mod.AuditKindError):
        mod.fedramp_audit_event("bogus", {}, 6)
    # cross-instance digest determinism
    mod2 = load_module()
    g2 = mod2.FedRAMP()
    r1 = g2.register("csp-l", 1, offering_digest=good_digest("offering"))
    g3 = mod.FedRAMP()
    r2 = g3.register("csp-l", 1, offering_digest=good_digest("offering"))
    assert r1.digest == r2.digest
    # 8-thread read smoke
    errors = []

    def reader():
        try:
            for _ in range(50):
                g.package_ids(7)
                g.audit_log(7)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    # main() self-check via subprocess
    proc = subprocess.run([sys.executable, str(MODULE_PATH)],
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert "fedramp OK:" in proc.stdout
