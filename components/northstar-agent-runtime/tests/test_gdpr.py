"""Tests for the GDPR governance decision ledger, Simulated."""

import ast
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "gdpr.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("gdpr", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["gdpr"] = module
    spec.loader.exec_module(module)
    return module


gdpr = _load()


# 1. version/schema pins
def test_version_and_schema_pins():
    assert gdpr.GDPR_VERSION == "gdpr.v1"
    assert gdpr.SCHEMA_PIN == "northstar.gdpr.v1"
    assert gdpr.LAWFUL_BASES == (
        "consent",
        "contract",
        "legal-obligation",
        "vital-interests",
        "public-task",
        "legitimate-interests",
    )
    assert gdpr.OUTCOMES == ("compliant", "non-compliant", "partial", "not-applicable")
    assert gdpr.RISK_LEVELS == ("low", "medium", "high", "critical")
    assert gdpr.REMEDIATION_ACTIONS == (
        "minimize-data",
        "add-safeguard",
        "restrict-purpose",
        "update-consent",
        "anonymize",
        "delete-data",
        "accept-risk",
    )
    assert gdpr.NOTIFY_CHANNELS == (
        "supervisory-authority",
        "data-subjects",
        "dpo",
        "internal",
    )
    assert gdpr.NOTIFY_REASONS == (
        "breach-72h",
        "high-risk-breach",
        "dpia-consultation",
        "manual",
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


# 3. register_processing roundtrip + verify
def test_register_roundtrip():
    g = gdpr.GDPR()
    rec = g.register_processing(
        "act-1", 1, lawful_basis="legitimate-interests",
        special_category=True, activity_digest=PIN,
    )
    assert rec.activity_id == "act-1"
    assert rec.lawful_basis == "legitimate-interests"
    assert rec.special_category is True
    assert rec.activity_digest == PIN
    assert rec.verify()
    got = g.processing_record("act-1", 0)
    assert got.verify()
    assert g.activity_ids(0) == ("act-1",)


# 4. register bad-input table + seq-burn + rejected rows
def test_register_bad_inputs():
    g = gdpr.GDPR()
    seq = 0
    n_rejected = 0
    g.register_processing("ok-1", 1, lawful_basis="consent")
    seq = 1
    bad = [
        ("", "consent"),  # empty id
        ("x" * 129, "consent"),  # too long
        (123, "consent"),  # non-str id
        ("bad-basis", "whatever"),  # unknown basis
        ("sc-str", "consent", "yes"),  # non-bool special_category
        ("bd-1", "consent", False, "not-a-pin"),  # bad digest
        ("ok-1", "consent"),  # duplicate
    ]
    for idx, case in enumerate(bad):
        s = 2 + idx  # fresh seq per case (claim-then-burn consumes each)
        aid = case[0]
        if len(case) == 2:
            _, basis = case
            with pytest.raises(gdpr.GDPRError):
                g.register_processing(aid, s, lawful_basis=basis)
        elif len(case) == 3:
            _, basis, sc = case
            with pytest.raises(gdpr.GDPRError):
                g.register_processing(aid, s, lawful_basis=basis,
                                      special_category=sc)
        else:
            _, basis, sc, dig = case
            with pytest.raises(gdpr.GDPRError):
                g.register_processing(aid, s, lawful_basis=basis,
                                      special_category=sc,
                                      activity_digest=dig)
        n_rejected += 1
        seq += 1
    assert seq == 1 + len(bad)
    assert g.stats(0)["audit_rows"] == 1 + n_rejected  # 1 registered + rejects
    kinds = [r["kind"] for r in g.audit_log(0)]
    assert kinds[0] == "registered"
    assert kinds[1:] == ["rejected"] * n_rejected


# 5. assess roundtrip + minted ids
def test_assess_roundtrip():
    g = gdpr.GDPR()
    g.register_processing("act-1", 1, lawful_basis="contract")
    a1 = g.assess("act-1", 2, outcome="non-compliant", risk_level="high",
                  evidence_digest=PIN)
    assert a1.assessment_id == "asm-1"
    assert a1.outcome == "non-compliant"
    assert a1.risk_level == "high"
    assert a1.verify()
    a2 = g.assess("act-1", 3, outcome="compliant")
    assert a2.assessment_id == "asm-2"
    assert a2.verify()
    assert g.assessment_ids(0) == ("asm-1", "asm-2")
    assert g.assessments_for("act-1", 0) == ("asm-1", "asm-2")


# 6. assess bad-input table + unknown activity
def test_assess_bad_inputs():
    g = gdpr.GDPR()
    g.register_processing("act-1", 1)
    n = 0
    for i, kwargs in enumerate([
        {"outcome": "bogus"},
        {"risk_level": "extreme"},
        {"evidence_digest": "nope"},
    ]):
        with pytest.raises(gdpr.GDPRError):
            g.assess("act-1", 2 + i, **kwargs)
        n += 1
    with pytest.raises(gdpr.UnknownActivityError):
        g.assess("ghost", 5)
    n += 1
    assert g.stats(0)["assessments"] == 0
    assert sum(1 for r in g.audit_log(0) if r["kind"] == "rejected") == n


# 7. remediate roundtrip + gating
def test_remediate_roundtrip():
    g = gdpr.GDPR()
    g.register_processing("act-1", 1)
    g.assess("act-1", 2, outcome="non-compliant")
    g.assess("act-1", 3, outcome="compliant")
    rem = g.remediate("asm-1", 4, action="add-safeguard", plan_digest=PIN2)
    assert rem.remediation_id == "rem-1"
    assert rem.assessment_id == "asm-1"
    assert rem.action == "add-safeguard"
    assert rem.verify()
    # compliant assessment needs no remediation
    with pytest.raises(gdpr.RemediationNotNeededError):
        g.remediate("asm-2", 5)
    # second remediation refused
    with pytest.raises(gdpr.AlreadyRemediatedError):
        g.remediate("asm-1", 6)
    # unknown assessment
    with pytest.raises(gdpr.UnknownAssessmentError):
        g.remediate("asm-99", 7)
    assert g.stats(0)["remediations"] == 1


# 8. remediate bad action + all-action vocabulary acceptance
def test_remediate_vocabularies():
    g = gdpr.GDPR()
    g.register_processing("act-1", 1)
    # assesses first (seqs 2..8), then remediations (seqs 9..15): seqs must
    # strictly increase, so the two phases cannot interleave.
    for i in range(len(gdpr.REMEDIATION_ACTIONS)):
        g.assess("act-1", 2 + i, outcome="partial")
    for i, action in enumerate(gdpr.REMEDIATION_ACTIONS):
        asm_id = f"asm-{i + 1}"
        rem = g.remediate(asm_id, 9 + i, action=action)
        assert rem.action == action
        assert rem.verify()
    assert g.stats(0)["remediations"] == len(gdpr.REMEDIATION_ACTIONS)
    # bad action
    g2 = gdpr.GDPR()
    g2.register_processing("b", 1)
    g2.assess("b", 2, outcome="non-compliant")
    with pytest.raises(gdpr.BadActionError):
        g2.remediate("asm-1", 3, action="magic")


# 9. notify roundtrip + minted ids + channel vocabulary
def test_notify_roundtrip():
    g = gdpr.GDPR()
    g.register_processing("act-1", 1)
    g.assess("act-1", 2, outcome="non-compliant", risk_level="critical")
    n1 = g.notify("asm-1", 3, channel="supervisory-authority",
                  reason="breach-72h")
    assert n1.notification_id == "ntf-1"
    assert n1.channel == "supervisory-authority"
    assert n1.reason == "breach-72h"
    assert n1.verify()
    for i, channel in enumerate(gdpr.NOTIFY_CHANNELS[1:], start=4):
        n = g.notify("asm-1", i, channel=channel, reason="manual")
        assert n.verify()
    assert g.stats(0)["notifications"] == len(gdpr.NOTIFY_CHANNELS)
    assert g.notifications_for("asm-1", 0) == tuple(
        f"ntf-{i + 1}" for i in range(len(gdpr.NOTIFY_CHANNELS)))
    # bad inputs
    with pytest.raises(gdpr.BadChannelError):
        g.notify("asm-1", 10, channel="carrier-pigeon")
    with pytest.raises(gdpr.BadNotifyReasonError):
        g.notify("asm-1", 11, reason="vibes")
    with pytest.raises(gdpr.UnknownAssessmentError):
        g.notify("asm-99", 12)


# 10. status read purity + posture math
def test_status_read_purity():
    g = gdpr.GDPR()
    g.register_processing("act-1", 1, lawful_basis="public-task")
    g.assess("act-1", 2, outcome="partial", risk_level="medium")
    g.remediate("asm-1", 3, action="restrict-purpose")
    g.notify("asm-1", 4, channel="dpo", reason="dpia-consultation")
    rows_before = g.stats(0)["audit_rows"]
    st1 = g.status("act-1", 0)
    st2 = g.status("act-1", 0)  # same seq twice - no consumption
    assert st1.verify() and st2.verify()
    assert st1.n_assessments == 1
    assert st1.latest_outcome == "partial"
    assert st1.n_remediations == 1
    assert st1.n_notifications == 1
    assert st1.integrity_ok
    assert g.stats(0)["audit_rows"] == rows_before  # no audit rows written
    with pytest.raises(gdpr.UnknownActivityError):
        g.status("ghost", 0)


# 11. seq discipline (rewind bare, malformed seqs, failed-mutation-consumes-seq)
def test_seq_discipline():
    g = gdpr.GDPR()
    g.register_processing("a", 1)
    with pytest.raises(gdpr.SeqOrderError):
        g.register_processing("b", 1)  # rewind: raises bare
    assert g.stats(0)["audit_rows"] == 1  # no rejected row for rewind
    for bad in (True, "2", 2.5, -3, 0):
        with pytest.raises(gdpr.SeqOrderError):
            g.register_processing("c", bad)
    assert g.stats(0)["audit_rows"] == 1  # still no rows
    # failed mutation consumes seq
    with pytest.raises(gdpr.BadBasisError):
        g.register_processing("d", 2, lawful_basis="nope")
    g.register_processing("e", 3)  # must continue at 3
    assert g.stats(0)["activities"] == 2
    assert g.stats(0)["audit_rows"] == 3  # registered, rejected, registered


# 12. audit shapes + leak ban + bad kind
def test_audit_shapes_and_leak_ban():
    g = gdpr.GDPR()
    g.register_processing("a", 1)
    g.assess("a", 2)
    rows = g.audit_log(0)
    assert all(r["schema"] == "audit.ndjson/1" for r in rows)
    assert rows[0]["kind"] == "registered"
    assert rows[1]["kind"] == "assessed"
    assert all("seq" in r and "details" in r for r in rows)
    # raw material never crosses the audit boundary
    for r in rows:
        for key in r["details"]:
            assert key not in gdpr._BANNED_AUDIT_KEYS
    # banned key refused at builder level
    with pytest.raises(gdpr.AuditKindError):
        gdpr.gdpr_audit_event("registered", 9, breach_detail="x")
    with pytest.raises(gdpr.AuditKindError):
        gdpr.gdpr_audit_event("bogus-kind", 9)
    with pytest.raises(gdpr.SeqOrderError):
        gdpr.gdpr_audit_event("registered", -1)


# 13. tamper breaks verify + frozen-ness + cross-instance determinism
def test_tamper_and_determinism():
    g = gdpr.GDPR()
    rec = g.register_processing("a", 1, activity_digest=PIN)
    assert rec.verify()
    g2 = gdpr.GDPR()
    rec2 = g2.register_processing("a", 1, activity_digest=PIN)
    assert rec.digest == rec2.digest  # deterministic across instances
    object.__setattr__(rec, "lawful_basis", "contract")
    assert not rec.verify()  # tamper reported as data
    st = g.status("a", 0)
    assert st.verify()  # ledger self-check still passes on stored record
    import dataclasses

    with pytest.raises(dataclasses.FrozenInstanceError):
        rec2.digest = "x"  # frozen


# 14. concurrency smoke (reads) + views
def test_concurrency_and_views():
    g = gdpr.GDPR()
    g.register_processing("a", 1)
    g.assess("a", 2, outcome="compliant")

    def read():
        assert g.processing_record("a", 0).verify()
        assert g.assessment_record("asm-1", 0).verify()
        assert g.activity_ids(0) == ("a",)
        assert g.stats(0)["activities"] == 1

    threads = [threading.Thread(target=read) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    with pytest.raises(gdpr.UnknownActivityError):
        g.assessments_for("ghost", 0)
    with pytest.raises(gdpr.UnknownAssessmentError):
        g.notifications_for("asm-99", 0)


# 15. main() subprocess check
def test_main_subprocess():
    out = subprocess.run(
        [sys.executable, str(MOD)], capture_output=True, text=True
    )
    assert out.returncode == 0, out.stderr
    assert "gdpr OK: register, assess, remediate, notify, status, pins" in out.stdout
