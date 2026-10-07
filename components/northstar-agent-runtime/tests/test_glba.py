"""Tests for glba.py: assess / safeguard / notify."""

import ast
import hashlib
import subprocess
import sys
from pathlib import Path

import pytest

import glba as gl

HERE = Path(__file__).resolve().parent
MODULE = Path(__file__).resolve().parent.parent / "glba.py"


def digest(seed: str) -> str:
    return "sha256:" + hashlib.sha256(seed.encode()).hexdigest()


def fresh(seq_start=1, institution_id="BANK-001", kind="safeguards-rule"):
    ledger = gl.GLBA()
    ledger.assess(institution_id, kind, seq_start)
    return ledger


def test_version_and_schema_pins():
    assert gl.GLBA_VERSION == "glba.v1"
    assert gl.GLBA_SCHEMA == "northstar.glba.v1"


def test_stdlib_only():
    tree = ast.parse(MODULE.read_text())
    allowed = {
        "hashlib",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
        "canonical_json",
        "json",
        "sys",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


def test_assess_roundtrip_verify_and_frozen():
    ledger = fresh()
    record = ledger.assessments_for("BANK-001", 2)[0]
    assert record.assessment_id == "asm-1"
    assert record.assessment_kind == "safeguards-rule"
    assert record.verdict == "not-assessed"
    assert record.verify()
    assert ledger.institution_ids(3) == ("BANK-001",)
    with pytest.raises(Exception):
        record.verdict = "compliant"  # frozen dataclass


def test_assess_bad_inputs_consume_seq():
    ledger = fresh()
    with pytest.raises(gl.BadAssessmentKindError):
        ledger.assess("BANK-002", "tax-rule", 2)
    with pytest.raises(gl.BadVerdictError):
        ledger.assess("BANK-002", "privacy-rule", 3, verdict="maybe")
    with pytest.raises(gl.BadInstitutionError):
        ledger.assess("  ", "privacy-rule", 4)
    with pytest.raises(gl.BadInstitutionError):
        ledger.assess(123, "privacy-rule", 5)  # type: ignore[arg-type]
    with pytest.raises(gl.BadDigestError):
        ledger.assess(
            "BANK-003", "privacy-rule", 6, findings_digest="raw text"
        )
    rejected = [e for e in ledger.audit_log(7) if e["kind"] == gl.KIND_REJECTED]
    assert len(rejected) == 5
    assert ledger.stats(8)["assessments"] == 1


def test_assess_malformed_seq_and_rewind_raise_bare():
    ledger = fresh()
    for bad_seq in (True, "x", -1):
        with pytest.raises(gl.SeqOrderError):
            ledger.assess("BANK-BAD", "privacy-rule", bad_seq)
    # rewind: seq not strictly greater -> bare raise, nothing consumed
    with pytest.raises(gl.SeqOrderError):
        ledger.assess("BANK-002", "privacy-rule", 1)
    assert len(ledger.audit_log(2)) == 1  # only the successful assess


def test_assess_full_kind_and_verdict_vocabularies():
    ledger = gl.GLBA()
    seq = 0
    for kind in sorted(gl._ASSESSMENT_KINDS):
        seq += 1
        rec = ledger.assess(
            f"BK-{kind[:4]}", kind, seq, findings_digest=digest("f")
        )
        assert rec.verify()
    seq += 1
    ledger.assess("BK-V", "privacy-rule", seq, verdict="compliant")
    for i, verdict in enumerate(sorted(gl._VERDICTS)):
        seq += 1
        rec = ledger.assess(
            "BK-V", "safeguards-rule", seq, verdict=verdict
        )
        assert rec.verdict == verdict
    with pytest.raises(gl.BadVerdictError):
        ledger.assess("BK-V", "safeguards-rule", seq + 1, verdict="ish")


def test_safeguard_roundtrip_and_full_vocabulary():
    ledger = fresh()
    s1 = ledger.safeguard("BANK-001", "encryption", 2)
    s2 = ledger.safeguard(
        "BANK-001", "multi-factor-auth", 3, implementation_digest=digest("i")
    )
    assert s1.safeguard_id != s2.safeguard_id
    assert s1.verify() and s2.verify()
    declared = [r.safeguard for r in ledger.safeguards_for("BANK-001", 4)]
    assert declared == ["encryption", "multi-factor-auth"]
    # full safeguard vocabulary accepted
    seq = 4
    for safeguard in sorted(gl._SAFEGUARDS):
        if safeguard in ("encryption", "multi-factor-auth"):
            continue
        seq += 1
        rec = ledger.safeguard("BANK-001", safeguard, seq)
        assert rec.verify()
    assert ledger.status("BANK-001", seq + 1).distinct_safeguards == len(
        gl._SAFEGUARDS
    )


def test_safeguard_unknown_institution_and_bad_inputs_consume_seq():
    ledger = fresh()
    with pytest.raises(gl.UnknownInstitutionError):
        ledger.safeguard("BANK-NOPE", "encryption", 2)
    with pytest.raises(gl.BadSafeguardError):
        ledger.safeguard("BANK-001", "trust-me-bro", 3)
    with pytest.raises(gl.BadDigestError):
        ledger.safeguard(
            "BANK-001", "encryption", 4, implementation_digest="nope"
        )
    rejected = [e for e in ledger.audit_log(5) if e["kind"] == gl.KIND_REJECTED]
    assert len(rejected) == 3
    assert ledger.safeguards_for("BANK-001", 6) == ()


def test_notify_roundtrip_and_full_vocabulary():
    ledger = fresh()
    n1 = ledger.notify("BANK-001", "initial-privacy-notice", 2)
    n2 = ledger.notify(
        "BANK-001",
        "opt-out-election",
        3,
        subject_digest=digest("cust"),
        notice_digest=digest("notice"),
    )
    assert n1.notification_id != n2.notification_id
    assert n1.verify() and n2.verify()
    events = [r.event for r in ledger.notifications_for("BANK-001", 4)]
    assert events == ["initial-privacy-notice", "opt-out-election"]
    # full event vocabulary accepted
    seq = 4
    for event in sorted(gl._EVENTS):
        if event in ("initial-privacy-notice", "opt-out-election"):
            continue
        seq += 1
        rec = ledger.notify("BANK-001", event, seq)
        assert rec.verify()
    with pytest.raises(gl.BadEventError):
        ledger.notify("BANK-001", "tweet-it", seq + 1)


def test_notify_unknown_institution_and_bad_inputs_consume_seq():
    ledger = fresh()
    with pytest.raises(gl.UnknownInstitutionError):
        ledger.notify("BANK-NOPE", "annual-privacy-notice", 2)
    with pytest.raises(gl.BadEventError):
        ledger.notify("BANK-001", "carrier-pigeon", 3)
    with pytest.raises(gl.BadDigestError):
        ledger.notify(
            "BANK-001", "annual-privacy-notice", 4, notice_digest="raw"
        )
    rejected = [e for e in ledger.audit_log(5) if e["kind"] == gl.KIND_REJECTED]
    assert len(rejected) == 3
    assert ledger.notifications_for("BANK-001", 6) == ()


def test_view_read_purity():
    ledger = fresh()
    ledger.safeguard("BANK-001", "risk-assessment", 2)
    ledger.notify("BANK-001", "annual-privacy-notice", 3)
    kinds_before = [e["kind"] for e in ledger.audit_log(4)]
    assert kinds_before == [
        gl.KIND_ASSESSED,
        gl.KIND_SAFEGUARDED,
        gl.KIND_NOTIFIED,
    ]
    # same seq twice, no audit rows, nothing consumed
    assert ledger.assessments_for("BANK-001", 4) == ledger.assessments_for(
        "BANK-001", 4
    )
    assert ledger.safeguards_for("BANK-001", 4) == ledger.safeguards_for(
        "BANK-001", 4
    )
    assert ledger.notifications_for("BANK-001", 4) == ledger.notifications_for(
        "BANK-001", 4
    )
    assert ledger.status("BANK-001", 4) == ledger.status("BANK-001", 4)
    assert ledger.stats(4) == ledger.stats(4)
    kinds_after = [e["kind"] for e in ledger.audit_log(4)]
    assert kinds_after == kinds_before
    with pytest.raises(gl.UnknownInstitutionError):
        ledger.status("BANK-NOPE", 4)


def test_status_posture_math():
    ledger = gl.GLBA()
    ledger.assess("BK-A", "privacy-rule", 1)  # not-assessed default
    status = ledger.status("BK-A", 2)
    assert status.assessments == 1
    assert status.open_gaps == 0
    assert status.posture == "assessed"
    ledger.assess(
        "BK-A", "safeguards-rule", 3, verdict="gap-identified"
    )
    status = ledger.status("BK-A", 4)
    assert status.open_gaps == 1
    assert status.posture == "gaps-open"
    ledger.assess("BK-B", "pretexting-protection", 5, verdict="non-compliant")
    status = ledger.status("BK-B", 6)
    assert status.posture == "gaps-open"
    tallies = dict(status.verdict_tallies)
    assert tallies["non-compliant"] == 1


def test_audit_shapes_leak_ban_and_bad_kind():
    ledger = fresh()
    ledger.safeguard("BANK-001", "encryption", 2)
    events = ledger.audit_log(3)
    assessed = events[0]
    assert assessed["schema"] == "audit.ndjson/1"
    assert assessed["kind"] == gl.KIND_ASSESSED
    assert assessed["seq"] == 1
    assert "record_digest" in assessed["detail"]
    # every banned raw-text key is refused by the builder
    for banned in sorted(gl._BANNED_AUDIT_KEYS):
        with pytest.raises(gl.AuditKindError):
            gl.glba_audit_event(gl.KIND_ASSESSED, 3, **{banned: "raw"})
    with pytest.raises(gl.AuditKindError):
        gl.glba_audit_event("glba.bogus", 3)
    # no banned raw-text key in any booked audit detail (exact-key check)
    for event in ledger.audit_log(4):
        for banned in gl._BANNED_AUDIT_KEYS:
            assert banned not in event["detail"]


def test_cross_instance_digest_determinism_and_tamper():
    a = gl.GLBA()
    b = gl.GLBA()
    ra = a.assess(
        "BK-X", "safeguards-rule", 1, verdict="compliant",
        findings_digest=digest("f"),
    )
    rb = b.assess(
        "BK-X", "safeguards-rule", 1, verdict="compliant",
        findings_digest=digest("f"),
    )
    assert ra.digest == rb.digest and ra.verify()
    sa = a.safeguard("BK-X", "encryption", 2)
    sb = b.safeguard("BK-X", "encryption", 2)
    assert sa.digest == sb.digest
    na = a.notify("BK-X", "opt-out-election", 3)
    nb = b.notify("BK-X", "opt-out-election", 3)
    assert na.digest == nb.digest
    # tamper breaks verify
    object.__setattr__(ra, "verdict", "non-compliant")
    assert not ra.verify()


def test_main_subprocess_and_thread_safety_smoke():
    proc = subprocess.run(
        [sys.executable, str(MODULE)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert "glba OK: assess, safeguard, notify, pins, audit" in proc.stdout
    import threading

    ledger = fresh()
    errors = []

    def reader(n):
        try:
            ledger.status("BANK-001", 4 + (n % 3))
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=reader, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
