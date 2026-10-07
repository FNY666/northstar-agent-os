"""Targeted tests for compliance.py (15 tests)."""

from __future__ import annotations

import ast
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

import compliance as cp

DIGEST = "sha256:" + "ab" * 32
DIGEST2 = "sha256:" + "cd" * 32


def make() -> cp.Compliance:
    return cp.Compliance()


def test_version_and_schema_pins():
    assert cp.COMPLIANCE_VERSION == "compliance.v1"
    assert cp.SCHEMA_PIN == "northstar.compliance.v1"
    assert cp.AUDIT_SCHEMA == "audit.ndjson/1"
    assert cp.KIND_SOC2 == "soc2"
    assert cp.VERDICT_PASS == "pass"
    assert cp.ACTION_PATCH == "patch"


def test_stdlib_only():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..",
                        "compliance.py")
    tree = ast.parse(open(path, encoding="utf-8").read())
    allowed = {"hashlib", "threading", "dataclasses", "typing",
               "__future__", "canonical_json", "json"}
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                imported.add(a.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert imported <= allowed, imported


def test_register_roundtrip_and_verify():
    c = make()
    rec = c.register_framework("fw-1", cp.KIND_SOC2, 1, DIGEST)
    assert rec.framework_id == "fw-1"
    assert rec.framework_kind == cp.KIND_SOC2
    assert rec.verify("fw-1", cp.KIND_SOC2, DIGEST) is True
    assert rec.verify("fw-1", cp.KIND_GDPR, DIGEST) is False
    assert c.framework_record("fw-1", 2) is rec
    assert c.framework_ids(3) == ("fw-1",)


def test_register_bad_inputs_seq_burn_rejected_rows():
    c = make()
    n_rejected = 0
    bad = [
        lambda s: c.register_framework("fw-1", "not-a-kind", s),
        lambda s: c.register_framework("fw-1", cp.KIND_SOC2, s, "raw-text"),
        lambda s: c.register_framework("", cp.KIND_SOC2, s),
        lambda s: c.register_framework(123, cp.KIND_SOC2, s),
    ]
    seq = 1
    for fn in bad:
        with pytest.raises(cp.ComplianceError):
            fn(seq)
        n_rejected += 1
        seq += 1
    # duplicate consumes seq and books a rejected row
    c.register_framework("fw-2", cp.KIND_GDPR, seq)
    seq += 1
    with pytest.raises(cp.DuplicateFrameworkError):
        c.register_framework("fw-2", cp.KIND_GDPR, seq)
    n_rejected += 1
    seq += 1
    stats = c.stats(seq)
    assert stats["rejected"] == n_rejected
    # seq still advanced: next live mutation takes the next seq
    rec = c.register_framework("fw-3", cp.KIND_ISO27001, seq)
    assert rec.seq == seq


def test_check_roundtrip_minted_ids_and_verify():
    c = make()
    c.register_framework("fw-1", cp.KIND_SOC2, 1)
    r1 = c.check("fw-1", "CC6.1", cp.VERDICT_PASS, 2, DIGEST)
    r2 = c.check("fw-1", "CC6.2", cp.VERDICT_FAIL, 3)
    assert r1.check_id == "chk-1"
    assert r2.check_id == "chk-2"
    assert r1.verify("fw-1", "CC6.1", cp.VERDICT_PASS, DIGEST) is True
    assert r2.verify("fw-1", "CC6.2", cp.VERDICT_FAIL, "") is True
    assert r2.verify("fw-1", "CC6.2", cp.VERDICT_FAIL, DIGEST) is False
    assert c.check_record("chk-1", 4) is r1
    assert c.checks_for("fw-1", 5) == ("chk-1", "chk-2")
    with pytest.raises(cp.UnknownCheckError):
        c.check_record("chk-9", 6)


def test_check_bad_inputs_seq_burn():
    c = make()
    c.register_framework("fw-1", cp.KIND_SOC2, 1)
    n_rejected = 0
    seq = 2
    cases = [
        lambda s: c.check("nope", "CC6.1", cp.VERDICT_PASS, s),
        lambda s: c.check("fw-1", "CC6.1", "maybe", s),
        lambda s: c.check("fw-1", "", cp.VERDICT_PASS, s),
        lambda s: c.check("fw-1", "CC6.1", cp.VERDICT_PASS, s, "raw"),
    ]
    for fn in cases:
        with pytest.raises(cp.ComplianceError):
            fn(seq)
        n_rejected += 1
        seq += 1
    assert c.stats(seq)["rejected"] == n_rejected
    r = c.check("fw-1", "CC6.1", cp.VERDICT_PASS, seq)
    assert r.check_id == "chk-1"


def test_remediate_roundtrip_and_verify():
    c = make()
    c.register_framework("fw-1", cp.KIND_SOC2, 1)
    c.check("fw-1", "CC6.2", cp.VERDICT_FAIL, 2)
    rec = c.remediate("chk-1", cp.ACTION_PATCH, 3, DIGEST)
    assert rec.remediation_id == "rmd-1"
    assert rec.verify("chk-1", cp.ACTION_PATCH, DIGEST) is True
    assert rec.verify("chk-1", cp.ACTION_MITIGATE, DIGEST) is False


def test_remediate_refusals_seq_burn():
    c = make()
    c.register_framework("fw-1", cp.KIND_SOC2, 1)
    c.check("fw-1", "CC6.1", cp.VERDICT_PASS, 2)      # chk-1: passing
    c.check("fw-1", "CC6.2", cp.VERDICT_PARTIAL, 3)   # chk-2: failing
    n_rejected = 0
    seq = 4
    with pytest.raises(cp.UnknownCheckError):
        c.remediate("chk-9", cp.ACTION_PATCH, seq)
    n_rejected += 1
    seq += 1
    with pytest.raises(cp.CheckNotFailingError):
        c.remediate("chk-1", cp.ACTION_PATCH, seq)
    n_rejected += 1
    seq += 1
    with pytest.raises(cp.BadActionError):
        c.remediate("chk-2", "wing-it", seq)
    n_rejected += 1
    seq += 1
    c.remediate("chk-2", cp.ACTION_MITIGATE, seq)
    seq += 1
    with pytest.raises(cp.AlreadyRemediatedError):
        c.remediate("chk-2", cp.ACTION_PATCH, seq)
    n_rejected += 1
    seq += 1
    assert c.stats(seq)["rejected"] == n_rejected


def test_attest_postures_and_read_purity():
    c = make()
    c.register_framework("fw-1", cp.KIND_SOC2, 1)
    rep = c.attest("fw-1", 2)
    assert rep.posture == "not-assessed"
    assert rep.verify("fw-1", "not-assessed", 0, 0, 0, 0) is True
    c.check("fw-1", "CC6.1", cp.VERDICT_PASS, 3)
    rep = c.attest("fw-1", 4)
    assert rep.posture == "compliant"
    c.check("fw-1", "CC6.2", cp.VERDICT_FAIL, 5)
    rep = c.attest("fw-1", 6)
    assert rep.posture == "non-compliant"
    assert (rep.n_checks, rep.n_passed, rep.n_failed, rep.n_remediated) == (2, 1, 1, 0)
    c.remediate("chk-2", cp.ACTION_PATCH, 7)
    rep2 = c.attest("fw-1", 8)
    assert rep2.posture == "compliant"
    assert rep2.n_remediated == 1
    # pure read: same seq twice, no audit rows, no seq consumption
    before = len(c.audit_log(9))
    r1 = c.attest("fw-1", 10)
    r2 = c.attest("fw-1", 10)
    assert r1 == r2
    assert len(c.audit_log(11)) == before
    with pytest.raises(cp.UnknownFrameworkError):
        c.attest("fw-9", 12)


def test_attest_na_checks_do_not_break_compliance():
    c = make()
    c.register_framework("fw-1", cp.KIND_CUSTOM, 1)
    c.check("fw-1", "C-1", cp.VERDICT_NA, 2)
    c.check("fw-1", "C-2", cp.VERDICT_PASS, 3)
    rep = c.attest("fw-1", 4)
    assert rep.posture == "compliant"
    assert rep.n_checks == 2
    assert rep.n_failed == 0


def test_seq_discipline():
    c = make()
    c.register_framework("fw-1", cp.KIND_SOC2, 1)
    # rewind raises bare with no rejected row
    n_before = c.stats(2)["rejected"]
    with pytest.raises(cp.SeqOrderError):
        c.check("fw-1", "CC6.1", cp.VERDICT_PASS, 1)
    assert c.stats(3)["rejected"] == n_before
    # malformed seqs raise bare
    for bad in (True, "2", 2.0, None, -1):
        with pytest.raises(cp.SeqOrderError):
            c.check("fw-1", "CC6.1", cp.VERDICT_PASS, bad)
    # failed mutation consumes its seq
    with pytest.raises(cp.BadVerdictError):
        c.check("fw-1", "CC6.1", "maybe", 4)
    r = c.check("fw-1", "CC6.1", cp.VERDICT_PASS, 5)
    assert r.check_id == "chk-1"


def test_audit_shapes_and_leak_ban():
    c = make()
    c.register_framework("fw-1", cp.KIND_SOC2, 1, DIGEST)
    c.check("fw-1", "CC6.1", cp.VERDICT_FAIL, 2)
    c.remediate("chk-1", cp.ACTION_DOCUMENT, 3)
    rows = c.audit_log(4)
    assert [r["kind"] for r in rows] == [
        "compliance.registered", "compliance.checked", "compliance.remediated"]
    for r in rows:
        assert r["schema"] == "audit.ndjson/1"
        assert r["module"] == "compliance.v1"
    for banned in ("policy", "raw", "content", "evidence", "finding",
                   "details", "description"):
        with pytest.raises(cp.AuditKindError):
            cp.compliance_audit_event("compliance.checked", {banned: "x"}, 1)
    with pytest.raises(cp.AuditKindError):
        cp.compliance_audit_event("compliance.bogus", {}, 1)


def test_cross_instance_determinism_and_tamper():
    a, b = make(), make()
    ra = a.register_framework("fw-1", cp.KIND_SOC2, 1, DIGEST)
    rb = b.register_framework("fw-1", cp.KIND_SOC2, 1, DIGEST)
    assert ra.digest == rb.digest
    ca = a.check("fw-1", "CC6.1", cp.VERDICT_PASS, 2, DIGEST)
    cb = b.check("fw-1", "CC6.1", cp.VERDICT_PASS, 2, DIGEST)
    assert ca.digest == cb.digest
    # tamper breaks verify
    object.__setattr__(ca, "digest", "sha256:" + "00" * 32)
    assert ca.verify("fw-1", "CC6.1", cp.VERDICT_PASS, DIGEST) is False
    assert a.stats(3)["frameworks"] == 1
    assert a.stats(4)["checks"] == 1


def test_frozen_records_and_concurrency_smoke():
    import threading
    c = make()
    rec = c.register_framework("fw-1", cp.KIND_GDPR, 1)
    with pytest.raises(Exception):
        rec.framework_kind = "soc2"  # type: ignore[misc]
    c.check("fw-1", "A1", cp.VERDICT_PASS, 2)
    errs = []
    def reader():
        try:
            c.attest("fw-1", 99)
            c.framework_ids(99)
        except Exception as e:  # pragma: no cover
            errs.append(e)
    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errs


def test_main_subprocess():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..",
                        "compliance.py")
    out = subprocess.run([sys.executable, path], capture_output=True,
                         text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == (
        "compliance OK: register, check, remediate, attest, pins, audit")
