"""Targeted tests for cmmc.py (15 tests)."""

from __future__ import annotations

import ast
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

import cmmc as cm

DIGEST = "sha256:" + "ab" * 32
DIGEST2 = "sha256:" + "cd" * 32


def make() -> cm.CMMC:
    return cm.CMMC()


def test_version_and_schema_pins():
    assert cm.CMMC_VERSION == "cmmc.v1"
    assert cm.SCHEMA_PIN == "northstar.cmmc.v1"
    assert cm.AUDIT_SCHEMA == "audit.ndjson/1"
    assert cm.LEVEL_1 == "level-1"
    assert cm.LEVEL_2 == "level-2"
    assert cm.LEVEL_3 == "level-3"
    assert cm.RESULT_MET == "met"
    assert cm.RESULT_NOT_MET == "not-met"
    assert cm.ACTION_FIX_CONTROL == "fix-control"


def test_stdlib_only():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..",
                        "cmmc.py")
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
    rec = c.register_system("sys-1", cm.LEVEL_2, 1, DIGEST)
    assert rec.system_id == "sys-1"
    assert rec.level == cm.LEVEL_2
    assert rec.verify("sys-1", cm.LEVEL_2, DIGEST) is True
    assert rec.verify("sys-1", cm.LEVEL_3, DIGEST) is False
    assert c.system_record("sys-1", 2) is rec
    assert c.system_ids(3) == ("sys-1",)
    assert c.level_practice_count(cm.LEVEL_1, 4) == 17
    assert c.level_practice_count(cm.LEVEL_2, 5) == 110
    assert c.level_practice_count(cm.LEVEL_3, 6) == 134
    with pytest.raises(cm.BadLevelError):
        c.level_practice_count("level-9", 7)


def test_register_bad_inputs_seq_burn_rejected_rows():
    c = make()
    n_rejected = 0
    bad = [
        lambda s: c.register_system("sys-1", "level-9", s),
        lambda s: c.register_system("sys-1", cm.LEVEL_1, s, "raw-text"),
        lambda s: c.register_system("", cm.LEVEL_1, s),
        lambda s: c.register_system(123, cm.LEVEL_1, s),
    ]
    seq = 1
    for fn in bad:
        with pytest.raises(cm.CMMCError):
            fn(seq)
        n_rejected += 1
        seq += 1
    # duplicate consumes seq and books a rejected row
    c.register_system("sys-2", cm.LEVEL_3, seq)
    seq += 1
    with pytest.raises(cm.DuplicateSystemError):
        c.register_system("sys-2", cm.LEVEL_3, seq)
    n_rejected += 1
    seq += 1
    stats = c.stats(seq)
    assert stats["rejected"] == n_rejected
    # seq still advanced: next live mutation takes the next seq
    rec = c.register_system("sys-3", cm.LEVEL_1, seq)
    assert rec.seq == seq


def test_assess_roundtrip_minted_ids_and_verify():
    c = make()
    c.register_system("sys-1", cm.LEVEL_2, 1)
    a1 = c.assess("sys-1", "AC.L2-3.1.1", cm.RESULT_MET, 2, DIGEST)
    a2 = c.assess("sys-1", "AC.L2-3.1.2", cm.RESULT_NOT_MET, 3)
    assert a1.assessment_id == "asm-1"
    assert a2.assessment_id == "asm-2"
    assert a1.verify("sys-1", "AC.L2-3.1.1", cm.RESULT_MET, DIGEST) is True
    assert a2.verify("sys-1", "AC.L2-3.1.2", cm.RESULT_NOT_MET, "") is True
    assert a2.verify("sys-1", "AC.L2-3.1.2", cm.RESULT_NOT_MET, DIGEST) is False
    assert c.assessment_record("asm-1", 4) is a1
    assert c.assessments_for("sys-1", 5) == ("asm-1", "asm-2")
    with pytest.raises(cm.UnknownAssessmentError):
        c.assessment_record("asm-9", 6)


def test_assess_bad_inputs_seq_burn():
    c = make()
    c.register_system("sys-1", cm.LEVEL_2, 1)
    n_rejected = 0
    seq = 2
    cases = [
        lambda s: c.assess("nope", "AC.L2-3.1.1", cm.RESULT_MET, s),
        lambda s: c.assess("sys-1", "AC.L2-3.1.1", "maybe", s),
        lambda s: c.assess("sys-1", "", cm.RESULT_MET, s),
        lambda s: c.assess("sys-1", "AC.L2-3.1.1", cm.RESULT_MET, s, "raw"),
    ]
    for fn in cases:
        with pytest.raises(cm.CMMCError):
            fn(seq)
        n_rejected += 1
        seq += 1
    assert c.stats(seq)["rejected"] == n_rejected
    a = c.assess("sys-1", "AC.L2-3.1.1", cm.RESULT_MET, seq)
    assert a.assessment_id == "asm-1"


def test_remediate_roundtrip_and_verify():
    c = make()
    c.register_system("sys-1", cm.LEVEL_2, 1)
    c.assess("sys-1", "AC.L2-3.1.2", cm.RESULT_NOT_MET, 2)
    rec = c.remediate("asm-1", cm.ACTION_FIX_CONTROL, 3, DIGEST)
    assert rec.remediation_id == "rmd-1"
    assert rec.verify("asm-1", cm.ACTION_FIX_CONTROL, DIGEST) is True
    assert rec.verify("asm-1", cm.ACTION_ESCALATE, DIGEST) is False


def test_remediate_refusals_seq_burn():
    c = make()
    c.register_system("sys-1", cm.LEVEL_2, 1)
    c.assess("sys-1", "AC.L2-3.1.1", cm.RESULT_MET, 2)      # asm-1: met
    c.assess("sys-1", "AC.L2-3.1.2", cm.RESULT_NOT_MET, 3)  # asm-2: not-met
    n_rejected = 0
    seq = 4
    with pytest.raises(cm.UnknownAssessmentError):
        c.remediate("asm-9", cm.ACTION_FIX_CONTROL, seq)
    n_rejected += 1
    seq += 1
    with pytest.raises(cm.RemediationNotNeededError):
        c.remediate("asm-1", cm.ACTION_FIX_CONTROL, seq)
    n_rejected += 1
    seq += 1
    with pytest.raises(cm.BadActionError):
        c.remediate("asm-2", "wing-it", seq)
    n_rejected += 1
    seq += 1
    c.remediate("asm-2", cm.ACTION_ESCALATE, seq)
    seq += 1
    with pytest.raises(cm.AlreadyRemediatedError):
        c.remediate("asm-2", cm.ACTION_FIX_CONTROL, seq)
    n_rejected += 1
    seq += 1
    assert c.stats(seq)["rejected"] == n_rejected


def test_certify_postures_and_read_purity():
    c = make()
    c.register_system("sys-1", cm.LEVEL_2, 1)
    rep = c.certify("sys-1", 2)
    assert rep.posture == "not-assessed"
    assert rep.verify("sys-1", cm.LEVEL_2, "not-assessed", 0, 0, 0, 0) is True
    c.assess("sys-1", "AC.L2-3.1.1", cm.RESULT_MET, 3)
    rep = c.certify("sys-1", 4)
    assert rep.posture == "certified"
    c.assess("sys-1", "AC.L2-3.1.2", cm.RESULT_NOT_MET, 5)
    rep = c.certify("sys-1", 6)
    assert rep.posture == "not-certified"
    assert (rep.n_assessments, rep.n_met, rep.n_not_met,
            rep.n_remediated) == (2, 1, 1, 0)
    c.remediate("asm-2", cm.ACTION_FIX_CONTROL, 7)
    rep2 = c.certify("sys-1", 8)
    assert rep2.posture == "certified"
    assert rep2.n_remediated == 1
    # pure read: same seq twice, no audit rows, no seq consumption
    before = len(c.audit_log(9))
    r1 = c.certify("sys-1", 10)
    r2 = c.certify("sys-1", 10)
    assert r1 == r2
    assert len(c.audit_log(11)) == before
    with pytest.raises(cm.UnknownSystemError):
        c.certify("sys-9", 12)


def test_certify_na_practices_do_not_break_certification():
    c = make()
    c.register_system("sys-1", cm.LEVEL_1, 1)
    c.assess("sys-1", "AC.L1-1.1.1", cm.RESULT_NA, 2)
    c.assess("sys-1", "AC.L1-1.1.2", cm.RESULT_MET, 3)
    rep = c.certify("sys-1", 4)
    assert rep.posture == "certified"
    assert rep.n_assessments == 2
    assert rep.n_not_met == 0


def test_seq_discipline():
    c = make()
    c.register_system("sys-1", cm.LEVEL_2, 1)
    # rewind raises bare with no rejected row
    n_before = c.stats(2)["rejected"]
    with pytest.raises(cm.SeqOrderError):
        c.assess("sys-1", "AC.L2-3.1.1", cm.RESULT_MET, 1)
    assert c.stats(3)["rejected"] == n_before
    # malformed seqs raise bare
    for bad in (True, "2", 2.0, None, -1):
        with pytest.raises(cm.SeqOrderError):
            c.assess("sys-1", "AC.L2-3.1.1", cm.RESULT_MET, bad)
    # failed mutation consumes its seq
    with pytest.raises(cm.BadResultError):
        c.assess("sys-1", "AC.L2-3.1.1", "maybe", 4)
    a = c.assess("sys-1", "AC.L2-3.1.1", cm.RESULT_MET, 5)
    assert a.assessment_id == "asm-1"


def test_audit_shapes_and_leak_ban():
    c = make()
    c.register_system("sys-1", cm.LEVEL_2, 1, DIGEST)
    c.assess("sys-1", "AC.L2-3.1.2", cm.RESULT_NOT_MET, 2)
    c.remediate("asm-1", cm.ACTION_DOCUMENT, 3)
    rows = c.audit_log(4)
    assert [r["kind"] for r in rows] == [
        "cmmc.registered", "cmmc.assessed", "cmmc.remediated"]
    for r in rows:
        assert r["schema"] == "audit.ndjson/1"
        assert r["module"] == "cmmc.v1"
    for banned in ("description", "raw", "content", "evidence", "finding",
                   "details", "plan"):
        with pytest.raises(cm.AuditKindError):
            cm.cmmc_audit_event("cmmc.assessed", {banned: "x"}, 1)
    with pytest.raises(cm.AuditKindError):
        cm.cmmc_audit_event("cmmc.bogus", {}, 1)


def test_cross_instance_determinism_and_tamper():
    a, b = make(), make()
    ra = a.register_system("sys-1", cm.LEVEL_2, 1, DIGEST)
    rb = b.register_system("sys-1", cm.LEVEL_2, 1, DIGEST)
    assert ra.digest == rb.digest
    aa = a.assess("sys-1", "AC.L2-3.1.1", cm.RESULT_MET, 2, DIGEST)
    ab = b.assess("sys-1", "AC.L2-3.1.1", cm.RESULT_MET, 2, DIGEST)
    assert aa.digest == ab.digest
    # tamper breaks verify
    object.__setattr__(aa, "digest", "sha256:" + "00" * 32)
    assert aa.verify("sys-1", "AC.L2-3.1.1", cm.RESULT_MET, DIGEST) is False
    assert a.stats(3)["systems"] == 1
    assert a.stats(4)["assessments"] == 1


def test_frozen_records_and_concurrency_smoke():
    import threading
    c = make()
    rec = c.register_system("sys-1", cm.LEVEL_1, 1)
    with pytest.raises(Exception):
        rec.level = "level-2"  # type: ignore[misc]
    c.assess("sys-1", "AC.L1-1.1.1", cm.RESULT_MET, 2)
    errs = []
    def reader():
        try:
            c.certify("sys-1", 99)
            c.system_ids(99)
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
                        "cmmc.py")
    out = subprocess.run([sys.executable, path], capture_output=True,
                         text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == (
        "cmmc OK: register, assess, remediate, certify, pins, audit")
