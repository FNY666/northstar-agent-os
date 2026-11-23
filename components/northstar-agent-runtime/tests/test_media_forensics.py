"""Targeted tests for media_forensics.py (15 tests)."""

from __future__ import annotations

import ast
import importlib
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

import media_forensics as mf

DIGEST = "sha256:" + "ab" * 32
DIGEST2 = "sha256:" + "cd" * 32


def make() -> mf.MediaForensics:
    return mf.MediaForensics()


def test_version_and_schema_pins():
    assert mf.MEDIA_FORENSICS_VERSION == "media-forensics.v1"
    assert mf.SCHEMA_PIN == "northstar.media-forensics.v1"
    assert mf.AUDIT_SCHEMA == "audit.ndjson/1"


def test_stdlib_only():
    tree = ast.parse(open(os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "media_forensics.py")).read())
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


def test_examine_roundtrip_and_verify():
    ledger = make()
    rec = ledger.examine("m-1", DIGEST, 1, mf.KIND_VIDEO)
    assert rec.media_id == "m-1"
    assert rec.media_kind == mf.KIND_VIDEO
    assert rec.verify("m-1", mf.KIND_VIDEO, DIGEST) is True
    assert rec.verify("m-1", mf.KIND_VIDEO, DIGEST2) is False
    view = ledger.examination("m-1", 2)
    assert view == rec
    assert "m-1" in ledger.media_ids(2)


def test_examine_duplicate_and_bad_inputs_burn_seq():
    ledger = make()
    ledger.examine("m-1", DIGEST, 1)
    with pytest.raises(mf.DuplicateMediaError):
        ledger.examine("m-1", DIGEST, 2)
    rows = [r for r in ledger.audit_log(3)
            if r["kind"] == mf.KIND_REJECTED]
    assert len(rows) == 1
    bad = [
        ("", DIGEST, mf.KIND_IMAGE),
        ("m-2", "nope", mf.KIND_IMAGE),
        ("m-2", DIGEST, "game"),
    ]
    for seq, (mid, dg, mk) in zip(range(3, 6), bad):
        with pytest.raises(mf.MediaForensicsError):
            ledger.examine(mid, dg, seq, mk)
    assert len([r for r in ledger.audit_log(6)
                if r["kind"] == mf.KIND_REJECTED]) == 4


def test_finding_roundtrip_minted_ids_and_verify():
    ledger = make()
    ledger.examine("m-1", DIGEST, 1)
    f1 = ledger.finding("m-1", mf.CHECK_METADATA, mf.VERDICT_AUTHENTIC, 2,
                        confidence=90)
    f2 = ledger.finding("m-1", mf.CHECK_COPYMOVE, mf.VERDICT_MANIPULATED, 3)
    assert f1.finding_id == "fnd-1"
    assert f2.finding_id == "fnd-2"
    assert f1.verify("m-1", mf.CHECK_METADATA, mf.VERDICT_AUTHENTIC) is True
    assert f2.verify("m-1", mf.CHECK_METADATA, mf.VERDICT_AUTHENTIC) is False
    ids = [r.finding_id for r in ledger.findings_for("m-1", 4)]
    assert ids == ["fnd-1", "fnd-2"]


def test_finding_bad_check_verdict_confidence_and_unknown():
    ledger = make()
    ledger.examine("m-1", DIGEST, 1)
    with pytest.raises(mf.UnknownMediaError):
        ledger.finding("nope", mf.CHECK_METADATA, mf.VERDICT_AUTHENTIC, 2)
    with pytest.raises(mf.BadCheckError):
        ledger.finding("m-1", "quantum", mf.VERDICT_AUTHENTIC, 3)
    with pytest.raises(mf.BadVerdictError):
        ledger.finding("m-1", mf.CHECK_METADATA, "maybe", 4)
    for seq, conf in zip(range(5, 9), [-1, 101, True, "90"]):
        with pytest.raises(mf.BadVerdictError):
            ledger.finding("m-1", mf.CHECK_METADATA, mf.VERDICT_AUTHENTIC,
                           seq, confidence=conf)
    rejected = [r for r in ledger.audit_log(9)
                if r["kind"] == mf.KIND_REJECTED]
    assert len(rejected) == 7


def test_report_verdict_derivation():
    ledger = make()
    ledger.examine("m-1", DIGEST, 1)
    r0 = ledger.report("m-1", 2)
    assert r0.verdict == mf.REPORT_INSUFFICIENT
    ledger.finding("m-1", mf.CHECK_METADATA, mf.VERDICT_AUTHENTIC, 3)
    ledger.finding("m-1", mf.CHECK_NOISE, mf.VERDICT_INCONCLUSIVE, 4)
    assert ledger.report("m-1", 5).verdict == mf.REPORT_INCONCLUSIVE
    ledger.finding("m-1", mf.CHECK_NOISE, mf.VERDICT_AUTHENTIC, 6)
    assert ledger.report("m-1", 7).verdict == mf.REPORT_AUTHENTIC
    ledger.finding("m-1", mf.CHECK_RESAMPLING, mf.VERDICT_MANIPULATED, 8)
    assert ledger.report("m-1", 9).verdict == mf.REPORT_MANIPULATED
    ledger.finding("m-1", mf.CHECK_HASH, mf.VERDICT_TAMPERED, 10)
    assert ledger.report("m-1", 11).verdict == mf.REPORT_TAMPERED
    rep = ledger.report("m-1", 12)
    assert rep.verify("m-1", mf.REPORT_TAMPERED) is True
    assert dict(rep.verdict_counts)[mf.VERDICT_AUTHENTIC] == 2


def test_report_pure_read_semantics():
    ledger = make()
    ledger.examine("m-1", DIGEST, 1)
    ledger.finding("m-1", mf.CHECK_METADATA, mf.VERDICT_AUTHENTIC, 2)
    n_before = len(ledger.audit_log(3))
    r1 = ledger.report("m-1", 3)
    r2 = ledger.report("m-1", 3)
    assert r1.verdict == r2.verdict == mf.REPORT_AUTHENTIC
    assert len(ledger.audit_log(3)) == n_before
    assert ledger.report("m-1", 2).verdict == mf.REPORT_AUTHENTIC


def test_chain_roundtrip_and_ordered_history():
    ledger = make()
    ledger.examine("m-1", DIGEST, 1)
    c1 = ledger.chain("m-1", "officer-a", 2, mf.ACTION_ACQUIRED)
    c2 = ledger.chain("m-1", "lab-x", 3, mf.ACTION_TRANSFERRED)
    assert c1.custody_id == "cst-1"
    assert c2.custody_id == "cst-2"
    assert c1.verify("m-1", "officer-a", mf.ACTION_ACQUIRED) is True
    hist = ledger.custody_for("m-1", 4)
    assert [c.custodian for c in hist] == ["officer-a", "lab-x"]
    with pytest.raises(mf.UnknownMediaError):
        ledger.chain("nope", "officer-a", 5)
    with pytest.raises(mf.BadActionError):
        ledger.chain("m-1", "officer-a", 6, "quantum")
    with pytest.raises(mf.BadCustodianError):
        ledger.chain("m-1", "", 7)


def test_seq_discipline():
    ledger = make()
    ledger.examine("m-1", DIGEST, 1)
    with pytest.raises(mf.SeqOrderError):
        ledger.examine("m-2", DIGEST, 1)
    with pytest.raises(mf.SeqOrderError):
        ledger.finding("m-1", mf.CHECK_METADATA, mf.VERDICT_AUTHENTIC, True)
    with pytest.raises(mf.SeqOrderError):
        ledger.report("m-1", -1)
    # rewind raises bare: no rejected row booked
    n_before = len([r for r in ledger.audit_log(2)
                    if r["kind"] == mf.KIND_REJECTED])
    with pytest.raises(mf.SeqOrderError):
        ledger.examine("m-2", DIGEST, 0)
    assert len([r for r in ledger.audit_log(2)
                if r["kind"] == mf.KIND_REJECTED]) == n_before


def test_audit_shapes_and_leak_ban():
    ledger = make()
    ledger.examine("m-1", DIGEST, 1)
    ledger.finding("m-1", mf.CHECK_METADATA, mf.VERDICT_AUTHENTIC, 2)
    ledger.chain("m-1", "lab-x", 3)
    rows = ledger.audit_log(4)
    kinds = {r["kind"] for r in rows}
    assert kinds == {mf.KIND_EXAMINED, mf.KIND_FINDING, mf.KIND_CUSTODY}
    for r in rows:
        assert r["schema"] == mf.AUDIT_SCHEMA
        assert r["module"] == mf.MEDIA_FORENSICS_VERSION
        assert not mf._BANNED_DETAIL_KEYS.intersection(r["detail"].keys())
    with pytest.raises(mf.AuditKindError):
        mf.media_forensics_audit_event("nope", {}, 1)
    with pytest.raises(mf.AuditKindError):
        mf.media_forensics_audit_event(mf.KIND_FINDING, {"notes": "x"}, 1)


def test_cross_instance_digest_determinism():
    a, b = make(), make()
    ra = a.examine("m-1", DIGEST, 1)
    rb = b.examine("m-1", DIGEST, 1)
    assert ra.digest == rb.digest
    fa = a.finding("m-1", mf.CHECK_METADATA, mf.VERDICT_AUTHENTIC, 2)
    fb = b.finding("m-1", mf.CHECK_METADATA, mf.VERDICT_AUTHENTIC, 2)
    assert fa.digest == fb.digest


def test_stats_view():
    ledger = make()
    ledger.examine("m-1", DIGEST, 1)
    ledger.finding("m-1", mf.CHECK_METADATA, mf.VERDICT_AUTHENTIC, 2)
    ledger.chain("m-1", "lab-x", 3)
    s = ledger.stats(4)
    assert s["media"] == 1 and s["findings"] == 1 and s["custody"] == 1
    assert s["audit_rows"] == 3 and s["last_seq"] == 3


def test_all_media_kind_vocabulary():
    ledger = make()
    for seq, kind in enumerate(mf._MEDIA_KINDS, start=1):
        ledger.examine(f"m-{seq}", DIGEST, seq, kind)
    assert len(ledger.media_ids(9)) == len(mf._MEDIA_KINDS)


def test_main_subprocess_check():
    result = subprocess.run(
        [sys.executable,
         os.path.join(os.path.dirname(os.path.dirname(
             os.path.abspath(__file__))), "media_forensics.py")],
        capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert "media-forensics OK" in result.stdout
