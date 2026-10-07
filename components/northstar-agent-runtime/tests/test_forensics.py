"""Targeted tests for forensics.py (15 tests)."""

from __future__ import annotations

import ast
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

import forensics as fr

DIGEST = "sha256:" + "ab" * 32
DIGEST2 = "sha256:" + "cd" * 32


def make() -> fr.Forensics:
    return fr.Forensics()


def test_version_and_schema_pins():
    assert fr.FORENSICS_VERSION == "forensics.v1"
    assert fr.SCHEMA_PIN == "northstar.forensics.v1"
    assert fr.AUDIT_SCHEMA == "audit.ndjson/1"


def test_stdlib_only():
    tree = ast.parse(open(os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "forensics.py")).read())
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


def test_acquire_roundtrip_and_verify():
    ledger = make()
    rec = ledger.acquire("case-1", "ev-1", DIGEST, 1, fr.KIND_DISK_IMAGE)
    assert rec.case_id == "case-1"
    assert rec.evidence_kind == fr.KIND_DISK_IMAGE
    assert rec.verify("case-1", "ev-1", fr.KIND_DISK_IMAGE, DIGEST) is True
    assert rec.verify("case-1", "ev-1", fr.KIND_DISK_IMAGE, DIGEST2) is False
    view = ledger.acquisition("ev-1", 2)
    assert view == rec
    assert "ev-1" in ledger.evidence_ids(2)
    assert "case-1" in ledger.case_ids(2)


def test_acquire_duplicate_and_bad_inputs_burn_seq():
    ledger = make()
    ledger.acquire("case-1", "ev-1", DIGEST, 1)
    with pytest.raises(fr.DuplicateEvidenceError):
        ledger.acquire("case-1", "ev-1", DIGEST, 2)
    rows = [r for r in ledger.audit_log(3)
            if r["kind"] == fr.KIND_REJECTED]
    assert len(rows) == 1
    bad = [
        ("", "ev-2", DIGEST, fr.KIND_DISK_IMAGE),   # empty case id
        ("case-1", "ev-2", "nope", fr.KIND_DISK_IMAGE),  # bad digest
        ("case-1", "ev-2", DIGEST, "game"),         # bad kind
    ]
    for seq, (cid, eid, dg, ek) in zip(range(3, 6), bad):
        with pytest.raises(fr.ForensicsError):
            ledger.acquire(cid, eid, dg, seq, ek)
    assert len([r for r in ledger.audit_log(6)
                if r["kind"] == fr.KIND_REJECTED]) == 4


def test_acquire_evidence_kind_vocabulary():
    ledger = make()
    kinds = [fr.KIND_DISK_IMAGE, fr.KIND_MEMORY_DUMP, fr.KIND_LOG_BUNDLE,
             fr.KIND_NETWORK_CAPTURE, fr.KIND_MOBILE_BACKUP]
    for i, kind in enumerate(kinds):
        rec = ledger.acquire("case-k", f"ev-k{i}", DIGEST, i + 1, kind)
        assert rec.evidence_kind == kind
    assert len(ledger.evidence_ids(99)) == 5


def test_analyze_roundtrip_minted_ids_and_verify():
    ledger = make()
    ledger.acquire("case-1", "ev-1", DIGEST, 1)
    rec = ledger.analyze("ev-1", fr.METHOD_TIMELINE,
                         fr.CONCLUSION_COMPROMISED, 2)
    assert rec.analysis_id == "anl-1"
    assert rec.verify("ev-1", fr.METHOD_TIMELINE,
                      fr.CONCLUSION_COMPROMISED) is True
    assert rec.verify("ev-1", fr.METHOD_TIMELINE,
                      fr.CONCLUSION_CLEAN) is False
    rec2 = ledger.analyze("ev-1", fr.METHOD_MALWARE,
                          fr.CONCLUSION_INCONCLUSIVE, 3)
    assert rec2.analysis_id == "anl-2"
    views = ledger.analyses_for("ev-1", 4)
    assert [r.analysis_id for r in views] == ["anl-1", "anl-2"]
    assert ledger.analysis("anl-1", 4) == rec


def test_analyze_bad_inputs_burn_seq():
    ledger = make()
    ledger.acquire("case-1", "ev-1", DIGEST, 1)
    bad = [
        (fr.METHOD_TIMELINE, fr.CONCLUSION_COMPROMISED, True),  # bool conf
        (fr.METHOD_TIMELINE, fr.CONCLUSION_COMPROMISED, 101),   # conf > 100
        (fr.METHOD_TIMELINE, fr.CONCLUSION_COMPROMISED, -1),    # conf < 0
        ("game", fr.CONCLUSION_CLEAN, 50),                     # bad method
        (fr.METHOD_HASH, "game", 50),                           # bad concl
        (True, fr.CONCLUSION_CLEAN, 50),                        # bool method
    ]
    seq = 2
    for method, conclusion, confidence in bad:
        with pytest.raises(fr.ForensicsError):
            ledger.analyze("ev-1", method, conclusion, seq,
                           confidence=confidence)
        seq += 1
    rows = [r for r in ledger.audit_log(100)
            if r["kind"] == fr.KIND_REJECTED]
    assert len(rows) == len(bad)


def test_analyze_unknown_evidence_refused():
    ledger = make()
    with pytest.raises(fr.UnknownEvidenceError):
        ledger.analyze("nope", fr.METHOD_HASH, fr.CONCLUSION_CLEAN, 1)
    with pytest.raises(fr.UnknownEvidenceError):
        ledger.analyses_for("nope", 2)
    with pytest.raises(fr.UnknownEvidenceError):
        ledger.analysis("anl-99", 2)


def test_analyze_after_preserve_refused():
    ledger = make()
    ledger.acquire("case-1", "ev-1", DIGEST, 1)
    ledger.analyze("ev-1", fr.METHOD_TIMELINE, fr.CONCLUSION_CLEAN, 2)
    ledger.preserve("ev-1", 3, fr.REASON_LEGAL_HOLD)
    with pytest.raises(fr.PreservedEvidenceError):
        ledger.analyze("ev-1", fr.METHOD_HASH, fr.CONCLUSION_CLEAN, 4)
    rows = [r for r in ledger.audit_log(5)
            if r["kind"] == fr.KIND_REJECTED]
    assert len(rows) == 1
    # Acquire with the preserved id is retired forever.
    with pytest.raises(fr.RetiredEvidenceError):
        ledger.acquire("case-1", "ev-1", DIGEST, 6)


def test_preserve_roundtrip_and_terminality():
    ledger = make()
    ledger.acquire("case-1", "ev-1", DIGEST, 1)
    rec = ledger.preserve("ev-1", 2, fr.REASON_LITIGATION)
    assert rec.reason == fr.REASON_LITIGATION
    assert rec.verify("ev-1", fr.REASON_LITIGATION) is True
    assert rec.verify("ev-1", fr.REASON_MANUAL) is False
    assert ledger.preservation("ev-1", 3) == rec
    assert "ev-1" in ledger.preserved_ids(3)
    with pytest.raises(fr.PreservedEvidenceError):
        ledger.preserve("ev-1", 4, fr.REASON_MANUAL)


def test_preserve_bad_reason_and_unknown():
    ledger = make()
    ledger.acquire("case-1", "ev-1", DIGEST, 1)
    with pytest.raises(fr.BadReasonError):
        ledger.preserve("ev-1", 2, "game")
    with pytest.raises(fr.BadReasonError):
        ledger.preserve("ev-1", 3, True)
    with pytest.raises(fr.UnknownEvidenceError):
        ledger.preserve("nope", 4)
    with pytest.raises(fr.UnknownEvidenceError):
        ledger.preservation("nope", 5)
    with pytest.raises(fr.UnknownEvidenceError):
        ledger.preservation("ev-1", 5)  # acquired but not preserved
    rows = [r for r in ledger.audit_log(6)
            if r["kind"] == fr.KIND_REJECTED]
    assert len(rows) == 3


def test_seq_discipline_rewind_and_malformed():
    ledger = make()
    ledger.acquire("case-1", "ev-1", DIGEST, 1)
    with pytest.raises(fr.SeqOrderError):  # rewind raises bare
        ledger.acquire("case-2", "ev-2", DIGEST, 1)
    with pytest.raises(fr.SeqOrderError):  # bool seq
        ledger.acquire("case-2", "ev-2", DIGEST, True)
    with pytest.raises(fr.SeqOrderError):  # negative seq
        ledger.acquire("case-2", "ev-2", DIGEST, -1)
    with pytest.raises(fr.SeqOrderError):  # str seq
        ledger.acquire("case-2", "ev-2", DIGEST, "2")
    # Bare rewinds write no rejected rows.
    assert [r for r in ledger.audit_log(2)
            if r["kind"] == fr.KIND_REJECTED] == []
    with pytest.raises(fr.SeqOrderError):  # malformed seq in view
        ledger.stats(True)
    ledger.acquire("case-2", "ev-2", DIGEST, 2)  # seq still free
    assert ledger.stats(3)["evidence"] == 2


def test_audit_shapes_leak_ban_and_bad_kind():
    ledger = make()
    ledger.acquire("case-1", "ev-1", DIGEST, 1)
    ledger.analyze("ev-1", fr.METHOD_TIMELINE,
                   fr.CONCLUSION_COMPROMISED, 2)
    ledger.preserve("ev-1", 3)
    rows = ledger.audit_log(4)
    kinds = [r["kind"] for r in rows]
    assert kinds == [fr.KIND_ACQUIRED, fr.KIND_ANALYZED, fr.KIND_PRESERVED]
    for row in rows:
        assert row["schema"] == "audit.ndjson/1"
        assert row["module"] == "forensics.v1"
        assert row["seq"] in (1, 2, 3)
        for banned in ("bytes", "raw", "content", "payload", "notes",
                       "disk", "memory", "logs", "evidence"):
            assert banned not in row["detail"]
    with pytest.raises(fr.AuditKindError):
        fr.forensics_audit_event("nope.kind", {}, 1)
    with pytest.raises(fr.AuditKindError):
        fr.forensics_audit_event(fr.KIND_ACQUIRED, {"bytes": "x"}, 1)
    with pytest.raises(fr.AuditKindError):
        fr.forensics_audit_event(fr.KIND_ANALYZED, {"disk": "x"}, 1)
    with pytest.raises(fr.AuditKindError):
        fr.forensics_audit_event(fr.KIND_PRESERVED, {"notes": "x"}, 1)


def test_cross_instance_digest_determinism_and_tamper():
    a = make()
    b = make()
    rec_a = a.acquire("case-1", "ev-1", DIGEST, 1)
    rec_b = b.acquire("case-1", "ev-1", DIGEST, 1)
    assert rec_a.digest == rec_b.digest
    anl_a = a.analyze("ev-1", fr.METHOD_HASH, fr.CONCLUSION_CLEAN, 2)
    anl_b = b.analyze("ev-1", fr.METHOD_HASH, fr.CONCLUSION_CLEAN, 2)
    assert anl_a.digest == anl_b.digest
    pre_a = a.preserve("ev-1", 3)
    pre_b = b.preserve("ev-1", 3)
    assert pre_a.digest == pre_b.digest
    # Tampered record fails verify().
    import dataclasses
    tampered = dataclasses.replace(rec_a)
    object.__setattr__(tampered, "digest", "sha256:" + "00" * 32)
    assert tampered.verify("case-1", "ev-1", fr.KIND_DISK_IMAGE,
                          DIGEST) is False


def test_views_stats_and_main():
    ledger = make()
    stats = ledger.stats(1)
    assert stats["evidence"] == 0
    assert stats["analyses"] == 0
    assert stats["preserved"] == 0
    assert stats["audit_rows"] == 0
    ledger.acquire("case-1", "ev-1", DIGEST, 2)
    ledger.acquire("case-2", "ev-2", DIGEST, 3)
    ledger.analyze("ev-1", fr.METHOD_TIMELINE, fr.CONCLUSION_CLEAN, 4)
    ledger.preserve("ev-1", 5)
    stats = ledger.stats(6)
    assert stats["evidence"] == 2
    assert stats["analyses"] == 1
    assert stats["preserved"] == 1
    assert stats["audit_rows"] == 4
    assert stats["last_seq"] == 5
    assert stats["schema"] == "northstar.forensics.v1"
    assert ledger.case_ids(6) == ("case-1", "case-2")
    assert ledger.evidence_ids(6) == ("ev-1", "ev-2")
    assert ledger.preserved_ids(6) == ("ev-1",)
    assert ledger.analyses_for("ev-2", 6) == ()
    # Same-seq reads twice: no seq consumption, no audit rows.
    assert ledger.stats(6) == ledger.stats(6)
    assert len(ledger.audit_log(6)) == 4
    proc = subprocess.run(
        [sys.executable, os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "forensics.py")],
        capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    assert "forensics OK" in proc.stdout
