"""Tests for deepfake_detection.py (synthetic-media detection decision ledger)."""

import ast
import dataclasses
import subprocess
import sys
from pathlib import Path

import pytest

import deepfake_detection as dd
from deepfake_detection import (
    DeepfakeDetection,
    deepfake_detection_audit_event,
    DEEPFAKE_DETECTION_VERSION,
    DEEPFAKE_DETECTION_SCHEMA,
    AUDIT_SCHEMA,
    KIND_ANALYZED,
    KIND_SCORED,
    KIND_FLAGGED,
    KIND_REJECTED,
    MODALITY_IMAGE,
    MODALITY_VIDEO,
    MODALITY_AUDIO,
    MODALITY_TEXT,
    VERDICT_AUTHENTIC,
    VERDICT_SUSPICIOUS,
    VERDICT_SYNTHETIC,
    FLAG_QUARANTINE,
    FLAG_HUMAN_REVIEW,
    FLAG_LABEL_SYNTHETIC,
    FLAG_BLOCK,
    FLAG_ESCALATE,
    DeepfakeDetectionError,
    BadMediaError,
    BadModelError,
    BadModalityError,
    BadDigestError,
    BadScoreError,
    BadFlagError,
    DuplicateMediaError,
    UnknownAnalysisError,
    SeqOrderError,
    AuditKindError,
)

MODULE = Path(dd.__file__)
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64


def fresh():
    return DeepfakeDetection()


def ledger_with_analysis(seq0=1):
    m = fresh()
    ana = m.analyze("media-1", seq0, media_digest=DIGEST_A, modality="video", model_id="det-x")
    return m, ana


# ---------------------------------------------------------------------------


def test_version_and_schema_pins():
    assert DEEPFAKE_DETECTION_VERSION == "deepfake-detection.v1"
    assert DEEPFAKE_DETECTION_SCHEMA == "northstar.deepfake-detection.v1"
    assert AUDIT_SCHEMA == "audit.ndjson/1"


def test_stdlib_only():
    tree = ast.parse(MODULE.read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imported.add(node.module.split(".")[0])
    allowlist = {"__future__", "hashlib", "threading", "dataclasses", "typing", "json", "canonical_json"}
    assert imported <= allowlist, imported - allowlist


def test_analyze_roundtrip_verify():
    m = fresh()
    ana = m.analyze("media-1", 1, media_digest=DIGEST_A, modality="image", model_id="det-v1")
    assert ana.verify()
    assert ana.analysis_id == "ana-1"
    assert ana.media_id == "media-1"
    assert ana.modality == MODALITY_IMAGE
    assert ana.media_digest == DIGEST_A
    assert ana.model_id == "det-v1"
    assert ana.schema == DEEPFAKE_DETECTION_SCHEMA
    assert m.analysis("ana-1", 1) is ana
    assert m.analysis_ids(1) == ("ana-1",)
    # frozen
    with pytest.raises(dataclasses.FrozenInstanceError):
        ana.media_id = "x"  # type: ignore


def test_analyze_bad_inputs_rejected_with_seq_burn():
    m = fresh()
    bad = [
        ("", 1),               # empty media_id
        (123, 2),              # non-str media_id
        (True, 3),             # bool media_id
        ("x" * 257, 4),        # too long
    ]
    for i, (media_id, seq) in enumerate(bad):
        with pytest.raises(DeepfakeDetectionError):
            m.analyze(media_id, seq)
    # bad modality
    with pytest.raises(BadModalityError):
        m.analyze("ok-media", 5, modality="hologram")
    # bad digest
    with pytest.raises(BadDigestError):
        m.analyze("ok-media", 6, media_digest="not-a-digest")
    # bad model_id (bool)
    with pytest.raises(BadModelError):
        m.analyze("ok-media", 7, model_id=True)
    # every failed mutation consumed its seq: 7 rejected rows
    kinds = [e["kind"] for e in m.audit_log()]
    assert kinds == [KIND_REJECTED] * 7
    # seq kept burning: next success must use seq 8
    ana = m.analyze("good", 8)
    assert ana.analysis_id == "ana-1"
    # duplicate media_id refused (ids never recycled)
    with pytest.raises(DuplicateMediaError):
        m.analyze("good", 9)
    assert [e["kind"] for e in m.audit_log()][-1] == KIND_REJECTED


def test_score_roundtrip_verify_verdicts():
    m, ana = ledger_with_analysis()
    cases = [
        (0.0, VERDICT_AUTHENTIC),
        (0.49, VERDICT_AUTHENTIC),
        (0.5, VERDICT_SUSPICIOUS),
        (0.79, VERDICT_SUSPICIOUS),
        (0.8, VERDICT_SYNTHETIC),
        (1, VERDICT_SYNTHETIC),   # int accepted as float
    ]
    for i, (value, verdict) in enumerate(cases):
        scr = m.score(ana.analysis_id, 2 + i, value, detector_digest=DIGEST_B)
        assert scr.verify()
        assert scr.score_id == f"scr-{i + 1}"
        assert scr.verdict == verdict
        assert scr.schema == DEEPFAKE_DETECTION_SCHEMA
    assert len(m.scores_for(ana.analysis_id, 8)) == 6


def test_score_bad_inputs_refused():
    m, ana = ledger_with_analysis()
    bad = [True, float("nan"), float("inf"), float("-inf"), -0.1, 1.1, "0.5", None, [0.5]]
    for i, v in enumerate(bad):
        with pytest.raises(BadScoreError):
            m.score(ana.analysis_id, 2 + i, v)
    # each failure burned its seq and booked a rejected row
    kinds = [e["kind"] for e in m.audit_log()]
    assert kinds[1:] == [KIND_REJECTED] * len(bad)  # kinds[0] is analyzed
    # unknown analysis refused, seq burned
    with pytest.raises(UnknownAnalysisError):
        m.score("ana-999", 2 + len(bad), 0.5)
    assert m.audit_log()[-1]["kind"] == KIND_REJECTED


def test_score_unknown_analysis_refusal_leaves_ledger_unchanged():
    m, ana = ledger_with_analysis()
    with pytest.raises(UnknownAnalysisError):
        m.score("ana-404", 2, 0.5)
    assert m.stats(2)["scores"] == 0
    assert m.scores_for(ana.analysis_id, 2) == ()


def test_flag_roundtrip_verify_vocab():
    m, ana = ledger_with_analysis()
    m.score(ana.analysis_id, 2, 0.9)
    for i, flag in enumerate(
        (FLAG_QUARANTINE, FLAG_HUMAN_REVIEW, FLAG_LABEL_SYNTHETIC, FLAG_BLOCK, FLAG_ESCALATE)
    ):
        rec = m.flag(ana.analysis_id, 3 + i, flag, reason_digest=DIGEST_C)
        assert rec.verify()
        assert rec.flag_id == f"flg-{i + 1}"
        assert rec.flag == flag
        assert rec.schema == DEEPFAKE_DETECTION_SCHEMA
    # flag chain: multiple flags on one analysis
    assert len(m.flags_for(ana.analysis_id, 8)) == 5
    assert m.is_flagged(ana.analysis_id, 8)
    # unknown flag vocabulary refused
    with pytest.raises(BadFlagError):
        m.flag(ana.analysis_id, 8, "delete-forever")
    # unknown analysis refused
    with pytest.raises(UnknownAnalysisError):
        m.flag("ana-999", 9, "block")
    assert [e["kind"] for e in m.audit_log()][-2:] == [KIND_REJECTED, KIND_REJECTED]


def test_seq_discipline():
    m, ana = ledger_with_analysis()
    # rewind: same seq raises bare, burns nothing
    with pytest.raises(SeqOrderError):
        m.analyze("m2", 1)
    assert m.audit_log()[0]["kind"] == KIND_ANALYZED  # no rejected row for rewind
    # malformed seqs
    for bad in (True, "2", 1.5, None, -1):
        with pytest.raises(SeqOrderError):
            m.analyze("m2", bad)
    # failed mutation consumed seq; success continues after burned seqs
    with pytest.raises(BadScoreError):
        m.score(ana.analysis_id, 2, 9.9)
    ana2 = m.analyze("media-2", 3)
    assert ana2.analysis_id == "ana-2"
    # pure-read views never consume seq: reading at the same seq is fine
    assert m.analysis(ana.analysis_id, 3) is ana
    assert m.analysis(ana.analysis_id, 3) is ana


def test_views_read_purity():
    m, ana = ledger_with_analysis()
    m.score(ana.analysis_id, 2, 0.9)
    m.flag(ana.analysis_id, 3, "block")
    before = len(m.audit_log())
    m.analysis("ana-1", 3)
    m.analysis_ids(3)
    m.scores_for(ana.analysis_id, 3)
    m.flags_for(ana.analysis_id, 3)
    m.is_flagged(ana.analysis_id, 3)
    m.summary(3)
    m.stats(3)
    # no audit rows from pure reads, no seq consumption (next mutation at seq 4)
    assert len(m.audit_log()) == before
    ana2 = m.analyze("media-2", 4)
    assert ana2.analysis_id == "ana-2"
    assert m.analysis("ana-999", 4) is None
    with pytest.raises(UnknownAnalysisError):
        m.is_flagged("ana-999", 4)


def test_summary_verify_counts():
    m, ana = ledger_with_analysis()
    m.score(ana.analysis_id, 2, 0.9)
    m.score(ana.analysis_id, 3, 0.1)
    m.score(ana.analysis_id, 4, 0.6)
    m.flag(ana.analysis_id, 5, "block")
    m.analyze("media-2", 6, modality="audio")
    m.analyze("media-3", 7, modality=MODALITY_TEXT)
    rep = m.summary(7)
    assert rep.verify()
    assert rep.total_analyses == 3
    assert rep.total_scores == 3
    assert rep.total_flags == 1
    assert rep.by_verdict == (
        (VERDICT_AUTHENTIC, 1),
        (VERDICT_SUSPICIOUS, 1),
        (VERDICT_SYNTHETIC, 1),
    )
    assert rep.by_flag == (("block", 1),)
    assert rep.by_modality == (("audio", 1), ("text", 1), ("video", 1))
    assert rep.open_analyses == ("ana-2", "ana-3")
    assert rep.schema == DEEPFAKE_DETECTION_SCHEMA
    assert rep.seq == 7
    stats = m.stats(7)
    assert stats["analyses"] == 3 and stats["scores"] == 3 and stats["flags"] == 1
    assert stats["open"] == 2 and stats["last_seq"] == 7


def test_audit_shapes_leak_ban_bad_kind():
    m, ana = ledger_with_analysis()
    ev = deepfake_detection_audit_event(KIND_ANALYZED, 1, analysis_id="ana-1", modality="video")
    assert ev["schema"] == "audit.ndjson/1"
    assert ev["module"] == "deepfake-detection"
    assert ev["digest"].startswith("sha256:")
    # banned detail keys
    for bad in ("media", "bytes", "text", "content", "payload", "raw", "value",
                "reason", "justification", "evidence", "transcript"):
        with pytest.raises(AuditKindError):
            deepfake_detection_audit_event(KIND_SCORED, 2, **{bad: "x"})
    with pytest.raises(AuditKindError):
        deepfake_detection_audit_event("nope.kind", 3)
    # allowed pins cross the boundary fine
    ok = deepfake_detection_audit_event(
        KIND_FLAGGED, 4, analysis_id="ana-1", flag_id="flg-1", flag="block",
        reason_digest=DIGEST_C, record_digest=DIGEST_A,
    )
    assert ok["kind"] == KIND_FLAGGED
    # audit log order matches booking order
    m.score(ana.analysis_id, 2, 0.9)
    m.flag(ana.analysis_id, 3, "block")
    kinds = [e["kind"] for e in m.audit_log()]
    assert kinds == [KIND_ANALYZED, KIND_SCORED, KIND_FLAGGED]


def test_cross_instance_determinism_and_tamper():
    a, _ = ledger_with_analysis()
    b, _ = ledger_with_analysis()
    a.score("ana-1", 2, 0.9, detector_digest=DIGEST_B)
    b.score("ana-1", 2, 0.9, detector_digest=DIGEST_B)
    a.flag("ana-1", 3, "block", reason_digest=DIGEST_C)
    b.flag("ana-1", 3, "block", reason_digest=DIGEST_C)
    sa = a.summary(3)
    sb = b.summary(3)
    assert sa.digest == sb.digest
    # tamper breaks verify
    scr = a.scores_for("ana-1", 3)[0]
    tampered = dataclasses.replace(scr, verdict=VERDICT_AUTHENTIC)
    assert not tampered.verify()
    ana = a.analysis("ana-1", 3)
    assert ana is not None and ana.verify()
    tampered_ana = dataclasses.replace(ana, modality="audio")
    assert not tampered_ana.verify()


def test_all_four_modalities():
    m = fresh()
    for i, mod in enumerate((MODALITY_IMAGE, MODALITY_VIDEO, MODALITY_AUDIO, MODALITY_TEXT)):
        ana = m.analyze(f"media-{i}", i + 1, modality=mod)
        assert ana.verify() and ana.modality == mod
    rep = m.summary(4)
    assert rep.total_analyses == 4
    assert rep.by_modality == (
        (MODALITY_AUDIO, 1), (MODALITY_IMAGE, 1), (MODALITY_TEXT, 1), (MODALITY_VIDEO, 1)
    )


def test_main_subprocess():
    proc = subprocess.run(
        [sys.executable, str(MODULE)],
        capture_output=True,
        text=True,
        cwd=str(MODULE.parent),
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "deepfake-detection OK: analyze, score, flag, summary, pins, audit"
