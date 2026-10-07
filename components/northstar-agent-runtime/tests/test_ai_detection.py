"""Tests for the AI-detection decision ledger, Simulated."""

import ast
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "ai_detection.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32
PIN3 = "sha256:" + "ef" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("ai_detection", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["ai_detection"] = module
    spec.loader.exec_module(module)
    return module


ad = _load()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert ad.AI_DETECTION_VERSION == "ai-detection.v1"
    assert ad.SCHEMA_PIN == "northstar.ai-detection.v1"
    assert ad.DETECTORS == (
        "watermark",
        "statistical-classifier",
        "stylometric",
        "perplexity",
        "metadata-forensics",
        "human-review",
        "ensemble",
        "behavioral",
    )
    assert ad.VERDICTS == (
        "ai-generated",
        "human-written",
        "uncertain",
    )
    assert ad.VERIFY_OUTCOMES == (
        "confirmed",
        "overturned",
        "inconclusive",
    )
    assert ad.RETIRE_REASONS == (
        "manual",
        "superseded",
        "decommissioned",
        "false-start",
    )
    assert set(ad.AUDIT_KINDS) == {
        "detected",
        "verified",
        "retired",
        "rejected",
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
            for alias in node.names:
                imports.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module.split(".")[0])
    assert imports <= allowed, f"non-stdlib imports: {imports - allowed}"


# 3. detect roundtrip + verify()
def test_detect_roundtrip_and_verify():
    g = ad.AIDetection()
    rec = g.detect(
        "sys-a", "sample-1", 1,
        detector="watermark", verdict="ai-generated", sample_digest=PIN,
    )
    assert rec.detection_id == "det-1"
    assert rec.system_id == "sys-a"
    assert rec.sample_id == "sample-1"
    assert rec.detector == "watermark"
    assert rec.verdict == "ai-generated"
    assert rec.sample_digest == PIN
    assert rec.verify()
    assert rec.as_dict()["schema"] == "northstar.ai-detection.v1"
    fetched = g.detection_record("det-1", 2)
    assert fetched == rec
    assert g.system_ids(3) == ("sys-a",)
    assert g.detection_ids(4) == ("det-1",)
    assert g.detections_for("sys-a", 5) == ("det-1",)


# 4. detect bad-input table + seq-burn + rejected rows
def test_detect_bad_inputs_and_seq_burn():
    g = ad.AIDetection()
    bad = [
        ("", "s1", "watermark", "ai-generated", PIN),
        ("x" * 129, "s1", "watermark", "ai-generated", PIN),
        (None, "s1", "watermark", "ai-generated", PIN),
        ("ok-1", "s1", "not-a-detector", "ai-generated", PIN),
        ("ok-1", "s1", "watermark", "not-a-verdict", PIN),
        ("ok-1", "s1", "watermark", "ai-generated", "not-a-digest"),
        ("ok-1", "s1", "watermark", "ai-generated", ""),
        ("ok-1", None, "watermark", "ai-generated", PIN),
        ("ok-1", "", "watermark", "ai-generated", PIN),
    ]
    for i, (sid, smp, det, ver, pin) in enumerate(bad, start=1):
        with pytest.raises(ad.AIDetectionError):
            g.detect(sid, smp, i, detector=det, verdict=ver, sample_digest=pin)
    assert g.stats(100)["rejected"] == len(bad)
    assert g.stats(101)["detections"] == 0
    kinds = [row["kind"] for row in g.audit_log(102)]
    assert kinds == ["rejected"] * len(bad)
    rows = list(g.audit_log(103))
    assert rows[0]["details"]["method"] == "detect"
    assert rows[0]["seq"] == 1


# 5. detect seq discipline: rewind raises bare, audit seqs are caller seqs
def test_detect_seq_discipline():
    g = ad.AIDetection()
    g.detect("sys-b", "s1", 10, detector="ensemble",
             verdict="human-written", sample_digest=PIN)
    with pytest.raises(ad.SeqOrderError):
        g.detect("sys-b", "s2", 10, detector="ensemble",
                 verdict="human-written", sample_digest=PIN)
    with pytest.raises(ad.SeqOrderError):
        g.detect("sys-b", "s2", 9, detector="ensemble",
                 verdict="human-written", sample_digest=PIN)
    # rewind raised bare: no rejected row for the rewind itself
    assert g.stats(11)["rejected"] == 0
    assert g.stats(12)["detections"] == 1
    seqs = [row["seq"] for row in g.audit_log(13)]
    assert seqs == [10]


# 6. verify roundtrip + double-verify fail-closed
def test_verify_roundtrip_and_double_verify():
    g = ad.AIDetection()
    g.detect("sys-c", "s1", 1, detector="statistical-classifier",
             verdict="uncertain", sample_digest=PIN)
    ver = g.verify("det-1", 2, outcome="confirmed", review_digest=PIN2)
    assert ver.verification_id == "ver-1"
    assert ver.detection_id == "det-1"
    assert ver.system_id == "sys-c"
    assert ver.outcome == "confirmed"
    assert ver.review_digest == PIN2
    assert ver.verify()
    assert g.verification_for("det-1", 3) == "ver-1"
    assert g.verification_ids(4) == ("ver-1",)
    assert g.verifications_for("sys-c", 5) == ("ver-1",)
    with pytest.raises(ad.AlreadyVerifiedError):
        g.verify("det-1", 6, outcome="overturned", review_digest=PIN3)
    with pytest.raises(ad.UnknownDetectionError):
        g.verify("det-999", 7, outcome="confirmed", review_digest=PIN2)
    with pytest.raises(ad.BadOutcomeError):
        g.verify("det-1", 8, outcome="nope", review_digest=PIN2)
    assert g.stats(9)["verifications"] == 1
    assert g.stats(10)["rejected"] == 3


# 7. verify seq-burn bookkeeping + audit shape
def test_verify_audit_shape_and_rejected_rows():
    g = ad.AIDetection()
    g.detect("sys-d", "s1", 1, detector="perplexity",
             verdict="human-written", sample_digest=PIN)
    with pytest.raises(ad.UnknownDetectionError):
        g.verify("det-404", 2, outcome="confirmed", review_digest=PIN)
    rows = list(g.audit_log(3))
    assert rows[0]["schema"] == "audit.ndjson/1"
    assert rows[0]["kind"] == "detected"
    assert rows[1]["kind"] == "rejected"
    assert rows[1]["details"]["method"] == "verify"
    assert rows[1]["details"]["error"] == "UnknownDetectionError"
    # audit rows never carry raw content/score keys
    for row in rows:
        assert "content" not in row["details"]
        assert "score" not in row["details"]


# 8. audit builder: banned keys and unknown kinds
def test_audit_builder_rejects_banned_keys_and_kinds():
    with pytest.raises(ad.AuditKindError):
        ad.ai_detection_audit_event("detected", 1, content="raw text")
    with pytest.raises(ad.AuditKindError):
        ad.ai_detection_audit_event("verified", 1, score=0.99)
    with pytest.raises(ad.AuditKindError):
        ad.ai_detection_audit_event("weird-kind", 1)
    with pytest.raises(ad.SeqOrderError):
        ad.ai_detection_audit_event("detected", -1)
    ev = ad.ai_detection_audit_event(
        "detected", 3, detection_id="det-1", verdict="uncertain")
    assert ev["schema"] == "audit.ndjson/1"
    assert ev["kind"] == "detected"
    assert ev["seq"] == 3


# 9. evaluate() tallies
def test_evaluate_tallies():
    g = ad.AIDetection()
    g.detect("sys-e", "s1", 1, detector="watermark",
             verdict="ai-generated", sample_digest=PIN)
    g.detect("sys-e", "s2", 2, detector="human-review",
             verdict="human-written", sample_digest=PIN2)
    g.detect("sys-e", "s3", 3, detector="ensemble",
             verdict="uncertain", sample_digest=PIN3)
    g.verify("det-1", 4, outcome="confirmed", review_digest=PIN)
    g.verify("det-2", 5, outcome="overturned", review_digest=PIN2)
    ev = g.evaluate("sys-e", 6)
    assert ev.verify()
    assert ev.integrity_ok is True
    assert ev.n_detections == 3
    assert ev.n_ai_generated == 1
    assert ev.n_human_written == 1
    assert ev.n_uncertain == 1
    assert ev.n_verified == 2
    assert ev.n_confirmed == 1
    assert ev.n_overturned == 1
    assert ev.as_dict()["schema"] == "northstar.ai-detection.v1"
    # per-system isolation
    g.detect("sys-f", "s9", 7, detector="stylometric",
             verdict="ai-generated", sample_digest=PIN)
    ev_f = g.evaluate("sys-f", 8)
    assert ev_f.n_detections == 1
    assert ev_f.n_verified == 0


# 10. evaluate unknown system raises
def test_evaluate_unknown_system():
    g = ad.AIDetection()
    with pytest.raises(ad.UnknownSystemError):
        g.evaluate("nope", 1)
    assert g.stats(2)["rejected"] == 0  # pure read burns nothing


# 11. retire + never-recycled ids
def test_retire_and_never_recycled():
    g = ad.AIDetection()
    g.detect("sys-g", "s1", 1, detector="metadata-forensics",
             verdict="ai-generated", sample_digest=PIN)
    rec = g.retire("sys-g", 2, reason="decommissioned")
    assert rec.verify()
    assert g.retired_ids(3) == ("sys-g",)
    with pytest.raises(ad.RetiredSystemError):
        g.detect("sys-g", "s2", 4, detector="watermark",
                 verdict="uncertain", sample_digest=PIN2)
    with pytest.raises(ad.RetiredSystemError):
        g.verify("det-1", 5, outcome="confirmed", review_digest=PIN)
    with pytest.raises(ad.RetiredSystemError):
        g.retire("sys-g", 6, reason="manual")
    with pytest.raises(ad.UnknownSystemError):
        g.retire("ghost", 7, reason="manual")
    with pytest.raises(ad.BadReasonError):
        g.detect("sys-h", "s1", 8, detector="watermark",
                 verdict="uncertain", sample_digest=PIN)
        g.retire("sys-h", 9, reason="nope")


# 12. concurrent detects keep mint order and seq integrity
def test_concurrent_detects():
    g = ad.AIDetection()
    errors = []

    def worker(i):
        try:
            g.detect("sys-i", f"sample-{i}", 1000 + i, detector="ensemble",
                     verdict="uncertain", sample_digest=PIN)
        except Exception as exc:  # pragma: no cover - should not happen
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    st = g.stats(2000)
    assert st["detections"] == 8
    assert st["rejected"] == 0
    assert g.detection_ids(2001) == tuple(f"det-{i}" for i in range(1, 9))
    assert all(r.verify() for r in (g.detection_record(f"det-{i}", 2002) for i in range(1, 9)))


# 13. record tampering breaks verify()
def test_tamper_breaks_verify():
    g = ad.AIDetection()
    rec = g.detect("sys-j", "s1", 1, detector="behavioral",
                   verdict="ai-generated", sample_digest=PIN)
    assert rec.verify()
    tampered = ad.DetectionRecord(
        detection_id=rec.detection_id,
        system_id=rec.system_id,
        sample_id=rec.sample_id,
        detector=rec.detector,
        verdict="human-written",
        sample_digest=rec.sample_digest,
        digest=rec.digest,
    )
    assert not tampered.verify()
    ev = g.evaluate("sys-j", 2)
    assert ev.integrity_ok is True  # ledger's own copy is intact


# 14. digest pins are stable across instances and canonical
def test_digest_stability_and_canonical_json():
    g1 = ad.AIDetection()
    g2 = ad.AIDetection()
    r1 = g1.detect("sys-k", "s1", 1, detector="watermark",
                   verdict="ai-generated", sample_digest=PIN)
    r2 = g2.detect("sys-k", "s1", 1, detector="watermark",
                   verdict="ai-generated", sample_digest=PIN)
    assert r1.digest == r2.digest
    assert r1 == r2
    v1 = g1.verify("det-1", 2, outcome="inconclusive", review_digest=PIN2)
    v2 = g2.verify("det-1", 2, outcome="inconclusive", review_digest=PIN2)
    assert v1.digest == v2.digest
    ev1 = g1.evaluate("sys-k", 3)
    ev2 = g2.evaluate("sys-k", 3)
    assert ev1.digest == ev2.digest


# 15. main() self-check runs clean
def test_main_self_check(capsys):
    ad.main()
    out = capsys.readouterr().out
    assert "ai-detection OK" in out
