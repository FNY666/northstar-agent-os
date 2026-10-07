"""Tests for the AI OOD-detection decision ledger (ai_ood_detection)."""

import ast
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import ai_ood_detection as ood
from ai_ood_detection import (
    AI_OOD_DETECTION_VERSION,
    AUDIT_KINDS,
    OOD_METHODS,
    RETIRE_REASONS,
    SCHEMA_PIN,
    VERDICTS,
    VERIFY_OUTCOMES,
    AIOODDetection,
    AIOODDetectionError,
    AlreadyVerifiedError,
    AuditKindError,
    BadDigestError,
    BadIdError,
    BadMethodError,
    BadOutcomeError,
    BadReasonError,
    BadVerdictError,
    RetiredSystemError,
    SeqOrderError,
    UnknownDetectionError,
    UnknownSystemError,
    ai_ood_detection_audit_event,
)

PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def fresh() -> AIOODDetection:
    return AIOODDetection()


def test_1_pins_and_vocabularies():
    assert AI_OOD_DETECTION_VERSION == "ai-ood-detection.v1"
    assert SCHEMA_PIN == "northstar.ai-ood-detection.v1"
    assert len(OOD_METHODS) == 8
    assert "mahalanobis" in OOD_METHODS
    assert "energy-score" in OOD_METHODS
    assert len(VERDICTS) == 3
    assert set(VERDICTS) == {"ood", "in-distribution", "inconclusive"}
    assert len(VERIFY_OUTCOMES) == 3
    assert len(RETIRE_REASONS) == 4
    assert set(AUDIT_KINDS) == {"detected", "verified", "retired", "rejected"}


def test_2_stdlib_only_ast_check():
    assert ood.stdlib_only() is True


def test_3_detect_roundtrip_and_frozen():
    led = fresh()
    rec = led.detect("sys-1", "in-1", 1, method="mahalanobis",
                     verdict="ood", input_digest=PIN)
    assert rec.detection_id == "ood-1"
    assert rec.verify() is True
    with pytest.raises(Exception):
        rec.verdict = "in-distribution"  # frozen
    assert led.detection_record("ood-1", 2).detection_id == "ood-1"


def test_4_detect_bad_inputs_seq_burn_and_rejected_rows():
    led = fresh()
    before = led.stats(1)["rejected"]
    cases = [
        (("s", "i", 2), dict(method="nope")),
        (("s", "i", 3), dict(verdict="nope")),
        (("s", "i", 4), dict(input_digest="bogus")),
        ((123, "i", 5), dict()),
        (("s", 123, 6), dict()),
        (("", "i", 7), dict()),
        (("s", "", 8), dict()),
        (("s", "i", 9, ), dict(input_digest=True)),
    ]
    for args, kwargs in cases:
        kwargs.setdefault("method", "mahalanobis")
        kwargs.setdefault("verdict", "ood")
        kwargs.setdefault("input_digest", PIN)
        with pytest.raises(AIOODDetectionError):
            led.detect(*args, **kwargs)
    assert led.stats(10)["rejected"] == before + len(cases)
    # rewind raises bare without consuming: no new audit row, no reject
    n_rows = len(led.audit_log(11))
    with pytest.raises(SeqOrderError):
        led.detect("s", "i", 5)
    assert len(led.audit_log(12)) == n_rows
    assert led.stats(13)["rejected"] == before + len(cases)
    # audit rejected rows account for the bad inputs
    kinds = [r["kind"] for r in led.audit_log(14)]
    assert kinds.count("rejected") == before + len(cases)


def test_5_full_method_vocabulary_accepted():
    led = fresh()
    seq = 1
    for method in OOD_METHODS:
        led.detect(f"sys-{method}", f"in-{method}", seq, method=method,
                   verdict="ood", input_digest=PIN)
        seq += 1
    assert led.stats(seq)["detections"] == len(OOD_METHODS)
    ev = led.evaluate(f"sys-{OOD_METHODS[0]}", seq + 1)
    assert ev.n_ood == 1


def test_6_full_verdict_vocabulary_and_tallies():
    led = fresh()
    led.detect("sys-1", "i1", 1, verdict="ood", input_digest=PIN)
    led.detect("sys-1", "i2", 2, verdict="in-distribution", input_digest=PIN)
    led.detect("sys-1", "i3", 3, verdict="inconclusive", input_digest=PIN)
    ev = led.evaluate("sys-1", 4)
    assert ev.n_detections == 3
    assert ev.n_ood == 1
    assert ev.n_in_distribution == 1
    assert ev.n_inconclusive == 1
    assert ev.integrity_ok is True
    assert ev.verify() is True


def test_7_verify_roundtrip_double_refusal_and_unknown_refusal():
    led = fresh()
    led.detect("sys-1", "i1", 1, verdict="ood", input_digest=PIN)
    v = led.verify("ood-1", 2, outcome="confirmed", review_digest=PIN)
    assert v.verification_id == "ver-1"
    assert v.verify() is True
    with pytest.raises(AlreadyVerifiedError):
        led.verify("ood-1", 3, review_digest=PIN)
    with pytest.raises(UnknownDetectionError):
        led.verify("ood-999", 4, review_digest=PIN)
    with pytest.raises(BadOutcomeError):
        led.verify("ood-1", 5, outcome="nope", review_digest=PIN)


def test_8_verify_semantics_tamper_as_data_and_read_purity():
    led = fresh()
    led.detect("sys-1", "i1", 1, verdict="ood", input_digest=PIN)
    led.verify("ood-1", 2, outcome="confirmed", review_digest=PIN)
    v = led.verification_record("ver-1", 3)
    assert v.verify() is True
    tampered = ood.VerificationRecord(
        verification_id=v.verification_id,
        detection_id=v.detection_id,
        system_id=v.system_id,
        outcome="overturned",
        review_digest=v.review_digest,
        digest=v.digest,
    )
    assert tampered.verify() is False  # tamper reported as data, never raised
    rows_before = len(led.audit_log(4))
    assert led.verification_for("ood-1", 5) == "ver-1"
    assert len(led.audit_log(6)) == rows_before  # pure reads add no rows


def test_9_evaluate_tallies_and_integrity_flip():
    led = fresh()
    led.detect("sys-1", "i1", 1, verdict="ood", input_digest=PIN)
    led.detect("sys-1", "i2", 2, verdict="ood", input_digest=PIN)
    led.verify("ood-1", 3, outcome="confirmed", review_digest=PIN)
    led.verify("ood-2", 4, outcome="overturned", review_digest=PIN2)
    ev = led.evaluate("sys-1", 5)
    assert ev.n_detections == 2
    assert ev.n_verified == 2
    assert ev.n_confirmed == 1
    assert ev.n_overturned == 1
    assert ev.integrity_ok is True
    assert ev.verify() is True
    # tamper flips integrity as data
    led._detections["ood-1"] = ood.DetectionRecord(
        detection_id="ood-1", system_id="sys-1", input_id="i1",
        method="mahalanobis", verdict="in-distribution",
        input_digest=PIN, digest=led._detections["ood-1"].digest,
    )
    ev2 = led.evaluate("sys-1", 6)
    assert ev2.integrity_ok is False
    assert ev2.verify() is True
    with pytest.raises(UnknownSystemError):
        led.evaluate("sys-unknown", 7)


def test_10_retire_terminality_id_non_recycling_and_post_retire_reads():
    led = fresh()
    led.detect("sys-1", "i1", 1, verdict="ood", input_digest=PIN)
    rec = led.retire("sys-1", 2, reason="manual")
    assert rec.verify() is True
    assert "sys-1" in led.retired_ids(3)
    with pytest.raises(RetiredSystemError):
        led.retire("sys-1", 4, reason="manual")
    with pytest.raises(RetiredSystemError):
        led.detect("sys-1", "i2", 5, verdict="ood", input_digest=PIN)
    # reads still work after retire
    assert led.detection_record("ood-1", 6).verdict == "ood"
    ev = led.evaluate("sys-1", 7)
    assert ev.n_detections == 1
    seq = 8
    for reason in ("superseded", "decommissioned", "false-start"):
        led.detect(f"s-{reason}", "i", seq, verdict="ood", input_digest=PIN)
        seq += 1
        led.retire(f"s-{reason}", seq, reason=reason)
        seq += 1
    led.detect("s-badreason", "i", seq, verdict="ood", input_digest=PIN)
    seq += 1
    with pytest.raises(BadReasonError):
        led.retire("s-badreason", seq, reason="nope")


def test_11_seq_discipline():
    led = fresh()
    # genesis rewind (seq 0) is malformed and raises bare
    with pytest.raises(SeqOrderError):
        led.detect("sys-1", "i1", 0, verdict="ood", input_digest=PIN)
    assert len(led.audit_log(1)) == 0
    for bad in (True, "1", 1.5, -3):
        with pytest.raises(SeqOrderError):
            led.detect("sys-1", "i1", bad, verdict="ood", input_digest=PIN)
    led.detect("sys-1", "i1", 1, verdict="ood", input_digest=PIN)
    with pytest.raises(SeqOrderError):
        led.detect("sys-1", "i2", 1, verdict="ood", input_digest=PIN)
    # failed mutation consumes seq (gap allowed, rewind still fires)
    with pytest.raises(BadMethodError):
        led.detect("sys-1", "i2", 2, method="nope", verdict="ood", input_digest=PIN)
    led.detect("sys-1", "i2", 3, verdict="ood", input_digest=PIN)
    assert led.detection_ids(4) == ("ood-1", "ood-2")


def test_12_audit_shapes_leak_ban_and_bad_kind():
    led = fresh()
    led.detect("sys-1", "i1", 1, method="energy-score",
               verdict="ood", input_digest=PIN)
    rows = led.audit_log(2)
    assert rows[0]["schema"] == "audit.ndjson/1"
    assert rows[0]["kind"] == "detected"
    assert rows[0]["details"]["detection_id"] == "ood-1"
    assert rows[0]["details"]["method"] == "energy-score"
    assert "sample_digest" not in rows[0]["details"]
    for banned in ("embedding", "embeddings", "score", "scores", "threshold",
                   "training_data", "input", "prompt", "response", "weights"):
        with pytest.raises(AuditKindError):
            ai_ood_detection_audit_event("detected", 1, **{banned: "x"})
    with pytest.raises(AuditKindError):
        ai_ood_detection_audit_event("nope", 1)
    with pytest.raises(SeqOrderError):
        ai_ood_detection_audit_event("detected", -1)


def test_13_views_and_stats():
    led = fresh()
    led.detect("sys-a", "i1", 1, verdict="ood", input_digest=PIN)
    led.detect("sys-a", "i2", 2, verdict="in-distribution", input_digest=PIN)
    led.detect("sys-b", "i3", 3, verdict="inconclusive", input_digest=PIN)
    led.verify("ood-1", 4, outcome="confirmed", review_digest=PIN)
    assert led.system_ids(5) == ("sys-a", "sys-b")
    assert led.detections_for("sys-a", 6) == ("ood-1", "ood-2")
    with pytest.raises(UnknownDetectionError):
        led.detection_record("ood-999", 7)
    with pytest.raises(UnknownSystemError):
        led.detections_for("sys-unknown", 8)
    assert led.stats(9) == {
        "systems": 2, "detections": 3, "verifications": 1,
        "retired": 0, "rejected": 0,
    }


def test_14_cross_instance_digest_determinism_and_thread_read_smoke():
    seq_led = fresh()
    rec1 = seq_led.detect("sys-1", "i1", 1, method="knn-distance",
                          verdict="in-distribution", input_digest=PIN)
    seq_led.verify("ood-1", 2, outcome="overturned", review_digest=PIN2)
    other = fresh()
    rec2 = other.detect("sys-1", "i1", 1, method="knn-distance",
                        verdict="in-distribution", input_digest=PIN)
    other.verify("ood-1", 2, outcome="overturned", review_digest=PIN2)
    assert rec1.digest == rec2.digest
    assert other.verification_record("ver-1", 3).digest == \
        seq_led.verification_record("ver-1", 3).digest
    errors = []

    def reader():
        try:
            for _ in range(50):
                seq_led.detection_record("ood-1", 1)
                seq_led.evaluate("sys-1", 1)
                seq_led.stats(1)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors


def test_15_main_subprocess_self_check():
    import subprocess

    proc = subprocess.run(
        [sys.executable, "-c", "from ai_ood_detection import main; main()"],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert "ai-ood-detection OK: detect, verify, evaluate, retire, pins, audit" \
        in proc.stdout
