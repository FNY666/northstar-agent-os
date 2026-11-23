"""Tests for model_theft.py — theft-detection/deterrence governance ledger."""

from __future__ import annotations

import ast
import hashlib
import importlib
import subprocess
import sys
import threading

import pytest

sys.path.insert(0, ".")

import model_theft  # noqa: E402
from model_theft import (  # noqa: E402
    AUDIT_KINDS,
    DETERRENCE_ACTIONS,
    SCHEMA,
    VERDICTS,
    VERSION,
    AuditKindError,
    AuditReport,
    BadActionError,
    BadDigestError,
    BadIdError,
    BadSuspicionError,
    BadVerdictError,
    DetectionRecord,
    DeterrenceRecord,
    ModelTheft,
    ModelTheftError,
    SeqOrderError,
    UnknownDetectionError,
    model_theft_audit_event,
)


def _pin(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


PIN = _pin("detector-report")
PARAMS = _pin("rate-limit-params")


def fresh() -> ModelTheft:
    return ModelTheft()


def n_rejected(ledger: ModelTheft) -> int:
    return sum(
        1
        for e in ledger.audit_log()
        if e["kind"] == "model-theft.rejected"
    )


# ---------------------------------------------------------------------------
# 1. pins
# ---------------------------------------------------------------------------


def test_version_schema_pins():
    assert model_theft.VERSION == VERSION == "model-theft.v1"
    assert model_theft.SCHEMA == SCHEMA == "northstar.model-theft.v1"
    assert model_theft.AUDIT_SCHEMA == "audit.ndjson/1"
    assert set(VERDICTS) == {
        "suspected-theft",
        "monitoring",
        "clean",
        "inconclusive",
    }
    assert set(DETERRENCE_ACTIONS) == {
        "rate-limit",
        "noise-inject",
        "watermark-inject",
        "challenge-response",
        "query-ban",
        "model-throttle",
        "escalate",
    }
    assert tuple(AUDIT_KINDS) == (
        "theft-detected",
        "deterrence-applied",
        "model-theft.rejected",
    )


def test_stdlib_only_ast():
    tree = ast.parse(open("model_theft.py").read())
    allowed = {
        "hashlib",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
        "canonical_json",
        "json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed, a.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


# ---------------------------------------------------------------------------
# 2. detect roundtrip
# ---------------------------------------------------------------------------


def test_detect_roundtrip():
    ledger = fresh()
    record = ledger.detect("model-alpha", PIN, 1, 0.85, "suspected-theft")
    assert isinstance(record, DetectionRecord)
    assert record.detection_id == "det-1"
    assert record.model_id == "model-alpha"
    assert record.detector_digest == PIN
    assert record.suspicion == 0.85
    assert record.verdict == "suspected-theft"
    assert record.verify()
    assert record.as_dict()["schema"] == SCHEMA
    got = ledger.detection_record("det-1")
    assert got == record
    assert ledger.stats()["detections"] == 1


def test_detect_ids_mint_in_order():
    ledger = fresh()
    a = ledger.detect("m1", PIN, 1, 0.1, "clean")
    b = ledger.detect("m1", PIN, 2, 0.95, "suspected-theft")
    assert (a.detection_id, b.detection_id) == ("det-1", "det-2")
    assert ledger.detection_ids() == ["det-1", "det-2"]
    assert ledger.model_ids() == ["m1"]


# ---------------------------------------------------------------------------
# 3. detect bad inputs, seq-burn, rejected rows
# ---------------------------------------------------------------------------


def test_detect_bad_inputs_seq_burn():
    ledger = fresh()
    seq = 1
    for call in (
        lambda: ledger.detect("", PIN, seq + 0, 0.5, "monitoring"),
        lambda: ledger.detect("m", "raw-bytes", seq + 1, 0.5, "monitoring"),
        lambda: ledger.detect("m", "SHA256:" + "ab" * 32, seq + 2, 0.5, "monitoring"),
        lambda: ledger.detect("m", PIN, seq + 3, 1.5, "monitoring"),
        lambda: ledger.detect("m", PIN, seq + 4, True, "monitoring"),
        lambda: ledger.detect("m", PIN, seq + 5, 0.5, "proved-theft"),
        lambda: ledger.detect("m", PIN, seq + 6, float("nan"), "monitoring"),
    ):
        with pytest.raises(ModelTheftError):
            call()
    # each failed mutation consumed its seq and booked a rejected row
    assert n_rejected(ledger) == 7
    assert ledger.stats()["seq"] == 7
    assert ledger.stats()["detections"] == 0
    with pytest.raises(BadVerdictError):
        ledger.detect("m", PIN, 8, 0.5, "proved-theft")


# ---------------------------------------------------------------------------
# 4. deter roundtrip + action chain
# ---------------------------------------------------------------------------


def test_deter_roundtrip_chain():
    ledger = fresh()
    det = ledger.detect("m1", PIN, 1, 0.9, "suspected-theft")
    a1 = ledger.deter(det.detection_id, "rate-limit", 2, PARAMS)
    assert isinstance(a1, DeterrenceRecord)
    assert a1.action_id == "dtr-1"
    assert a1.params_digest == PARAMS
    assert a1.verify()
    a2 = ledger.deter(det.detection_id, "query-ban", 3)
    assert a2.action_id == "dtr-2"
    assert a2.params_digest == ""
    chain = ledger.deterrence_for(det.detection_id)
    assert [a.action_id for a in chain] == ["dtr-1", "dtr-2"]
    assert ledger.stats()["deterrence_actions"] == 2


def test_deter_bad_inputs_seq_burn():
    ledger = fresh()
    det = ledger.detect("m1", PIN, 1, 0.9, "suspected-theft")
    seq = 2
    for call in (
        lambda: ledger.deter(det.detection_id, "nuke-model", seq + 0),
        lambda: ledger.deter("det-999", "rate-limit", seq + 1),
        lambda: ledger.deter(det.detection_id, "rate-limit", seq + 2, "not-a-pin"),
    ):
        with pytest.raises(ModelTheftError):
            call()
    assert n_rejected(ledger) == 3
    with pytest.raises(BadActionError):
        ledger.deter(det.detection_id, "nuke-model", 5)
    with pytest.raises(UnknownDetectionError):
        ledger.deter("det-999", "rate-limit", 6)


# ---------------------------------------------------------------------------
# 5. audit report
# ---------------------------------------------------------------------------


def test_audit_report_math():
    ledger = fresh()
    d1 = ledger.detect("m1", PIN, 1, 0.9, "suspected-theft")
    ledger.detect("m1", PIN, 2, 0.2, "clean")
    ledger.deter(d1.detection_id, "rate-limit", 3)
    ledger.deter(d1.detection_id, "rate-limit", 4)
    ledger.deter(d1.detection_id, "escalate", 5)
    report = ledger.audit(6, "m1")
    assert isinstance(report, AuditReport)
    assert report.verify()
    assert report.detection_ids == ("det-1", "det-2")
    assert report.verdict_counts == (("suspected-theft", 1), ("clean", 1))
    assert report.deterrence_ids == ("dtr-1", "dtr-2", "dtr-3")
    assert report.actions_applied == (("rate-limit", 2), ("escalate", 1))
    d = report.as_dict()
    assert d["model_id"] == "m1"
    assert d["verdict_counts"] == [
        {"verdict": "suspected-theft", "count": 1},
        {"verdict": "clean", "count": 1},
    ]


def test_audit_pure_read():
    ledger = fresh()
    d1 = ledger.detect("m1", PIN, 1, 0.9, "suspected-theft")
    before = len(ledger.audit_log())
    r1 = ledger.audit(2, "m1")
    r2 = ledger.audit(2, "m1")  # same seq reused: no consumption
    assert r1 == r2
    assert ledger.stats()["seq"] == 1  # detect's seq; audit consumed nothing
    assert len(ledger.audit_log()) == before  # no audit rows written
    assert ledger.audit(3, "no-such-model").detection_ids == ()
    with pytest.raises(BadIdError):
        ledger.audit(4, "")
    with pytest.raises(UnknownDetectionError):
        ledger.detection_record("det-999")


# ---------------------------------------------------------------------------
# 6. seq discipline
# ---------------------------------------------------------------------------


def test_seq_discipline():
    ledger = fresh()
    ledger.detect("m", PIN, 5, 0.5, "monitoring")
    with pytest.raises(SeqOrderError):  # rewind raises bare
        ledger.detect("m", PIN, 5, 0.5, "monitoring")
    with pytest.raises(SeqOrderError):  # below current
        ledger.detect("m", PIN, 3, 0.5, "monitoring")
    with pytest.raises(SeqOrderError):  # bool rejected
        ledger.detect("m", PIN, True, 0.5, "monitoring")
    with pytest.raises(SeqOrderError):  # negative accepted as int but not > current
        ledger.detect("m", PIN, -1, 0.5, "monitoring")
    with pytest.raises(SeqOrderError):
        ledger.detect("m", PIN, "7", 0.5, "monitoring")  # type: ignore[arg-type]
    assert n_rejected(ledger) == 0  # bare raises consume nothing, book nothing
    assert ledger.stats()["detections"] == 1


# ---------------------------------------------------------------------------
# 7. audit builder shapes + leak ban
# ---------------------------------------------------------------------------


def test_audit_event_shapes_and_leak_ban():
    event = model_theft_audit_event("theft-detected", 1, detection_id="det-1")
    assert event["schema"] == "audit.ndjson/1"
    assert event["module"] == "model_theft"
    assert event["kind"] == "theft-detected"
    assert isinstance(event["digest"], str) and event["digest"].startswith("sha256:")
    with pytest.raises(AuditKindError):
        model_theft_audit_event("bogus-kind", 1)
    for banned in (
        "query",
        "queries",
        "input",
        "output",
        "text",
        "content",
        "payload",
        "raw",
        "value",
        "weights",
        "secret",
        "plaintext",
        "key",
    ):
        with pytest.raises(AuditKindError):
            model_theft_audit_event("theft-detected", 2, **{banned: "x"})
    ledger = fresh()
    ledger.detect("m1", PIN, 1, 0.9, "suspected-theft")
    for event in ledger.audit_log():
        assert all(
            k not in event["detail"] for k in ("query", "input", "weights", "text")
        )


def test_mutation_audit_rows():
    ledger = fresh()
    det = ledger.detect("m1", PIN, 1, 0.9, "suspected-theft")
    ledger.deter(det.detection_id, "watermark-inject", 2)
    kinds = [e["kind"] for e in ledger.audit_log()]
    assert kinds == ["theft-detected", "deterrence-applied"]
    assert ledger.audit_log()[0]["detail"]["verdict"] == "suspected-theft"


# ---------------------------------------------------------------------------
# 8. determinism, tamper, threads, main
# ---------------------------------------------------------------------------


def test_cross_instance_digest_determinism_and_tamper():
    a = fresh()
    b = fresh()
    ra = a.detect("m1", PIN, 1, 0.75, "monitoring")
    rb = b.detect("m1", PIN, 1, 0.75, "monitoring")
    assert ra.digest == rb.digest
    tampered = DetectionRecord(
        detection_id=ra.detection_id,
        model_id=ra.model_id,
        detector_digest=ra.detector_digest,
        suspicion=0.01,
        verdict=ra.verdict,
        seq=ra.seq,
        digest=ra.digest,
    )
    assert not tampered.verify()
    act = a.deter("det-1", "noise-inject", 2)
    assert act.verify()


def test_frozen_and_thread_smoke():
    ledger = fresh()
    det = ledger.detect("m1", PIN, 1, 0.9, "suspected-theft")
    with pytest.raises(Exception):
        det.model_id = "mutated"  # type: ignore[misc]
    def reader():
        ledger.audit(2, "m1")
        ledger.stats()
        ledger.detection_ids()
    threads = [threading.Thread(target=reader) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert ledger.stats()["detections"] == 1


def test_main_self_check():
    proc = subprocess.run(
        [sys.executable, "model_theft.py"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.startswith("model-theft OK:")
