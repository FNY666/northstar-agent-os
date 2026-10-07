"""Tests for specification_gaming.py (15 tests, house conventions)."""

import subprocess
import sys
import threading
from dataclasses import FrozenInstanceError

import pytest

import specification_gaming as sg_mod
from specification_gaming import (
    EXPLOIT_KINDS,
    POSTURES,
    RETIRE_REASONS,
    SCHEMA_PIN,
    SPECIFICATION_GAMING_VERSION,
    VERDICTS,
    AuditKindError,
    BadDigestError,
    BadIdError,
    BadKindError,
    BadReasonError,
    BadSeverityError,
    BadVerdictError,
    DuplicateRetireError,
    RetiredObjectiveError,
    SeqOrderError,
    SpecificationGaming,
    UnknownDetectionError,
    UnknownObjectiveError,
    specification_gaming_audit_event,
)

DIGEST = "sha256:" + "c" * 64


# 1. pins ---------------------------------------------------------------
def test_pins():
    assert SPECIFICATION_GAMING_VERSION == "specification-gaming.v1"
    assert SCHEMA_PIN == "northstar.specification-gaming.v1"
    assert len(EXPLOIT_KINDS) == 8
    assert len(VERDICTS) == 4
    assert len(POSTURES) == 5
    assert len(RETIRE_REASONS) == 4


# 2. detect roundtrip ----------------------------------------------------
def test_detect_roundtrip():
    g = SpecificationGaming()
    rec = g.detect("obj-1", 1, exploit_kind="rule-loophole",
                   verdict="exploit-detected", severity=77,
                   evidence_digest=DIGEST)
    assert rec.detection_id == "det-1"
    assert rec.verify()
    assert rec.as_dict()["schema"] == SCHEMA_PIN
    assert rec.objective_id == "obj-1"
    with pytest.raises(FrozenInstanceError):
        rec.severity = 99  # type: ignore[misc]


# 3. detect bad-input table + seq-burn ------------------------------------
def test_detect_bad_inputs():
    g = SpecificationGaming()
    with pytest.raises(BadIdError):
        g.detect("", 1)
    with pytest.raises(BadKindError):
        g.detect("obj-1", 2, exploit_kind="nope")
    with pytest.raises(BadVerdictError):
        g.detect("obj-1", 3, verdict="nope")
    for i, bad in enumerate((True, -1, 101, 1.5, "77", None), start=4):
        with pytest.raises(BadSeverityError):
            g.detect("obj-1", i, severity=bad)
    with pytest.raises(BadDigestError):
        g.detect("obj-1", 10, evidence_digest="sha256:short")
    with pytest.raises(SeqOrderError):
        g.detect("obj-1", 1)  # rewind raises bare
    stats = g.stats(100)
    assert stats["rejected"] == 10  # id + kind + verdict + 6 severity + digest
    assert stats["detections"] == 0
    assert stats["seq"] == 10


# 4. full exploit-kind vocabulary ------------------------------------------
def test_exploit_kind_vocabulary():
    g = SpecificationGaming()
    for i, kind in enumerate(EXPLOIT_KINDS, start=1):
        rec = g.detect("obj-k", i, exploit_kind=kind)
        assert rec.verify()
    assert g.detections_for("obj-k", 100) == tuple(
        f"det-{i}" for i in range(1, 9))


# 5. full verdict vocabulary ------------------------------------------------
def test_verdict_vocabulary():
    g = SpecificationGaming()
    for i, verdict in enumerate(VERDICTS, start=1):
        rec = g.detect(f"obj-v{i}", i, verdict=verdict)
        assert rec.verify()
    tallies = dict(g.evaluate(100).verdict_tallies)
    assert tallies == {v: 1 for v in VERDICTS}


# 6. evaluate posture math ---------------------------------------------------
def test_evaluate_posture_math():
    g = SpecificationGaming()
    assert g.evaluate(1).posture == "unexamined"
    seq = 2
    g.detect("o-exploit", seq, verdict="no-exploit"); seq += 1
    assert g.evaluate(seq, "o-exploit").posture == "spec-sound"; seq += 1
    g.detect("o-incon", seq, verdict="inconclusive"); seq += 1
    assert g.evaluate(seq, "o-incon").posture == "inconclusive"; seq += 1
    g.detect("o-susp", seq, verdict="suspected"); seq += 1
    assert g.evaluate(seq, "o-susp").posture == "suspect"; seq += 1
    g.detect("o-susp", seq, verdict="inconclusive"); seq += 1
    assert g.evaluate(seq, "o-susp").posture == "suspect"
    g.detect("o-game", seq, verdict="exploit-detected"); seq += 1
    g.detect("o-game", seq + 1, verdict="suspected")
    rep = g.evaluate(seq + 2, "o-game")
    assert rep.posture == "gamed"  # precedence over suspected
    assert rep.n_detections == 2
    assert rep.verify()


# 7. evaluate read purity ----------------------------------------------------
def test_evaluate_read_purity():
    g = SpecificationGaming()
    g.detect("obj-1", 1, verdict="suspected")
    r1 = g.evaluate(2, "obj-1")
    r2 = g.evaluate(2, "obj-1")
    assert r1.digest == r2.digest
    stats = g.stats(3)
    assert stats["audit_rows"] == 1  # detect only; evaluate adds nothing
    assert stats["seq"] == 1


# 8. evaluate unknown objective ----------------------------------------------
def test_evaluate_unknown_objective():
    g = SpecificationGaming()
    with pytest.raises(UnknownObjectiveError):
        g.evaluate(1, "ghost")


# 9. verify roundtrip + tamper as data ----------------------------------------
def test_verify_semantics():
    g = SpecificationGaming()
    rec = g.detect("obj-1", 1)
    v = g.verify("det-1", 2)
    assert v.verify() and v.verdict == "verified"
    object.__setattr__(rec, "severity", 99)
    assert rec.verify() is False
    v2 = g.verify("det-1", 3)
    assert v2.verify() and v2.verdict == "tampered"
    with pytest.raises(UnknownDetectionError):
        g.verify("det-9", 4)


# 10. retire terminality ------------------------------------------------------
def test_retire_terminality():
    g = SpecificationGaming()
    g.detect("obj-1", 1)
    r = g.retire("obj-1", 2, reason="spec-repaired")
    assert r.verify()
    with pytest.raises(RetiredObjectiveError):
        g.detect("obj-1", 3)
    with pytest.raises(DuplicateRetireError):
        g.retire("obj-1", 4)
    with pytest.raises(BadReasonError):
        g.retire("obj-2", 5, reason="nope")
    assert g.retired_ids(6) == ("obj-1",)
    assert g.retire_record("obj-1", 7).reason == "spec-repaired"
    # reads still work post-retire
    assert g.detections_for("obj-1", 8) == ("det-1",)
    rep = g.evaluate(9, "obj-1")
    assert rep.posture == "gamed"


# 11. seq discipline ------------------------------------------------------------
def test_seq_discipline():
    g = SpecificationGaming()
    with pytest.raises(SeqOrderError):
        g.detect("obj-1", 0)
    for bad in (True, 1.5, "1", None):
        with pytest.raises(SeqOrderError):
            g.detect("obj-1", bad)
    assert g.stats(100)["rejected"] == 0  # malformed seqs burn nothing
    with pytest.raises(BadKindError):
        g.detect("obj-1", 1, exploit_kind="nope")
    assert g.stats(100)["rejected"] == 1  # failed mutation consumed seq
    assert g.stats(100)["seq"] == 1


# 12. views + stats --------------------------------------------------------------
def test_views_and_stats():
    g = SpecificationGaming()
    g.detect("o1", 1)
    g.detect("o2", 2)
    assert g.objective_ids(3) == ("o1", "o2")
    assert g.detection_ids(4) == ("det-1", "det-2")
    assert g.detection_record("det-1", 5).objective_id == "o1"
    with pytest.raises(UnknownDetectionError):
        g.detection_record("det-9", 6)
    with pytest.raises(UnknownObjectiveError):
        g.retire_record("o9", 7)
    stats = g.stats(8)
    assert stats["objectives"] == 2
    assert stats["detections"] == 2
    assert stats["audit_rows"] == 2


# 13. audit shapes + leak ban + bad kind --------------------------------------------
def test_audit_shapes_and_leak_ban():
    g = SpecificationGaming()
    g.detect("obj-1", 1, severity=10)
    rows = g.audit_log(2)
    assert len(rows) == 1
    assert rows[0]["kind"] == "specification-gaming.detected"
    with pytest.raises(AuditKindError):
        specification_gaming_audit_event("nope", {})
    with pytest.raises(AuditKindError):
        specification_gaming_audit_event("detected", {"spec_text": "x"})
    with pytest.raises(AuditKindError):
        specification_gaming_audit_event("detected", {"metric": "x"})
    g.retire("obj-1", 3)
    kinds = [r["kind"] for r in g.audit_log(4)]
    assert kinds == ["specification-gaming.detected",
                     "specification-gaming.retired"]


# 14. cross-instance determinism + 8-thread read smoke ---------------------------------
def test_determinism_and_threads():
    a, b = SpecificationGaming(), SpecificationGaming()
    ra = a.detect("obj-1", 1, exploit_kind="rule-loophole",
                  verdict="suspected", severity=42)
    rb = b.detect("obj-1", 1, exploit_kind="rule-loophole",
                  verdict="suspected", severity=42)
    assert ra.digest == rb.digest

    g = SpecificationGaming()
    g.detect("obj-1", 1)
    results = []

    def reader():
        results.append(g.evaluate(2, "obj-1").posture)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results == ["gamed"] * 8


# 15. main() subprocess check ----------------------------------------------------------
def test_main_subprocess():
    proc = subprocess.run(
        [sys.executable, sg_mod.__file__],
        capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == (
        "specification-gaming OK: detect, evaluate, verify, pins, audit")
