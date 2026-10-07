"""Tests for the AI distribution-shift decision ledger, Simulated."""

import ast
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "ai_distribution_shift.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32
PIN3 = "sha256:" + "ef" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("ai_distribution_shift", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["ai_distribution_shift"] = module
    spec.loader.exec_module(module)
    return module


ads = _load()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert ads.AI_DISTRIBUTION_SHIFT_VERSION == "ai-distribution-shift.v1"
    assert ads.SCHEMA_PIN == "northstar.ai-distribution-shift.v1"
    assert ads.SHIFT_KINDS == (
        "covariate-shift",
        "label-shift",
        "concept-drift",
        "prior-shift",
        "domain-shift",
        "temporal-drift",
        "selection-bias",
        "covariate-drift",
    )
    assert ads.VERDICTS == (
        "shift-detected",
        "suspected",
        "inconclusive",
        "no-shift",
        "not-assessed",
    )
    assert ads.VERIFY_VERDICTS == ("verified", "tampered")
    assert ads.POSTURES == (
        "unexamined",
        "shifted",
        "suspect",
        "contested",
        "unassessed",
        "clean",
    )
    assert ads.RETIRE_REASONS == (
        "manual",
        "superseded",
        "decommissioned",
        "false-start",
    )
    assert set(ads.AUDIT_KINDS) == {"detected", "retired", "rejected"}
    for rec in (ads.DetectionRecord, ads.VerificationReport, ads.RetireRecord,
                ads.ShiftEvaluation):
        assert rec.__dataclass_params__.frozen


# 2. stdlib-only AST check
def test_stdlib_only():
    assert ads.stdlib_only()
    tree = ast.parse(MOD.read_text())
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                found.add(node.module.split(".")[0])
    assert found <= {
        "hashlib", "threading", "dataclasses", "typing", "__future__",
        "ast", "pathlib", "canonical_json", "json",
    }


# 3. detect roundtrip: minting, digest self-verification, frozen records
def test_detect_roundtrip():
    ledger = ads.AIDistributionShift()
    rec = ledger.detect(
        "system-a", 1, shift_kind="covariate-shift",
        verdict="shift-detected", severity=75, detection_digest=PIN,
    )
    assert rec.detection_id == "det-1"
    assert rec.verify()
    assert ledger.system_ids(2) == ("system-a",)
    assert ledger.detection_ids(3) == ("det-1",)
    assert ledger.detections_for("system-a", 4) == ("det-1",)
    assert ledger.detection_record("det-1", 5).detection_id == "det-1"
    # second detection, minted in order
    rec2 = ledger.detect(
        "system-a", 6, shift_kind="label-shift",
        verdict="no-shift", severity=0, detection_digest=PIN2,
    )
    assert rec2.detection_id == "det-2"
    # defaults: shift_kind covariate-shift, verdict not-assessed, severity 0
    rec3 = ledger.detect("system-b", 7, detection_digest=PIN3)
    assert rec3.detection_id == "det-3"
    assert rec3.shift_kind == "covariate-shift"
    assert rec3.verdict == "not-assessed"
    assert rec3.severity == 0
    assert rec3.verify()
    # stats counters
    assert ledger.stats(8) == {
        "systems": 2, "detections": 3, "retired": 0, "rejected": 0,
    }
    # records are frozen
    with pytest.raises(Exception):
        rec.verdict = "suspected"  # type: ignore


# 4. bad-input table: every bad mutation burns its seq and books a rejected row
def test_detect_bad_inputs_burn_seq_and_book_rejected():
    ledger = ads.AIDistributionShift()
    before = len(ledger.audit_log(1))
    # seq starts at 0 (bare rewind check in test 11); first valid claim is 2
    ledger.detect("sys-1", 2, detection_digest=PIN)
    bad_calls = [
        # bad shift_kind
        dict(system_id="sys-2", shift_kind="unknown-kind", detection_digest=PIN),
        # bad verdict
        dict(system_id="sys-2", verdict="maybe", detection_digest=PIN),
        # severity out of range
        dict(system_id="sys-2", severity=101, detection_digest=PIN),
        dict(system_id="sys-2", severity=-1, detection_digest=PIN),
        # severity bool refused
        dict(system_id="sys-2", severity=True, detection_digest=PIN),
        # severity float refused
        dict(system_id="sys-2", severity=1.5, detection_digest=PIN),
        # malformed digest
        dict(system_id="sys-2", detection_digest="nope"),
        dict(system_id="sys-2", detection_digest="sha256:short"),
        # empty system id
        dict(system_id="", detection_digest=PIN),
        dict(system_id=None, detection_digest=PIN),
    ]
    seq = 3
    for kwargs in bad_calls:
        with pytest.raises(ads.AIDistributionShiftError):
            ledger.detect(seq=seq, **kwargs)
        seq += 1
    rejected = [r for r in ledger.audit_log(seq) if r["kind"] == "rejected"]
    assert len(rejected) == len(bad_calls)
    assert all(r["schema"] == "audit.ndjson/1" for r in rejected)
    assert ledger.stats(seq)["rejected"] == len(bad_calls)
    # only the good detection landed
    assert ledger.detection_ids(seq) == ("det-1",)


# 5. full 8-term shift-kind vocabulary accepted
def test_full_shift_kind_vocabulary():
    ledger = ads.AIDistributionShift()
    for i, kind in enumerate(ads.SHIFT_KINDS, start=1):
        rec = ledger.detect(
            f"sys-{kind}", i, shift_kind=kind,
            verdict="suspected", detection_digest=PIN,
        )
        assert rec.shift_kind == kind
        assert rec.verify()
    assert len(ledger.detection_ids(9)) == 8


# 6. full 5-term verdict vocabulary + severity bounds + precedence note
def test_full_verdict_vocabulary_and_severity_bounds():
    ledger = ads.AIDistributionShift()
    for i, verdict in enumerate(ads.VERDICTS, start=1):
        rec = ledger.detect(
            f"sys-{verdict}", i, shift_kind="domain-shift",
            verdict=verdict, severity=100, detection_digest=PIN,
        )
        assert rec.verdict == verdict
        assert rec.severity == 100
        assert rec.verify()
    # severity 0 lower bound
    rec = ledger.detect(
        "sys-zero", 6, verdict="no-shift", severity=0, detection_digest=PIN,
    )
    assert rec.severity == 0


# 7. verify(): pure read, tamper-as-data, unknown refusal, read purity
def test_verify_semantics():
    ledger = ads.AIDistributionShift()
    ledger.detect(
        "sys-1", 1, shift_kind="concept-drift",
        verdict="shift-detected", severity=80, detection_digest=PIN,
    )
    n_audit = len(ledger.audit_log(2))
    rep = ledger.verify("det-1", 3)
    assert rep.verdict == "verified"
    assert rep.verify()
    assert rep.record_id == "det-1"
    # pure read: same seq twice allowed, no audit row, seq not consumed
    rep2 = ledger.verify("det-1", 3)
    assert rep2.verdict == "verified"
    assert len(ledger.audit_log(3)) == n_audit
    # unknown record refuses
    with pytest.raises(ads.UnknownDetectionError):
        ledger.verify("det-999", 4)
    with pytest.raises(ads.BadIdError):
        ledger.verify("", 4)
    # tamper reported as data, never raised
    rec = ledger._detections["det-1"]
    object.__setattr__(rec, "severity", 0)
    rep3 = ledger.verify("det-1", 5)
    assert rep3.verdict == "tampered"
    assert rep3.verify()  # report itself is intact
    ev = ledger.evaluate("sys-1", 6)
    assert ev.integrity_ok is False
    # retire record also verifiable
    ledger.retire("sys-1", 7)
    rep4 = ledger.verify("sys-1", 8)
    assert rep4.verdict == "verified"


# 8. evaluate(): posture ladder math (all postures + precedence)
def test_evaluate_posture_math():
    ledger = ads.AIDistributionShift()
    # shifted outranks everything
    ledger.detect("s1", 1, verdict="shift-detected", severity=90, detection_digest=PIN)
    ledger.detect("s1", 2, verdict="suspected", severity=10, detection_digest=PIN)
    ledger.detect("s1", 3, verdict="no-shift", severity=0, detection_digest=PIN)
    ev = ledger.evaluate("s1", 4)
    assert ev.posture == "shifted"
    assert ev.n_detections == 3
    assert ev.n_shift_detected == 1
    assert ev.n_suspected == 1
    assert ev.n_no_shift == 1
    assert ev.integrity_ok is True
    assert ev.verify()
    # suspect ladder
    ledger.detect("s2", 5, verdict="suspected", detection_digest=PIN)
    ledger.detect("s2", 6, verdict="no-shift", detection_digest=PIN)
    assert ledger.evaluate("s2", 7).posture == "suspect"
    # contested
    ledger.detect("s3", 8, verdict="inconclusive", detection_digest=PIN)
    assert ledger.evaluate("s3", 9).posture == "contested"
    # unassessed (default verdict not-assessed)
    ledger.detect("s4", 10, detection_digest=PIN)
    assert ledger.evaluate("s4", 11).posture == "unassessed"
    # clean (all no-shift)
    ledger.detect("s5", 12, verdict="no-shift", detection_digest=PIN)
    assert ledger.evaluate("s5", 13).posture == "clean"
    # unknown system refuses
    with pytest.raises(ads.UnknownSystemError):
        ledger.evaluate("nope", 14)
    # evaluate is pure read: same seq twice, no audit rows
    n_audit = len(ledger.audit_log(15))
    ledger.evaluate("s5", 15)
    ledger.evaluate("s5", 15)
    assert len(ledger.audit_log(15)) == n_audit


# 9. retire: terminality, id non-recycling, post-retire reads
def test_retire_terminality():
    ledger = ads.AIDistributionShift()
    ledger.detect("sys-1", 1, verdict="shift-detected", detection_digest=PIN)
    ret = ledger.retire("sys-1", 2, reason="decommissioned")
    assert ret.system_id == "sys-1"
    assert ret.reason == "decommissioned"
    assert ret.verify()
    # double retire refused (seq burned, rejected row)
    with pytest.raises(ads.RetiredSystemError):
        ledger.retire("sys-1", 3)
    # post-retire detection refused (id never recycled)
    with pytest.raises(ads.RetiredSystemError):
        ledger.detect("sys-1", 4, detection_digest=PIN)
    # post-retire reads still work
    assert ledger.evaluate("sys-1", 5).posture == "shifted"
    assert ledger.verify("det-1", 6).verdict == "verified"
    assert ledger.retired_ids(7) == ("sys-1",)
    # unknown system retire refused
    with pytest.raises(ads.UnknownSystemError):
        ledger.retire("ghost", 8)
    # all four reasons accepted
    for i, reason in enumerate(ads.RETIRE_REASONS, start=1):
        ledger.detect(f"sys-r{i}", 8 + 2 * i, detection_digest=PIN)
        ledger.retire(f"sys-r{i}", 9 + 2 * i, reason=reason)
    assert len(ledger.retired_ids(18)) == 5
    # bad reason burns seq
    ledger.detect("sys-bad", 19, detection_digest=PIN)
    with pytest.raises(ads.BadReasonError):
        ledger.retire("sys-bad", 20, reason="later")
    assert ledger.stats(21)["rejected"] >= 3


# 10. seq discipline: rewinds bare, malformed seqs, failed-mutation-consumes-seq
def test_seq_discipline():
    ledger = ads.AIDistributionShift()
    # genesis rewind: seq 0 / True are malformed, raise bare, zero rows
    for bad in (0, -1, True, False, 1.5, "2", None):
        with pytest.raises(ads.SeqOrderError):
            ledger.detect("sys-1", bad, detection_digest=PIN)
    assert ledger.audit_log(1) == ()
    assert ledger.stats(1)["rejected"] == 0
    # first valid claim
    ledger.detect("sys-1", 1, detection_digest=PIN)
    # rewind raises bare (no rejected row)
    with pytest.raises(ads.SeqOrderError):
        ledger.detect("sys-2", 1, detection_digest=PIN)
    assert ledger.stats(2)["rejected"] == 0
    # gap seqs allowed
    ledger.detect("sys-2", 100, detection_digest=PIN)
    assert ledger.detection_ids(101) == ("det-1", "det-2")
    # failed mutation after claim consumes seq (burned)
    with pytest.raises(ads.BadShiftKindError):
        ledger.detect("sys-3", 101, shift_kind="bogus", detection_digest=PIN)
    assert ledger.stats(102)["rejected"] == 1
    assert ledger.detection_ids(103) == ("det-1", "det-2")
    # pure-read rewinds also bare (shape check passes but... _check_seq allows
    # any positive int, so reads never fail on seq order; malformed still bare)
    with pytest.raises(ads.SeqOrderError):
        ledger.verify("det-1", 0)


# 11. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    ledger = ads.AIDistributionShift()
    ledger.detect(
        "sys-1", 1, shift_kind="temporal-drift",
        verdict="suspected", severity=42, detection_digest=PIN,
    )
    ledger.retire("sys-1", 2)
    rows = ledger.audit_log(3)
    assert [r["kind"] for r in rows] == ["detected", "retired"]
    det_row = rows[0]
    assert det_row["schema"] == "audit.ndjson/1"
    assert det_row["seq"] == 1
    assert det_row["details"]["shift_kind"] == "temporal-drift"
    assert det_row["details"]["severity"] == 42
    # audit builder bans raw-material keys
    for banned in ("samples", "drift_scores", "feature_stats", "p_values",
                   "reference_data", "labels", "embeddings", "histograms",
                   "dataset", "user_data"):
        with pytest.raises(ads.AuditKindError):
            ads.ai_distribution_shift_audit_event("detected", 9, **{banned: "x"})
    # pinned vocab values and digests stay emittable as declared data
    row = ads.ai_distribution_shift_audit_event(
        "detected", 9, shift_kind="label-shift", verdict="shift-detected",
        severity=42, detection_digest=PIN,
    )
    assert row["details"]["shift_kind"] == "label-shift"
    assert row["details"]["severity"] == 42
    # bad audit kind / bad seq
    with pytest.raises(ads.AuditKindError):
        ads.ai_distribution_shift_audit_event("bogus", 9)
    with pytest.raises(ads.SeqOrderError):
        ads.ai_distribution_shift_audit_event("detected", -1)
    with pytest.raises(ads.SeqOrderError):
        ads.ai_distribution_shift_audit_event("detected", True)
    # failed audit-kind raise happens before any row is appended
    assert len(ledger.audit_log(4)) == 2


# 12. views and stats
def test_views_and_stats():
    ledger = ads.AIDistributionShift()
    ledger.detect("sys-a", 1, shift_kind="prior-shift", verdict="suspected", detection_digest=PIN)
    ledger.detect("sys-b", 2, shift_kind="covariate-drift", verdict="no-shift", detection_digest=PIN2)
    ledger.detect("sys-a", 3, shift_kind="selection-bias", verdict="shift-detected", severity=55, detection_digest=PIN3)
    assert ledger.system_ids(4) == ("sys-a", "sys-b")
    assert ledger.detection_ids(5) == ("det-1", "det-2", "det-3")
    assert ledger.detections_for("sys-a", 6) == ("det-1", "det-3")
    assert ledger.detections_for("sys-b", 7) == ("det-2",)
    assert ledger.retired_ids(8) == ()
    assert ledger.stats(9) == {
        "systems": 2, "detections": 3, "retired": 0, "rejected": 0,
    }
    # unknown lookups refuse
    with pytest.raises(ads.UnknownDetectionError):
        ledger.detection_record("det-999", 10)
    with pytest.raises(ads.UnknownSystemError):
        ledger.detections_for("ghost", 11)
    assert len(ledger.audit_log(12)) == 3


# 13. cross-instance digest determinism + thread read smoke
def test_determinism_and_thread_safety():
    a = ads.AIDistributionShift()
    b = ads.AIDistributionShift()
    for ledger in (a, b):
        ledger.detect(
            "sys-x", 1, shift_kind="label-shift",
            verdict="shift-detected", severity=61, detection_digest=PIN,
        )
    ra = a.detection_record("det-1", 2)
    rb = b.detection_record("det-1", 2)
    assert ra.digest == rb.digest
    assert ra.verify() and rb.verify()
    assert a.evaluate("sys-x", 3).digest == b.evaluate("sys-x", 3).digest
    # 8-thread concurrent pure reads
    errors = []

    def read_worker():
        try:
            for _ in range(50):
                ledger = a
                ledger.verify("det-1", 7)
                ledger.evaluate("sys-x", 8)
                ledger.stats(9)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=read_worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    # tamper on one instance does not leak to the other
    object.__setattr__(ra, "verdict", "no-shift")
    assert ra.verify() is False
    assert rb.verify() is True


# 14. distinct layer: shift ledger vs monitoring/detection ledgers
def test_distinct_layer_vocabularies():
    assert "shift-detected" in ads.VERDICTS
    assert "shifted" in ads.POSTURES
    assert "covariate-shift" in ads.SHIFT_KINDS
    assert "concept-drift" in ads.SHIFT_KINDS
    # shift kinds do not leak into verdicts or postures
    assert not (set(ads.SHIFT_KINDS) & set(ads.VERDICTS))
    assert not (set(ads.VERDICTS) & set(ads.POSTURES))
    assert not (set(ads.SHIFT_KINDS) & set(ads.POSTURES))


# 15. main() subprocess self-check
def test_main_self_check():
    import subprocess

    proc = subprocess.run(
        [sys.executable, str(MOD)],
        capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == (
        "ai-distribution-shift OK: detect, verify, evaluate, retire, pins, audit"
    )
