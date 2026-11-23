"""Tests for the ai_feature decision ledger (Simulated).

House contract: frozen records, caller int seqs strictly increasing
with claim-then-burn, no wall-clock, RLock-guarded, fail-closed
taxonomy, stdlib-only AST-verified, sha256: digest pins, audit.ndjson/1.
"""
from __future__ import annotations

import ast
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import ai_feature
from ai_feature import (
    AI_FEATURE_VERSION,
    SCHEMA_PIN,
    AIFeature,
    AIFeatureError,
    AuditKindError,
    BadDigestError,
    BadFeatureKindError,
    BadReasonError,
    BadSystemError,
    BadVerdictError,
    FEATURE_KINDS,
    FEATURE_VERDICTS,
    POSTURES,
    RETIRE_REASONS,
    RetiredSystemError,
    SeqOrderError,
    UnknownFeatureError,
    UnknownSystemError,
    ai_feature_audit_event,
    stdlib_only,
)

GOOD_DIGEST = "sha256:" + "ab" * 32


def test_pins_and_vocabularies():
    """Version/schema pins and pinned vocabularies are exact."""
    assert AI_FEATURE_VERSION == "ai-feature.v1"
    assert SCHEMA_PIN == "northstar.ai-feature.v1"
    assert FEATURE_KINDS == (
        "activation-pattern",
        "embedding-vector",
        "attention-weight",
        "neuron-response",
        "gradient-signal",
        "representation-cluster",
        "feature-visualization",
        "probe-classifier",
    )
    assert FEATURE_VERDICTS == (
        "extracted",
        "partial",
        "failed",
        "inconclusive",
        "not-attempted",
    )
    assert POSTURES == (
        "unextracted",
        "failed",
        "contested",
        "partially-extracted",
        "extracted",
    )
    assert RETIRE_REASONS == ("manual", "superseded", "decommissioned", "false-start")


def test_stdlib_only():
    """AST self-check: only stdlib (plus canonical_json fallback) is imported."""
    assert stdlib_only()
    path = Path(ai_feature.__file__)
    tree = ast.parse(path.read_text())
    allowed = {
        "hashlib",
        "json",
        "threading",
        "dataclasses",
        "typing",
        "__future__",
        "ast",
        "pathlib",
        "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                assert node.module.split(".")[0] in allowed, node.module


def test_extract_roundtrip():
    """extract() mints fea-N ids; records are frozen and digest-verified."""
    ledger = AIFeature()
    rec = ledger.extract(
        "system-1",
        1,
        feature_kind="embedding-vector",
        verdict="extracted",
        feature_digest=GOOD_DIGEST,
    )
    assert rec.feature_id == "fea-1"
    assert rec.system_id == "system-1"
    assert rec.seq == 1
    assert rec.feature_kind == "embedding-vector"
    assert rec.verdict == "extracted"
    assert rec.feature_digest == GOOD_DIGEST
    assert rec.verify()
    # frozen dataclass
    with pytest.raises(Exception):
        rec.verdict = "failed"  # type: ignore
    rec2 = ledger.extract("system-1", 2)
    assert rec2.feature_id == "fea-2"


def test_extract_bad_inputs():
    """Bad inputs fail closed: seq burned, rejected row booked, rewinds bare."""
    ledger = AIFeature()
    # bad feature kind burns seq 1 and books a rejected row
    with pytest.raises(BadFeatureKindError):
        ledger.extract("system-1", 1, feature_kind="nope")
    rows = ledger.audit_log(2)
    assert rows and rows[-1]["kind"] == "rejected"
    assert ledger.stats(2)["seq"] == 1
    # bad verdict burns seq 2
    with pytest.raises(BadVerdictError):
        ledger.extract("system-1", 2, verdict="nope")
    # bad digest burns seq 3
    with pytest.raises(BadDigestError):
        ledger.extract("system-1", 3, feature_digest="not-a-digest")
    # bad system id burns seq 4
    with pytest.raises(BadSystemError):
        ledger.extract("", 4)
    with pytest.raises(BadSystemError):
        ledger.extract(True, 5)  # type: ignore
    # bad seq shapes are malformed (not AIFeatureError-domain burns)
    with pytest.raises(SeqOrderError):
        ledger.extract("system-1", True)  # type: ignore
    # valid extract on seq 6 after burns
    rec = ledger.extract("system-1", 6)
    assert rec.feature_id == "fea-1"
    # rewind raises bare, consumes nothing
    n_rows = len(ledger.audit_log(7))
    with pytest.raises(SeqOrderError):
        ledger.extract("system-1", 5)
    assert len(ledger.audit_log(7)) == n_rows
    assert ledger.stats(7)["seq"] == 6


def test_full_feature_kind_vocabulary():
    """Every pinned feature kind is accepted as declared data."""
    ledger = AIFeature()
    for i, kind in enumerate(FEATURE_KINDS, start=1):
        rec = ledger.extract("sys-k", i, feature_kind=kind)
        assert rec.feature_kind == kind
        assert rec.verify()


def test_full_verdict_vocabulary():
    """Every pinned verdict is accepted and tallied as data."""
    ledger = AIFeature()
    for i, verdict in enumerate(FEATURE_VERDICTS, start=1):
        ledger.extract("sys-v", i, verdict=verdict)
    ev = ledger.evaluate("sys-v", 6)
    assert ev.n_features == 5
    assert ev.n_extracted == 1
    assert ev.n_partial == 1
    assert ev.n_failed == 1
    assert ev.n_inconclusive == 1
    assert ev.posture == "failed"  # failed outranks


def test_verify_semantics():
    """verify() is a pure read: no seq consumed, no audit row."""
    ledger = AIFeature()
    rec = ledger.extract("system-1", 1)
    before = len(ledger.audit_log(2))
    rep = ledger.verify(rec.feature_id, 1)  # same seq OK - pure read
    assert rep.verdict == "verified"
    assert rep.integrity_ok
    assert rep.verify()
    assert len(ledger.audit_log(2)) == before
    assert ledger.stats(2)["seq"] == 1
    # unknown feature id refuses
    with pytest.raises(UnknownFeatureError):
        ledger.verify("fea-999", 2)
    # bad read seq shape refuses
    with pytest.raises(SeqOrderError):
        ledger.verify(rec.feature_id, "x")  # type: ignore


def test_verify_tamper_as_data():
    """Tampering is reported as data (tampered), never raised."""
    ledger = AIFeature()
    rec = ledger.extract("system-1", 1)
    object.__setattr__(rec, "verdict", "failed")
    assert not rec.verify()
    rep = ledger.verify(rec.feature_id, 2)
    assert rep.verdict == "tampered"
    assert not rep.integrity_ok
    assert rep.verify()  # report itself is well-formed
    ev = ledger.evaluate("system-1", 3)
    assert not ev.integrity_ok


def test_evaluate_posture_math():
    """Posture ladder: failed > contested > partially-extracted > extracted."""
    ledger = AIFeature()
    ledger.extract("sys-a", 1, verdict="extracted")
    ledger.extract("sys-a", 2, verdict="extracted")
    assert ledger.evaluate("sys-a", 3).posture == "extracted"
    ledger.extract("sys-b", 4, verdict="extracted")
    ledger.extract("sys-b", 5, verdict="partial")
    assert ledger.evaluate("sys-b", 6).posture == "partially-extracted"
    ledger.extract("sys-c", 7, verdict="extracted")
    ledger.extract("sys-c", 8, verdict="not-attempted")
    assert ledger.evaluate("sys-c", 9).posture == "partially-extracted"
    ledger.extract("sys-d", 10, verdict="extracted")
    ledger.extract("sys-d", 11, verdict="inconclusive")
    assert ledger.evaluate("sys-d", 12).posture == "contested"
    ledger.extract("sys-e", 13, verdict="inconclusive")
    ledger.extract("sys-e", 14, verdict="failed")
    assert ledger.evaluate("sys-e", 15).posture == "failed"
    # unknown system refuses, pure read
    before = len(ledger.audit_log(16))
    with pytest.raises(UnknownSystemError):
        ledger.evaluate("sys-nope", 16)
    assert len(ledger.audit_log(16)) == before
    ev = ledger.evaluate("sys-a", 17)
    assert ev.n_features == 2
    assert ev.integrity_ok
    assert ev.verify()


def test_retire_terminality():
    """retire() is terminal: ids never recycled, reads still work."""
    ledger = AIFeature()
    ledger.extract("system-1", 1)
    ret = ledger.retire("system-1", 2, reason="decommissioned")
    assert ret.verify()
    assert ret.reason == "decommissioned"
    # post-retire mutations refused (burns seq + rejected row)
    with pytest.raises(RetiredSystemError):
        ledger.extract("system-1", 3)
    rows = ledger.audit_log(4)
    assert rows[-1]["kind"] == "rejected"
    # double retire refused
    with pytest.raises(RetiredSystemError):
        ledger.retire("system-1", 4)
    # bad reason refused
    with pytest.raises(BadReasonError):
        ledger.retire("system-2", 5, reason="nope")
    # unknown system retire refused
    with pytest.raises(UnknownSystemError):
        ledger.retire("sys-nope", 6)
    # post-retire reads still work
    assert ledger.retire_record("system-1", 7).verify()
    assert ledger.evaluate("system-1", 7).posture == "extracted"
    assert ledger.retired_ids(7) == ("system-1",)


def test_seq_discipline():
    """Claim-then-burn: failed mutations consume seq; rewinds raise bare."""
    ledger = AIFeature()
    # genesis rewind (seq 0) raises bare with zero rows
    with pytest.raises(SeqOrderError):
        ledger.extract("system-1", 0)
    assert ledger.audit_log(1) == ()
    assert ledger.stats(1)["seq"] == 0
    # malformed seqs raise bare
    for bad in (-3, "2", 2.5, None, True):  # type: ignore
        with pytest.raises(SeqOrderError):
            ledger.extract("system-1", bad)
    assert ledger.stats(1)["seq"] == 0
    # failed mutation consumes seq
    with pytest.raises(BadFeatureKindError):
        ledger.extract("system-1", 1, feature_kind="bogus")
    assert ledger.stats(1)["seq"] == 1
    # gap seqs are allowed
    rec = ledger.extract("system-1", 10)
    assert rec.seq == 10
    assert ledger.stats(11)["seq"] == 10


def test_audit_shapes_and_leak_ban():
    """Audit rows carry schema/module/version/kind; raw keys are banned."""
    ledger = AIFeature()
    ledger.extract("system-1", 1, feature_kind="attention-weight")
    row = ledger.audit_log(2)[0]
    assert row["schema"] == "audit.ndjson/1"
    assert row["module"] == "ai-feature"
    assert row["version"] == "ai-feature.v1"
    assert row["kind"] == "extracted"
    assert row["details"]["feature_kind"] == "attention-weight"
    # pinned vocab values remain emittable; raw material keys are banned
    for banned in ("activations", "embeddings", "weights", "gradients", "prompt"):
        with pytest.raises(AIFeatureError):
            ai_feature_audit_event("extracted", 2, **{banned: "raw"})
    # bad audit kind refuses
    with pytest.raises(AuditKindError):
        ai_feature_audit_event("nope", 2)
    # digest pins of banned material are fine
    ok = ai_feature_audit_event("extracted", 2, feature_digest=GOOD_DIGEST)
    assert ok["details"]["feature_digest"] == GOOD_DIGEST


def test_views_and_stats():
    """Pure-read views, stats, and audit log are consistent."""
    ledger = AIFeature()
    rec1 = ledger.extract("sys-1", 1)
    rec2 = ledger.extract("sys-1", 2, feature_kind="probe-classifier")
    rec3 = ledger.extract("sys-2", 3)
    assert ledger.feature_record("fea-1", 4) == rec1
    assert ledger.features_for("sys-1", 4) == (rec1, rec2)
    assert ledger.features_for("sys-missing", 4) == ()
    assert ledger.system_ids(4) == ("sys-1", "sys-2")
    assert ledger.feature_ids(4) == ("fea-1", "fea-2", "fea-3")
    assert ledger.retired_ids(4) == ()
    stats = ledger.stats(4)
    assert stats == {
        "n_systems": 2,
        "n_features": 3,
        "n_retired": 0,
        "seq": 3,
        "version": "ai-feature.v1",
    }
    assert len(ledger.audit_log(4)) == 3
    with pytest.raises(UnknownSystemError):
        ledger.retire_record("sys-1", 5)  # not retired yet
    ledger.retire("sys-1", 5)
    assert ledger.stats(6)["n_retired"] == 1


def test_cross_instance_and_threads():
    """Digests are deterministic across instances; reads are thread-safe."""
    a = AIFeature()
    b = AIFeature()
    ra = a.extract("s", 1, feature_kind="gradient-signal")
    rb = b.extract("s", 1, feature_kind="gradient-signal")
    assert ra.digest == rb.digest
    # 8-thread concurrent extract smoke: unique seqs, all land
    ledger = AIFeature()
    errors = []

    def worker(i: int) -> None:
        try:
            ledger.extract("sys-t", (i + 1) * 100)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert ledger.stats(999)["n_features"] == 8
    assert all(r.verify() for r in ledger.features_for("sys-t", 999))


def test_main_subprocess():
    """Module main() self-check runs green in a subprocess."""
    proc = subprocess.run(
        [sys.executable, "-m", "ai_feature"],
        cwd=str(Path(ai_feature.__file__).parent),
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == (
        "ai-feature OK: extract, verify, evaluate, retire, pins, audit"
    )
