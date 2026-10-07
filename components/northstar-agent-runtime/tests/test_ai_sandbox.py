"""Tests for the ai_sandbox decision ledger (Simulated).

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

import ai_sandbox
from ai_sandbox import (
    AI_SANDBOX_VERSION,
    SCHEMA_PIN,
    AISandbox,
    AISandboxError,
    ARTIFACT_KINDS,
    AuditKindError,
    BadArtifactError,
    BadArtifactKindError,
    BadDigestError,
    BadOutcomeError,
    BadReasonError,
    BadSandboxProfileError,
    POSTURES,
    RETIRE_REASONS,
    RUN_OUTCOMES,
    SANDBOX_PROFILES,
    RetiredArtifactError,
    SeqOrderError,
    UnknownArtifactError,
    UnknownSandboxError,
    ai_sandbox_audit_event,
    stdlib_only,
)

GOOD_DIGEST = "sha256:" + "ab" * 32


def test_pins_and_vocabularies():
    """Version/schema pins and pinned vocabularies are exact."""
    assert AI_SANDBOX_VERSION == "ai-sandbox.v1"
    assert SCHEMA_PIN == "northstar.ai-sandbox.v1"
    assert ARTIFACT_KINDS == (
        "model",
        "agent",
        "tool",
        "plugin",
        "prompt-pack",
        "dataset",
        "policy",
        "workflow",
    )
    assert SANDBOX_PROFILES == (
        "process-jail",
        "no-network",
        "read-only-fs",
        "cpu-quota",
        "no-egress",
        "container",
        "vm",
        "full-isolation",
    )
    assert RUN_OUTCOMES == ("clean", "blocked", "anomalous", "inconclusive")
    assert POSTURES == (
        "untested",
        "compromised-suspect",
        "contested",
        "guarded",
        "clean",
    )
    assert RETIRE_REASONS == ("manual", "superseded", "decommissioned", "false-start")


def test_stdlib_only():
    """AST self-check: only stdlib (plus canonical_json fallback) is imported."""
    assert stdlib_only()
    path = Path(ai_sandbox.__file__)
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


def test_sandbox_roundtrip():
    """sandbox() mints sbx-N ids; records are frozen and digest-verified."""
    ledger = AISandbox()
    rec = ledger.sandbox(
        "artifact-1",
        1,
        artifact_kind="agent",
        sandbox_profile="no-network",
        outcome="clean",
        artifact_digest=GOOD_DIGEST,
    )
    assert rec.sandbox_id == "sbx-1"
    assert rec.artifact_id == "artifact-1"
    assert rec.seq == 1
    assert rec.artifact_kind == "agent"
    assert rec.sandbox_profile == "no-network"
    assert rec.outcome == "clean"
    assert rec.artifact_digest == GOOD_DIGEST
    assert rec.verify()
    # frozen dataclass
    with pytest.raises(Exception):
        rec.outcome = "blocked"  # type: ignore
    rec2 = ledger.sandbox("artifact-1", 2)
    assert rec2.sandbox_id == "sbx-2"


def test_sandbox_bad_inputs():
    """Bad inputs fail closed: seq burned, rejected row booked, rewinds bare."""
    ledger = AISandbox()
    before = len(ledger.audit_log(0))
    # rewind on genesis (seq 0 <= seq 0) raises bare with zero rows
    with pytest.raises(SeqOrderError):
        ledger.sandbox("artifact-1", 0)
    assert len(ledger.audit_log(0)) == before
    bad_calls = [
        ("", 1, "model", "process-jail", "clean"),
        (True, 2, "model", "process-jail", "clean"),
        ("artifact-1", 3, "not-a-kind", "process-jail", "clean"),
        ("artifact-1", 4, "model", "not-a-profile", "clean"),
        ("artifact-1", 5, "model", "process-jail", "not-an-outcome"),
        ("artifact-1", 6, "model", "process-jail", "clean"),
    ]
    # last tuple is valid-shaped; patch digest via kwargs below for the bad digest case
    for artifact_id, seq, kind, profile, outcome in bad_calls[:5]:
        with pytest.raises(AISandboxError):
            ledger.sandbox(
                artifact_id,
                seq,
                artifact_kind=kind,
                sandbox_profile=profile,
                outcome=outcome,
            )
    with pytest.raises(AISandboxError):
        ledger.sandbox("artifact-1", 6, artifact_digest="bad-digest")
    rows = ledger.audit_log(0)
    rejected = [r for r in rows if r["kind"] == "rejected"]
    assert len(rejected) == 6
    for r in rejected:
        assert r["schema"] == "audit.ndjson/1"
        assert r["module"] == "ai-sandbox"


def test_full_artifact_kind_vocabulary():
    """All 8 artifact kinds are accepted."""
    ledger = AISandbox()
    seq = 1
    for kind in ARTIFACT_KINDS:
        rec = ledger.sandbox(f"artifact-{kind}", seq, artifact_kind=kind)
        assert rec.artifact_kind == kind
        assert rec.verify()
        seq += 1


def test_full_sandbox_profile_vocabulary():
    """All 8 sandbox profiles are accepted; bad profile is fail-closed."""
    ledger = AISandbox()
    seq = 1
    for profile in SANDBOX_PROFILES:
        rec = ledger.sandbox(f"artifact-p{seq}", seq, sandbox_profile=profile)
        assert rec.sandbox_profile == profile
        assert rec.verify()
        seq += 1
    with pytest.raises(AISandboxError):
        ledger.sandbox("artifact-bad", seq, sandbox_profile="open-internet")


def test_verify_semantics():
    """verify() is a pure read: verified verdict, read purity, unknown refusal."""
    ledger = AISandbox()
    rec = ledger.sandbox("artifact-v", 1)
    before = len(ledger.audit_log(0))
    rep = ledger.verify(rec.sandbox_id, 2)
    assert rep.verdict == "verified"
    assert rep.integrity_ok is True
    assert rep.verify()
    # same-seq twice: no audit rows, no seq consumption
    rep2 = ledger.verify(rec.sandbox_id, 2)
    assert rep2.digest == rep.digest
    assert len(ledger.audit_log(0)) == before
    with pytest.raises(UnknownSandboxError):
        ledger.verify("sbx-999", 3)


def test_verify_tamper_as_data():
    """Tampering a record flips the verdict to tampered as data, never raised."""
    ledger = AISandbox()
    rec = ledger.sandbox("artifact-t", 1)
    object.__setattr__(rec, "outcome", "anomalous")
    rep = ledger.verify(rec.sandbox_id, 2)
    assert rep.verdict == "tampered"
    assert rep.integrity_ok is False
    assert rep.verify()
    ev = ledger.evaluate("artifact-t", 3)
    assert ev.integrity_ok is False


def test_evaluate_posture_math():
    """All 5 postures, with anomalous > inconclusive > blocked > clean precedence."""
    ledger = AISandbox()
    # clean: all clean
    ledger.sandbox("art-a", 1, outcome="clean")
    ledger.sandbox("art-a", 2, outcome="clean")
    assert ledger.evaluate("art-a", 3).posture == "clean"
    # guarded: any blocked
    ledger.sandbox("art-b", 4, outcome="clean")
    ledger.sandbox("art-b", 5, outcome="blocked")
    assert ledger.evaluate("art-b", 6).posture == "guarded"
    # contested: any inconclusive outranks blocked
    ledger.sandbox("art-c", 7, outcome="blocked")
    ledger.sandbox("art-c", 8, outcome="inconclusive")
    assert ledger.evaluate("art-c", 9).posture == "contested"
    # compromised-suspect: any anomalous outranks everything
    ledger.sandbox("art-d", 10, outcome="clean")
    ledger.sandbox("art-d", 11, outcome="inconclusive")
    ledger.sandbox("art-d", 12, outcome="anomalous")
    ev = ledger.evaluate("art-d", 13)
    assert ev.posture == "compromised-suspect"
    assert ev.n_runs == 3
    assert ev.n_anomalous == 1
    assert ev.n_inconclusive == 1
    assert ev.n_clean == 1
    assert ev.verify()
    # unknown artifact refused
    with pytest.raises(UnknownArtifactError):
        ledger.evaluate("no-such-artifact", 14)


def test_retire_terminality():
    """Retired artifact ids refuse mutations; ids never recycled; reads still work."""
    ledger = AISandbox()
    ledger.sandbox("artifact-r", 1)
    ret = ledger.retire("artifact-r", 2, reason="superseded")
    assert ret.verify()
    assert ret.reason == "superseded"
    # post-retire mutation refused (fail-closed), seq burned
    with pytest.raises(RetiredArtifactError):
        ledger.sandbox("artifact-r", 3)
    assert len([r for r in ledger.audit_log(0) if r["kind"] == "rejected"]) == 1
    # double retire refused
    with pytest.raises(RetiredArtifactError):
        ledger.retire("artifact-r", 4)
    # bad reason refused on unknown artifact
    with pytest.raises(AISandboxError):
        ledger.retire("no-such", 5, reason="nope")
    # new artifact can reuse a different id
    rec = ledger.sandbox("artifact-r2", 6)
    assert rec.sandbox_id == "sbx-2"
    # reads still work post-retire
    assert ledger.evaluate("artifact-r", 7).posture == "clean"
    assert ledger.retire_record("artifact-r", 8).verify()
    assert ledger.retired_ids(9) == ("artifact-r",)
    # all retire reasons work on live artifacts
    seq = 10
    for reason in ("manual", "superseded", "decommissioned", "false-start"):
        ledger.sandbox(f"artifact-{reason}", seq)
        assert ledger.retire(f"artifact-{reason}", seq + 1, reason=reason).verify()
        seq += 2
    ledger.sandbox("artifact-f", seq)
    assert ledger.retire("artifact-f", seq + 1).verify()


def test_seq_discipline():
    """Rewinds raise bare; failed mutations consume seq; malformed seqs raise."""
    ledger = AISandbox()
    ledger.sandbox("artifact-s", 5)
    with pytest.raises(SeqOrderError):
        ledger.sandbox("artifact-s", 5)
    with pytest.raises(SeqOrderError):
        ledger.sandbox("artifact-s", 3)
    for bad in (True, "1", None, 1.5):
        with pytest.raises(SeqOrderError):
            ledger.sandbox("artifact-s", bad)
    # views accept any int shape without consuming
    assert ledger.artifact_ids(-1) == ("artifact-s",)
    assert ledger.audit_log(0) == ledger.audit_log(0)
    for bad in (True, "x", None):
        with pytest.raises(SeqOrderError):
            ledger.artifact_ids(bad)


def test_audit_shapes_and_leak_ban():
    """Audit rows have pinned shape; raw keys banned at builder level; bad kind raises."""
    ledger = AISandbox()
    rec = ledger.sandbox("artifact-a", 1)
    row = ledger.audit_log(0)[0]
    assert row["schema"] == "audit.ndjson/1"
    assert row["module"] == "ai-sandbox"
    assert row["version"] == "ai-sandbox.v1"
    assert row["kind"] == "sandboxed"
    assert row["seq"] == 1
    assert row["details"]["sandbox_id"] == rec.sandbox_id
    # banned raw keys raise at the builder level
    with pytest.raises(AISandboxError):
        ai_sandbox_audit_event("sandboxed", 9, trajectories="raw trajectories")
    with pytest.raises(AISandboxError):
        ai_sandbox_audit_event("sandboxed", 9, weights="raw weights")
    # bad kind raises
    with pytest.raises(AuditKindError):
        ai_sandbox_audit_event("nope", 9)
    # pinned vocab values remain emittable as declared data
    ok = ai_sandbox_audit_event(
        "sandboxed", 9, sandbox_profile="full-isolation", outcome="clean"
    )
    assert ok["details"]["sandbox_profile"] == "full-isolation"


def test_views_and_stats():
    """Pure-read views, stats, and unknown lookups."""
    ledger = AISandbox()
    ledger.sandbox("artifact-x", 1, artifact_kind="tool", sandbox_profile="vm")
    ledger.sandbox("artifact-y", 2, artifact_kind="dataset", outcome="blocked")
    assert ledger.artifact_ids(0) == ("artifact-x", "artifact-y")
    assert ledger.sandbox_ids(0) == ("sbx-1", "sbx-2")
    assert ledger.sandboxes_for("artifact-x", 0)[0].sandbox_id == "sbx-1"
    assert ledger.sandboxes_for("no-such", 0) == ()
    assert ledger.sandbox_record("sbx-1", 0).sandbox_profile == "vm"
    with pytest.raises(UnknownSandboxError):
        ledger.sandbox_record("sbx-999", 0)
    stats = ledger.stats(0)
    assert stats["n_artifacts"] == 2
    assert stats["n_runs"] == 2
    assert stats["n_retired"] == 0
    assert stats["version"] == "ai-sandbox.v1"
    # cross-instance digest determinism
    other = AISandbox()
    other.sandbox("artifact-x", 1, artifact_kind="tool", sandbox_profile="vm")
    assert ledger.sandbox_record("sbx-1", 0).digest == other.sandbox_record(
        "sbx-1", 0
    ).digest


def test_cross_instance_and_threads():
    """Digest determinism + 8-thread concurrent read smoke."""
    ledger = AISandbox()
    ledger.sandbox("artifact-smoke", 1)
    rec = ledger.sandbox_record("sbx-1", 0)
    errors: list = []

    def reader() -> None:
        try:
            for _ in range(50):
                ledger.evaluate("artifact-smoke", 0)
                ledger.verify("sbx-1", 0)
                ledger.audit_log(0)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert rec.verify()


def test_main_subprocess():
    """main() self-check runs green in a subprocess."""
    proc = subprocess.run(
        [sys.executable, "-c", "import ai_sandbox; ai_sandbox.main()"],
        capture_output=True,
        text=True,
        cwd=Path(ai_sandbox.__file__).parent,
    )
    assert proc.returncode == 0, proc.stderr
    assert "ai-sandbox OK: sandbox, verify, evaluate, retire, pins, audit" in proc.stdout
