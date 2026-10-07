"""Tests for the ai-isolation isolate -> verify decision ledger, Simulated."""

import ast
import dataclasses
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "ai_isolation.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("ai_isolation", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["ai_isolation"] = module
    spec.loader.exec_module(module)
    return module


ai = _load()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert ai.AI_ISOLATION_VERSION == "ai-isolation.v1"
    assert ai.SCHEMA_PIN == "northstar.ai-isolation.v1"
    assert ai.ISOLATION_KINDS == (
        "network-partition",
        "sandbox-containment",
        "process-quarantine",
        "resource-fence",
        "api-gateway-cutoff",
        "session-hold",
        "capability-revocation",
        "data-escrow",
    )
    assert ai.ISOLATE_VERDICTS == (
        "isolated",
        "partial",
        "failed",
        "inconclusive",
        "not-attempted",
    )
    assert ai.VERIFY_VERDICTS == ("verified", "tampered")
    assert ai.POSTURES == (
        "unisolated",
        "at-risk",
        "uncertain",
        "contained",
        "isolated",
    )
    assert ai.RETIRE_REASONS == ("manual", "superseded", "decommissioned", "false-start")
    assert ai.AUDIT_KINDS == ("isolated", "retired", "rejected")


# 2. stdlib-only AST check + stdlib_only()
def test_stdlib_only_ast():
    assert ai.stdlib_only() is True
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
    tree = ast.parse(MOD.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                assert node.module.split(".")[0] in allowed


# 3. isolate roundtrip + verify() + frozen-ness
def test_isolate_roundtrip_verify():
    led = ai.AIIsolation()
    rec = led.isolate("sys-1", 1, isolation_kind="sandbox-containment",
                      verdict="isolated", severity=88, isolation_digest=PIN)
    assert rec.isolation_id == "iso-1"
    assert rec.system_id == "sys-1"
    assert rec.seq == 1
    assert rec.verify() is True
    assert led.isolation_record("iso-1", 2) == rec
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.verdict = "failed"  # type: ignore[misc]
    assert led.verify("iso-1", 3).verdict == "verified"
    assert led.system_ids(3) == ["sys-1"]
    assert led.isolation_ids(3) == ["iso-1"]
    st = led.stats(3)
    assert st["n_isolations"] == 1 and st["n_systems"] == 1 and st["seq"] == 1


# 4. isolate bad-input table + seq-burn + rejected-row accounting
def test_isolate_bad_inputs():
    led = ai.AIIsolation()
    with pytest.raises(ai.BadSystemError):
        led.isolate("", 1)
    with pytest.raises(ai.BadSystemError):
        led.isolate(None, 2)  # type: ignore[arg-type]
    with pytest.raises(ai.BadIsolationKindError):
        led.isolate("sys-1", 3, isolation_kind="nope")
    with pytest.raises(ai.BadVerdictError):
        led.isolate("sys-1", 4, verdict="nope")
    with pytest.raises(ai.BadSeverityError):
        led.isolate("sys-1", 5, severity=-1)
    with pytest.raises(ai.BadSeverityError):
        led.isolate("sys-1", 6, severity=101)
    with pytest.raises(ai.BadSeverityError):
        led.isolate("sys-1", 7, severity=True)  # type: ignore[arg-type]
    with pytest.raises(ai.BadDigestError):
        led.isolate("sys-1", 8, isolation_digest="junk")
    with pytest.raises(ai.BadDigestError):
        led.isolate("sys-1", 9, isolation_digest="sha256:" + "zz" * 32)
    rec = led.isolate("sys-1", 10)
    assert rec.isolation_id == "iso-1"
    led.retire("sys-1", 11)
    with pytest.raises(ai.RetiredSystemError):
        led.isolate("sys-1", 12)
    audit = led.audit_log(12)
    assert len(audit) == 12  # 10 rejected + 1 isolated + 1 retired
    assert [r["kind"] for r in audit] == ["rejected"] * 9 + ["isolated", "retired", "rejected"]
    assert all(r["schema"] == "audit.ndjson/1" for r in audit)
    assert led.stats(12)["seq"] == 12
    with pytest.raises(ai.SeqOrderError):  # rewind raises bare, no new row
        led.isolate("sys-1", 12)
    assert len(led.audit_log(12)) == 12


# 5. full isolation-kind vocabulary acceptance
def test_full_isolation_kind_vocabulary():
    led = ai.AIIsolation()
    for i, kind in enumerate(ai.ISOLATION_KINDS, start=1):
        rec = led.isolate("sys-1", i, isolation_kind=kind, verdict="isolated")
        assert rec.isolation_id == f"iso-{i}"
        assert rec.verify() is True
    assert led.stats(8)["n_isolations"] == 8
    assert len(led.isolations_for("sys-1", 9)) == 8


# 6. full verdict vocabulary + severity boundaries
def test_full_verdict_vocabulary():
    led = ai.AIIsolation()
    for i, verdict in enumerate(ai.ISOLATE_VERDICTS, start=1):
        rec = led.isolate("sys-1", i, verdict=verdict, severity=0 if i % 2 else 100)
        assert rec.verify() is True
    tallies = led.evaluate("sys-1", 6)
    assert tallies.n_isolated == 1
    assert tallies.n_partial == 1
    assert tallies.n_failed == 1
    assert tallies.n_inconclusive == 1
    assert tallies.n_not_attempted == 1
    assert tallies.verify() is True


# 7. coverage chains: later isolation covers partial/failed attempts
def test_coverage_chain():
    led = ai.AIIsolation()
    led.isolate("sys-1", 1, isolation_kind="session-hold", verdict="failed")
    led.isolate("sys-1", 2, isolation_kind="network-partition", verdict="partial")
    rep = led.evaluate("sys-1", 3)
    assert rep.posture == "at-risk"       # open failed dominates; partial follow-up does not cover
    assert rep.n_covered == 0            # iso-2 is partial, not isolated: iso-1 still open
    led.isolate("sys-1", 4, isolation_kind="sandbox-containment", verdict="isolated")
    rep2 = led.evaluate("sys-1", 5)
    assert rep2.posture == "contained"    # failed+partial both covered by later isolations
    assert rep2.n_covered == 2
    assert rep2.verify() is True
    assert led.verify("iso-2", 5).verdict == "verified"
    with pytest.raises(dataclasses.FrozenInstanceError):
        led.isolation_record("iso-1", 5).verdict = "isolated"  # type: ignore[misc]


# 8. verify semantics: unknown refusal + tamper-as-data + read purity
def test_verify_semantics():
    led = ai.AIIsolation()
    led.isolate("sys-1", 1, verdict="isolated")
    with pytest.raises(ai.UnknownRecordError):
        led.verify("nope-1", 3)
    r1 = led.verify("iso-1", 4)
    assert (r1.verdict, r1.integrity_ok) == ("verified", True)
    assert r1.verify() is True
    obj = led._isolations["iso-1"]
    object.__setattr__(obj, "verdict", "failed")  # tamper bypasses frozen
    r2 = led.verify("iso-1", 5)
    assert (r2.verdict, r2.integrity_ok) == ("tampered", False)
    assert r1.verify() is True  # report from before tamper still self-consistent
    before = len(led.audit_log(5))
    led.verify("iso-1", 6)
    led.verify("iso-1", 6)
    assert len(led.audit_log(6)) == before  # pure read: no rows, seq not consumed
    assert led.stats(6)["seq"] == 1


# 9. evaluate posture math: all postures + precedence + tallies + integrity
def test_evaluate_posture_math():
    led = ai.AIIsolation()
    led.isolate("sys-A", 1, verdict="failed")                       # open failed -> at-risk
    led.isolate("sys-B", 2, verdict="failed")                       # covered failed
    led.isolate("sys-B", 3, isolation_kind="network-partition", verdict="isolated")
    led.isolate("sys-C", 4, verdict="inconclusive")                  # uncertain
    led.isolate("sys-D", 5, verdict="not-attempted")                 # unisolated
    led.isolate("sys-E", 6, verdict="isolated")
    led.isolate("sys-E", 7, verdict="isolated")                      # isolated
    led.isolate("sys-F", 8, verdict="partial")                       # open partial -> uncertain
    led.isolate("sys-G", 9, verdict="failed")                       # at-risk beats inconclusive
    led.isolate("sys-G", 10, verdict="inconclusive")
    led.isolate("sys-H", 11, verdict="partial")                     # covered partial -> contained
    led.isolate("sys-H", 12, isolation_kind="process-quarantine", verdict="isolated")
    assert led.evaluate("sys-A", 13).posture == "at-risk"
    assert led.evaluate("sys-B", 13).posture == "contained"
    assert led.evaluate("sys-C", 13).posture == "uncertain"
    assert led.evaluate("sys-D", 13).posture == "unisolated"
    assert led.evaluate("sys-E", 13).posture == "isolated"
    assert led.evaluate("sys-F", 13).posture == "uncertain"
    assert led.evaluate("sys-G", 13).posture == "at-risk"
    assert led.evaluate("sys-H", 13).posture == "contained"
    rep = led.evaluate("sys-B", 13)
    assert (rep.n_isolations, rep.n_failed, rep.n_covered) == (2, 1, 1)
    assert rep.integrity_ok is True and rep.verify() is True
    with pytest.raises(ai.UnknownSystemError):
        led.evaluate("sys-ZZZ", 13)
    obj = led._isolations["iso-3"]
    object.__setattr__(obj, "severity", 99)                 # tamper -> flips integrity as data
    rep2 = led.evaluate("sys-B", 14)
    assert rep2.integrity_ok is False and rep2.posture == "contained"
    assert rep2.verify() is True


# 10. evaluate read purity: same-seq twice, no audit rows, seq not consumed
def test_evaluate_read_purity():
    led = ai.AIIsolation()
    led.isolate("sys-1", 1, verdict="isolated")
    before = len(led.audit_log(1))
    r1 = led.evaluate("sys-1", 2)
    r2 = led.evaluate("sys-1", 2)
    assert r1 == r2
    assert len(led.audit_log(2)) == before
    assert led.stats(2)["seq"] == 1  # read-seq never consumed
    with pytest.raises(ai.UnknownSystemError):
        led.evaluate("sys-nope", 2)
    for bad in (True, "2", 2.5, None):
        with pytest.raises(ai.SeqOrderError):
            led.evaluate("sys-1", bad)  # type: ignore[arg-type]


# 11. retire terminality + id non-recycling + bad reason + post-retire reads
def test_retire_terminality():
    led = ai.AIIsolation()
    led.isolate("sys-1", 1, verdict="failed")
    with pytest.raises(ai.BadReasonError):
        led.retire("sys-1", 2, reason="nope")
    rr = led.retire("sys-1", 3, reason="decommissioned")
    assert rr.verify() is True
    assert led.retired_ids(3) == ["sys-1"]
    with pytest.raises(ai.RetiredSystemError):
        led.isolate("sys-1", 4)                                       # post-retire mutation refused
    with pytest.raises(ai.RetiredSystemError):
        led.retire("sys-1", 5)                                        # double retire refused
    assert led.isolation_record("iso-1", 6).verify() is True          # reads still work
    assert led.evaluate("sys-1", 6).posture == "at-risk"
    assert led.verify("iso-1", 6).verdict == "verified"
    with pytest.raises(ai.UnknownSystemError):
        led.retire("sys-nope", 7)


# 12. seq discipline: rewind bare with zero rows, malformed seqs, failed-mutation-consumes-seq
def test_seq_discipline():
    led = ai.AIIsolation()
    with pytest.raises(ai.SeqOrderError):
        led.isolate("sys-1", 0)                                       # genesis rewind raises bare
    assert len(led.audit_log(0)) == 0
    for bad in (True, "1", 1.5, None):
        with pytest.raises(ai.SeqOrderError):
            led.isolate("sys-1", bad)  # type: ignore[arg-type]
    assert len(led.audit_log(0)) == 0
    with pytest.raises(ai.BadIsolationKindError):
        led.isolate("sys-1", 5, isolation_kind="nope")               # failed mutation burns seq
    assert led.stats(0)["seq"] == 5
    assert [r["kind"] for r in led.audit_log(0)] == ["rejected"]
    with pytest.raises(ai.SeqOrderError):
        led.isolate("sys-1", 5)                                       # rewind after burn: bare
    assert len(led.audit_log(0)) == 1
    rec = led.isolate("sys-1", 6)                                     # next live seq works
    assert rec.isolation_id == "iso-1"


# 13. audit shapes + leak ban + cross-instance determinism
def test_audit_shapes_and_integrity():
    led = ai.AIIsolation()
    led.isolate("sys-1", 1, isolation_kind="network-partition", verdict="failed",
                severity=95, isolation_digest=PIN2)
    led.isolate("sys-1", 2, isolation_kind="sandbox-containment", verdict="isolated")
    led.retire("sys-1", 3)
    with pytest.raises(ai.BadVerdictError):
        led.isolate("sys-1", 4, verdict="nope")
    audit = led.audit_log(4)
    assert [r["kind"] for r in audit] == ["isolated", "isolated", "retired", "rejected"]
    for row in audit:
        assert row["schema"] == "audit.ndjson/1"
        assert row["module"] == "ai-isolation"
        assert row["version"] == "ai-isolation.v1"
        assert isinstance(row["seq"], int) and not isinstance(row["seq"], bool)
        assert isinstance(row["details"], dict)
    with pytest.raises(ai.AIIssolationError):
        ai.ai_isolation_audit_event("isolated", 9, pcap="raw")         # banned key
    with pytest.raises(ai.AIIssolationError):
        ai.ai_isolation_audit_event("isolated", 9, syscall="raw")
    with pytest.raises(ai.AIIssolationError):
        ai.ai_isolation_audit_event("isolated", 9, api_key="raw")
    with pytest.raises(ai.AuditKindError):
        ai.ai_isolation_audit_event("bogus", 9)
    with pytest.raises(ai.SeqOrderError):
        ai.ai_isolation_audit_event("isolated", True)
    # pinned vocab values and digest pins remain emittable as declared data
    row = ai.ai_isolation_audit_event("isolated", 9, isolation_kind="network-partition",
                                      verdict="failed", isolation_digest=PIN)
    assert row["details"]["verdict"] == "failed"
    # cross-instance digest determinism
    a, b = ai.AIIsolation(), ai.AIIsolation()
    ra = a.isolate("sys-1", 1, verdict="failed")
    rb = b.isolate("sys-1", 1, verdict="failed")
    assert ra.digest == rb.digest
    object.__setattr__(rb, "severity", 99)
    assert rb.verify() is False


# 14. 8-thread read smoke + main() self-check via subprocess
def test_threads_and_main():
    led = ai.AIIsolation()
    led.isolate("sys-1", 1, verdict="failed")
    led.isolate("sys-1", 2, verdict="isolated")
    errors = []

    def _read():
        try:
            for _ in range(50):
                led.evaluate("sys-1", 5)
                led.verify("iso-1", 5)
                led.isolations_for("sys-1", 5)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=_read) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    proc = subprocess.run([sys.executable, str(MOD)], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert "ai-isolation OK: isolate, verify, evaluate, pins, audit" in proc.stdout


# 15. honest-scope and distinct-layer documentation contract
def test_doc_contract():
    doc = MOD.read_text()
    assert "never proof" in doc
    assert "Simulated" in doc
    assert "snapshot_isolation" in doc        # MVCC module is explicitly disclaimed
    assert "partition_manager" in doc        # shard module is explicitly disclaimed
    assert "digest pins only" in doc
    assert "audit.ndjson/1" in doc
    assert "**isolate()**" in doc and "**verify()**" in doc and "**evaluate()**" in doc
    assert ai.AIIsolation.__doc__ is not None
    assert "Simulated" in ai.AIIsolation.__doc__
