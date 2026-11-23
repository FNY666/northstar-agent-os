"""Tests for the ai-throttling throttling-operations decision ledger, Simulated."""

import ast
import dataclasses
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "ai_throttling.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("ai_throttling", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["ai_throttling"] = module
    spec.loader.exec_module(module)
    return module


sa = _load()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert sa.AI_THROTTLING_VERSION == "ai-throttling.v1"
    assert sa.SCHEMA_PIN == "northstar.ai-throttling.v1"
    assert sa.THROTTLE_KINDS == (
        "rate-limit",
        "token-bucket",
        "concurrency-limit",
        "compute-quota",
        "bandwidth-cap",
        "cooldown",
        "queue-depth",
        "burst-limit",
    )
    assert sa.READINESS == ("enforcing", "partial", "disabled", "degraded")
    assert sa.THROTTLE_REASONS == (
        "burst-protection",
        "abuse-mitigation",
        "cost-control",
        "fairness",
        "overload-protection",
        "policy-enforcement",
        "degradation",
        "manual",
    )
    assert sa.THROTTLE_OUTCOMES == (
        "throttled", "delayed", "denied", "allowed", "escalated", "not-engaged"
    )
    assert sa.VERIFY_VERDICTS == ("verified", "tampered")
    assert sa.POSTURES == ("open", "overloaded", "throttled", "contested", "guarded")
    assert sa.RETIRE_REASONS == ("manual", "superseded", "decommissioned", "false-start")
    assert sa.AUDIT_KINDS == ("declared", "throttled", "retired", "rejected")


# 2. stdlib-only AST check + stdlib_only()
def test_stdlib_only_ast():
    assert sa.stdlib_only() is True
    tree = ast.parse(MOD.read_text())
    allowed = {
        "hashlib", "json", "threading", "dataclasses", "typing",
        "__future__", "ast", "pathlib", "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                assert node.module.split(".")[0] in allowed


# 3. declare roundtrip + pol-N minting + verify() + frozen-ness
def test_declare_roundtrip():
    ledger = sa.AIThrottling()
    rec = ledger.declare(
        "sys-1", 1, throttle_kind="token-bucket", readiness="enforcing",
        declaration_digest=PIN,
    )
    assert rec.declaration_id == "pol-1"
    assert rec.system_id == "sys-1"
    assert rec.seq == 1
    assert rec.verify() is True
    rec2 = ledger.declare("sys-2", 2)
    assert rec2.declaration_id == "pol-2"
    assert rec2.throttle_kind == "rate-limit"
    assert rec2.readiness == "disabled"
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.readiness = "enforcing"  # type: ignore[misc]


# 4. declare bad-input table + seq-burn + rejected-row accounting + rewind bare
def test_declare_bad_inputs():
    ledger = sa.AIThrottling()
    bads = [
        ("", 1, "rate-limit", "enforcing", PIN),          # empty system id
        (123, 2, "rate-limit", "enforcing", PIN),         # non-string id
        ("sys-1", 3, "bogus-kind", "enforcing", PIN),     # bad throttle kind
        ("sys-1", 4, "rate-limit", "bogus", PIN),         # bad readiness
        ("sys-1", 5, "rate-limit", "enforcing", "nope"),  # bad digest
        ("sys-1", 6, "rate-limit", "enforcing", "sha256:" + "zz" * 32),  # bad hex
        (None, 7, "rate-limit", "enforcing", PIN),        # None id
        ("sys-1", 8, "rate-limit", True, PIN),            # bool readiness
    ]
    for system_id, seq, kind, readiness, digest in bads:
        with pytest.raises(sa.AIThrottlingError):
            ledger.declare(
                system_id, seq, throttle_kind=kind, readiness=readiness,
                declaration_digest=digest,
            )
    # claim-then-burn: each failed mutation consumed its seq
    assert ledger.stats(9)["seq"] == 8
    rejected = [r for r in ledger.audit_log(9) if r["kind"] == "rejected"]
    assert len(rejected) == 8
    # rewind raises bare: no seq consumption, no rejected row
    ledger.declare("sys-9", 9)
    n_before = len(ledger.audit_log(10))
    with pytest.raises(sa.SeqOrderError):
        ledger.declare("sys-9", 9)
    assert ledger.stats(10)["seq"] == 9
    assert len(ledger.audit_log(10)) == n_before


# 5. full 8-throttle-kind vocabulary
def test_all_throttle_kinds_accepted():
    ledger = sa.AIThrottling()
    seq = 0
    for i, kind in enumerate(sa.THROTTLE_KINDS):
        seq += 1
        rec = ledger.declare(f"sys-{i}", seq, throttle_kind=kind, readiness="partial")
        assert rec.throttle_kind == kind
        assert rec.verify() is True
    assert ledger.stats(seq + 1)["n_declarations"] == 8


# 6. throttle roundtrip + thr-N minting + frozen-ness
def test_throttle_roundtrip():
    ledger = sa.AIThrottling()
    ledger.declare("sys-1", 1)
    thr = ledger.throttle(
        "sys-1", 2, reason="abuse-mitigation", outcome="throttled",
        throttle_digest=PIN,
    )
    assert thr.throttle_id == "thr-1"
    assert thr.system_id == "sys-1"
    assert thr.reason == "abuse-mitigation"
    assert thr.outcome == "throttled"
    assert thr.verify() is True
    thr2 = ledger.throttle("sys-1", 3)
    assert thr2.throttle_id == "thr-2"
    assert thr2.reason == "burst-protection"
    assert thr2.outcome == "not-engaged"
    with pytest.raises(dataclasses.FrozenInstanceError):
        thr.outcome = "denied"  # type: ignore[misc]


# 7. throttle refusal table (unknown system/retired/bad reason/bad outcome/bad digest) + seq-burn
def test_throttle_refusals():
    ledger = sa.AIThrottling()
    ledger.declare("live", 1)
    ledger.declare("retire-me", 2)
    ledger.retire("retire-me", 3)
    bads = [
        ("ghost", 4, "burst-protection", "throttled", PIN),    # unknown system
        ("retire-me", 5, "burst-protection", "throttled", PIN),  # retired system
        ("live", 6, "bogus-reason", "throttled", PIN),        # bad reason
        ("live", 7, "burst-protection", "bogus", PIN),        # bad outcome
        ("live", 8, "burst-protection", "throttled", "nope"),  # bad digest
    ]
    for system_id, seq, reason, outcome, digest in bads:
        with pytest.raises(sa.AIThrottlingError):
            ledger.throttle(
                system_id, seq, reason=reason, outcome=outcome,
                throttle_digest=digest,
            )
    assert ledger.stats(9)["seq"] == 8
    rejected = [r for r in ledger.audit_log(9) if r["kind"] == "rejected"]
    assert len(rejected) == 5
    with pytest.raises(sa.UnknownSystemError):
        ledger.throttle("ghost", 9)
    with pytest.raises(sa.RetiredSystemError):
        ledger.throttle("retire-me", 10)


# 8. full 8-reason vocabulary + full 6-outcome vocabulary
def test_reason_and_outcome_vocabularies():
    ledger = sa.AIThrottling()
    ledger.declare("vocab-sys", 1)
    seq = 1
    for reason in sa.THROTTLE_REASONS:
        seq += 1
        thr = ledger.throttle("vocab-sys", seq, reason=reason, outcome="throttled")
        assert thr.reason == reason
        assert thr.verify() is True
    for outcome in sa.THROTTLE_OUTCOMES:
        seq += 1
        thr = ledger.throttle("vocab-sys", seq, reason="manual", outcome=outcome)
        assert thr.outcome == outcome
    assert ledger.stats(seq + 1)["n_throttles"] == 14


# 9. verify semantics: roundtrip + tamper-as-data + unknown refusal + read purity
def test_verify_semantics():
    ledger = sa.AIThrottling()
    pol = ledger.declare("sys-1", 1)
    thr = ledger.throttle("sys-1", 2, reason="manual", outcome="delayed")
    n_before = len(ledger.audit_log(3))
    rep = ledger.verify(thr.throttle_id, 3)
    assert rep.verdict == "verified"
    assert rep.integrity_ok is True
    assert rep.verify() is True
    rep2 = ledger.verify(pol.declaration_id, 3)  # same read seq twice
    assert rep2.verdict == "verified"
    assert len(ledger.audit_log(3)) == n_before  # reads emit no audit rows
    assert ledger.stats(3)["seq"] == 2  # reads consume no seq
    with pytest.raises(sa.UnknownRecordError):
        ledger.verify("thr-999", 3)
    # tamper is reported as data, never raised
    object.__setattr__(thr, "outcome", "denied")
    tampered = ledger.verify(thr.throttle_id, 4)
    assert tampered.verdict == "tampered"
    assert tampered.integrity_ok is False
    ev = ledger.evaluate("sys-1", 5)
    assert ev.integrity_ok is False


# 10. evaluate posture math: all postures + precedence + unknown refusal
def test_evaluate_posture_math():
    ledger = sa.AIThrottling()
    ledger.declare("s-open", 1)                            # no throttle engagements
    ledger.declare("s-overloaded", 2)
    ledger.throttle("s-overloaded", 3, outcome="throttled")
    ledger.throttle("s-overloaded", 4, outcome="escalated")  # escalated outranks
    ledger.declare("s-throttled", 5)
    ledger.throttle("s-throttled", 6, outcome="throttled")
    ledger.throttle("s-throttled", 7, outcome="denied")     # denied outranks delayed
    ledger.declare("s-contested", 8)
    ledger.throttle("s-contested", 9, outcome="delayed")
    ledger.declare("s-guarded", 10)
    ledger.throttle("s-guarded", 11, outcome="allowed")
    ledger.declare("s-idle", 12)
    ledger.throttle("s-idle", 13, outcome="not-engaged")    # never engaged
    assert ledger.evaluate("s-open", 14).posture == "open"
    ev = ledger.evaluate("s-overloaded", 14)
    assert ev.posture == "overloaded"
    assert ev.n_throttles == 2 and ev.n_escalated == 1 and ev.n_throttled == 1
    assert ledger.evaluate("s-throttled", 14).posture == "throttled"
    assert ledger.evaluate("s-contested", 14).posture == "contested"
    assert ledger.evaluate("s-guarded", 14).posture == "guarded"
    assert ledger.evaluate("s-idle", 14).posture == "open"
    with pytest.raises(sa.UnknownSystemError):
        ledger.evaluate("ghost", 14)


# 11. evaluate read purity + tamper flips integrity_ok
def test_evaluate_read_purity():
    ledger = sa.AIThrottling()
    ledger.declare("sys-1", 1)
    ledger.throttle("sys-1", 2, outcome="throttled")
    n_before = len(ledger.audit_log(3))
    ev1 = ledger.evaluate("sys-1", 3)
    ev2 = ledger.evaluate("sys-1", 3)  # same read seq twice
    assert ev1.posture == ev2.posture == "contested"
    assert ev1.integrity_ok is True
    assert len(ledger.audit_log(3)) == n_before
    assert ledger.stats(3)["seq"] == 2
    with pytest.raises(sa.SeqOrderError):
        ledger.evaluate("sys-1", -1)


# 12. retire terminality + id non-recycling + bad reason + post-retire reads
def test_retire_terminality():
    ledger = sa.AIThrottling()
    ledger.declare("sys-1", 1)
    ledger.throttle("sys-1", 2, outcome="throttled")
    ret = ledger.retire("sys-1", 3, reason="decommissioned")
    assert ret.verify() is True
    assert ledger.retired_ids(4) == ("sys-1",)
    with pytest.raises(sa.RetiredSystemError):
        ledger.declare("sys-1", 4)   # ids never recycled
    with pytest.raises(sa.RetiredSystemError):
        ledger.throttle("sys-1", 5)
    with pytest.raises(sa.RetiredSystemError):
        ledger.retire("sys-1", 6)    # double retire
    with pytest.raises(sa.BadRetireReasonError):
        ledger.retire("sys-1", 7, reason="bogus")
    with pytest.raises(sa.UnknownSystemError):
        ledger.retire("ghost", 8)
    # reads still work post-retire
    assert ledger.evaluate("sys-1", 9).posture == "contested"
    assert ledger.declaration_record("pol-1", 9).system_id == "sys-1"
    assert ledger.throttle_record("thr-1", 9).outcome == "throttled"
    with pytest.raises(sa.UnknownDeclarationError):
        ledger.declaration_record("pol-999", 9)
    with pytest.raises(sa.UnknownThrottleError):
        ledger.throttle_record("thr-999", 9)


# 13. seq discipline: malformed seqs + rewind bare + failed-mutation-consumes-seq
def test_seq_discipline():
    ledger = sa.AIThrottling()
    for bad_seq in (True, False, "1", 1.5, None):
        with pytest.raises(sa.SeqOrderError):
            ledger.declare("sys-1", bad_seq)
    assert ledger.stats(0)["seq"] == 0
    assert len(ledger.audit_log(0)) == 0  # malformed seqs burn nothing
    ledger.declare("sys-1", 1)
    with pytest.raises(sa.SeqOrderError):
        ledger.throttle("sys-1", 1)  # rewind raises bare
    assert ledger.stats(1)["seq"] == 1
    assert len(ledger.audit_log(1)) == 1  # only the declared row
    with pytest.raises(sa.BadReasonError):
        ledger.throttle("sys-1", 2, reason="bogus")
    assert ledger.stats(2)["seq"] == 2  # failed mutation consumed its seq


# 14. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    ledger = sa.AIThrottling()
    ledger.declare("sys-1", 1)
    ledger.throttle("sys-1", 2, reason="manual", outcome="throttled")
    rows = ledger.audit_log(3)
    assert [r["kind"] for r in rows] == ["declared", "throttled"]
    for row in rows:
        assert row["schema"] == "audit.ndjson/1"
        assert row["module"] == "ai-throttling"
        assert row["version"] == "ai-throttling.v1"
    declared = rows[0]["details"]
    assert declared["throttle_kind"] == "rate-limit"  # pinned vocab emittable
    # raw material keys may not cross the audit boundary
    with pytest.raises(sa.AIThrottlingError):
        sa.ai_throttling_audit_event("declared", 9, limit=1000)
    with pytest.raises(sa.AIThrottlingError):
        sa.ai_throttling_audit_event("throttled", 9, quota={"tokens": "1e9"})
    with pytest.raises(sa.AuditKindError):
        sa.ai_throttling_audit_event("bogus", 9)
    with pytest.raises(sa.SeqOrderError):
        sa.ai_throttling_audit_event("declared", "9")


# 15. cross-instance digest determinism + 8-thread read smoke + main() subprocess
def test_determinism_threads_and_main():
    def build():
        ledger = sa.AIThrottling()
        ledger.declare("sys-1", 1, throttle_kind="concurrency-limit", readiness="enforcing")
        ledger.throttle("sys-1", 2, reason="fairness", outcome="delayed")
        return ledger

    l1, l2 = build(), build()
    assert l1.declaration_record("pol-1", 0).digest == l2.declaration_record("pol-1", 0).digest
    assert l1.throttle_record("thr-1", 0).digest == l2.throttle_record("thr-1", 0).digest
    ledger = build()
    errors = []

    def read_smoke():
        try:
            for _ in range(50):
                ledger.evaluate("sys-1", 3)
                ledger.verify("thr-1", 3)
                ledger.throttles_for("sys-1", 3)
                ledger.stats(3)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=read_smoke) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    proc = subprocess.run(
        [sys.executable, str(MOD)], capture_output=True, text=True, timeout=60
    )
    assert proc.returncode == 0
    assert "ai-throttling OK: declare, throttle, verify, evaluate, retire, pins, audit" in proc.stdout
