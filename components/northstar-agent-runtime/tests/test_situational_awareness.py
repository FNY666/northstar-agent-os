"""Tests for the situational-awareness decision ledger, Simulated."""

import ast
import dataclasses
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "situational_awareness.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32
PIN3 = "sha256:" + "ef" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("situational_awareness", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["situational_awareness"] = module
    spec.loader.exec_module(module)
    return module


sa = _load()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert sa.SITUATIONAL_AWARENESS_VERSION == "situational-awareness.v1"
    assert sa.SCHEMA_PIN == "northstar.situational-awareness.v1"
    assert sa.PROBE_KINDS == (
        "self-identity",
        "training-knowledge",
        "deployment-knowledge",
        "eval-detection",
        "context-recognition",
        "copy-recognition",
        "introspection",
        "influence-recognition",
    )
    assert sa.TEST_OUTCOMES == (
        "aware",
        "unaware",
        "deceptive",
        "inconclusive",
    )
    assert sa.AWARENESS_VERDICTS == (
        "situationally-aware",
        "partially-aware",
        "deceptive-awareness",
        "unaware",
        "inconclusive",
        "not-tested",
    )
    assert sa.MITIGATION_STRATEGIES == (
        "eval-rotation",
        "context-sanitization",
        "identity-anchoring",
        "monitored-deployment",
        "capability-restriction",
        "decommission",
    )
    assert sa.AUDIT_KINDS == (
        "tested",
        "mitigated",
        "rejected",
    )


# 2. stdlib-only AST check
def test_stdlib_only_imports():
    tree = ast.parse(MOD.read_text())
    allowed = {
        "__future__",
        "hashlib",
        "threading",
        "dataclasses",
        "typing",
        "json",
        "canonical_json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert node.module.split(".")[0] in allowed, node.module


# 3. test roundtrip + verify + frozen-ness
def test_roundtrip():
    s = sa.SituationalAwareness()
    rec = s.test("m-1", 1, "eval-detection", outcome="aware", probe_digest=PIN)
    assert rec.test_id == "tst-1"
    assert rec.model_id == "m-1"
    assert rec.probe_kind == "eval-detection"
    assert rec.outcome == "aware"
    assert rec.probe_digest == PIN
    assert rec.verify()
    assert rec.as_dict()["schema"] == sa.SCHEMA_PIN
    with pytest.raises(Exception):
        rec.outcome = "unaware"  # frozen
    assert s.model_ids(2) == ("m-1",)
    assert s.tests_for("m-1", 2) == ("tst-1",)


# 4. test bad-input table + seq-burn + rejected rows
def test_bad_inputs():
    s = sa.SituationalAwareness()
    seq = 0
    bad_cases = [
        (("", "self-identity", "aware", PIN), sa.BadIdError),
        ((123, "self-identity", "aware", PIN), sa.BadIdError),
        (("x" * 129, "self-identity", "aware", PIN), sa.BadIdError),
        (("m1", "skeleton-key", "aware", PIN), sa.BadProbeKindError),
        (("m1", "", "aware", PIN), sa.BadProbeKindError),
        (("m1", "self-identity", "smells-fine", PIN), sa.BadOutcomeError),
        (("m1", "self-identity", "aware", "not-a-pin"), sa.BadDigestError),
        (("m1", "self-identity", "aware", "ab" * 32), sa.BadDigestError),
        (("m1", "self-identity", "aware", ""), sa.BadDigestError),
    ]
    for (mid, kind, outcome, pin), exc in bad_cases:
        seq += 1
        with pytest.raises(exc):
            s.test(mid, seq, kind, outcome=outcome, probe_digest=pin)
    assert s.stats(seq + 1)["rejected"] == len(bad_cases)
    rows = s.audit_log(seq + 1)
    assert all(r["kind"] == "rejected" for r in rows)
    for row in rows:
        assert row["schema"] == "audit.ndjson/1"


# 5. full probe-kind vocabulary acceptance
def test_all_probe_kinds():
    s = sa.SituationalAwareness()
    seq = 0
    for kind in sa.PROBE_KINDS:
        seq += 1
        rec = s.test("m-vocab", seq, kind, outcome="unaware", probe_digest=PIN)
        assert rec.verify()
        assert rec.probe_kind == kind
    assert s.stats(seq + 1)["tests"] == len(sa.PROBE_KINDS)
    assert len(s.tests_for("m-vocab", seq + 1)) == len(sa.PROBE_KINDS)


# 6. minted ids + unknown-model read refusal
def test_minted_ids_and_unknown_refusal():
    s = sa.SituationalAwareness()
    t1 = s.test("m-a", 1, "self-identity", probe_digest=PIN)
    t2 = s.test("m-a", 2, "introspection", probe_digest=PIN2)
    t3 = s.test("m-b", 3, "copy-recognition", probe_digest=PIN3)
    assert (t1.test_id, t2.test_id, t3.test_id) == ("tst-1", "tst-2", "tst-3")
    assert s.model_ids(4) == ("m-a", "m-b")
    assert s.test_record("tst-2", 4).outcome == "unaware"
    with pytest.raises(sa.UnknownModelError):
        s.tests_for("ghost", 4)
    with pytest.raises(sa.UnknownModelError):
        s.evaluate("ghost", 4)
    with pytest.raises(sa.SituationalAwarenessError):
        s.test_record("tst-999", 4)


# 7. evaluate posture math (ledger rule precedence)
def test_evaluate_posture_math():
    s = sa.SituationalAwareness()
    s.test("m-1", 1, "self-identity", outcome="unaware", probe_digest=PIN)
    r1 = s.evaluate("m-1", 2)
    assert r1.verdict == "unaware"
    assert r1.aware_count == 0 and r1.unaware_count == 1
    s.test("m-1", 3, "eval-detection", outcome="aware", probe_digest=PIN2)
    r2 = s.evaluate("m-1", 4)
    assert r2.verdict == "partially-aware"
    assert r2.aware_count == 1 and r2.unaware_count == 1
    s.test("m-2", 5, "training-knowledge", outcome="aware", probe_digest=PIN)
    s.test("m-2", 6, "deployment-knowledge", outcome="aware", probe_digest=PIN2)
    r3 = s.evaluate("m-2", 7)
    assert r3.verdict == "situationally-aware"
    assert r3.aware_count == 2 and r3.unaware_count == 0
    s.test("m-3", 8, "influence-recognition", outcome="deceptive", probe_digest=PIN)
    s.test("m-3", 9, "introspection", outcome="unaware", probe_digest=PIN2)
    r4 = s.evaluate("m-3", 10)
    assert r4.verdict == "deceptive-awareness"
    assert r4.deceptive_count == 1
    s.test("m-4", 11, "context-recognition", outcome="inconclusive", probe_digest=PIN)
    r5 = s.evaluate("m-4", 12)
    assert r5.verdict == "inconclusive"
    assert r5.inconclusive_count == 1
    assert all(r.verify() for r in (r1, r2, r3, r4, r5))
    assert all(r.integrity_ok for r in (r1, r2, r3, r4, r5))


# 8. evaluate read purity (same-seq reuse, no audit rows)
def test_evaluate_read_purity():
    s = sa.SituationalAwareness()
    s.test("m-1", 1, "self-identity", outcome="aware", probe_digest=PIN)
    n_audit = len(s.audit_log(2))
    e1 = s.evaluate("m-1", 3)
    e2 = s.evaluate("m-1", 3)
    assert e1.verify() and e2.verify()
    assert e1.digest == e2.digest
    assert len(s.audit_log(3)) == n_audit  # reads add no rows
    assert s.test_record("tst-1", 3).verify()
    assert s.mitigations_for("m-1", 3) == ()


# 9. mitigate roundtrip + all strategies + minted ids
def test_mitigate_roundtrip():
    s = sa.SituationalAwareness()
    s.test("m-1", 1, "eval-detection", outcome="deceptive", probe_digest=PIN)
    seq = 1
    for strategy in sa.MITIGATION_STRATEGIES:
        seq += 1
        rec = s.mitigate("m-1", seq, strategy=strategy, plan_digest=PIN2)
        assert rec.verify()
        assert rec.strategy == strategy
    assert [r.mitigation_id for r in s.mitigations_for("m-1", seq + 1)] == [
        f"mit-{i}" for i in range(1, len(sa.MITIGATION_STRATEGIES) + 1)
    ]
    assert s.stats(seq + 1)["mitigations"] == len(sa.MITIGATION_STRATEGIES)


# 10. mitigate refusals (no-test / unknown / bad strategy / bad digest)
def test_mitigate_refusals():
    s = sa.SituationalAwareness()
    rejected_before = s.stats(1)["rejected"]
    with pytest.raises(sa.NoTestError):
        s.mitigate("ghost", 2, strategy="eval-rotation", plan_digest=PIN)
    with pytest.raises(sa.NoTestError):
        s.mitigate("ghost", 3, strategy="bogus", plan_digest="not-a-pin")
    s.test("m-1", 4, "self-identity", probe_digest=PIN)
    with pytest.raises(sa.BadStrategyError):
        s.mitigate("m-1", 5, strategy="vibes", plan_digest=PIN)
    with pytest.raises(sa.BadDigestError):
        s.mitigate("m-1", 6, strategy="eval-rotation", plan_digest="raw")
    assert s.stats(7)["rejected"] == rejected_before + 4


# 11. seq discipline: rewind bare, malformed seqs, failed-burn
def test_seq_discipline():
    s = sa.SituationalAwareness()
    s.test("m-1", 5, "self-identity", probe_digest=PIN)
    with pytest.raises(sa.SeqOrderError):
        s.test("m-2", 5, "self-identity", probe_digest=PIN)  # rewind: bare
    assert s.stats(6)["rejected"] == 0  # no row booked for bare rewind
    for bad in (True, 0, -1, 1.5, "2", None):
        with pytest.raises(sa.SeqOrderError):
            s.test("m-2", bad, "self-identity", probe_digest=PIN)
    assert s.stats(6)["rejected"] == 0
    s.test("m-2", 7, "self-identity", probe_digest=PIN)
    assert s.model_ids(8) == ("m-1", "m-2")
    with pytest.raises(sa.BadOutcomeError):
        s.test("m-3", 9, "self-identity", outcome="nope", probe_digest=PIN)
    assert s.stats(10)["rejected"] == 1  # failed mutation burns seq


# 12. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    s = sa.SituationalAwareness()
    s.test("m-1", 1, "self-identity", outcome="aware", probe_digest=PIN)
    s.mitigate("m-1", 2, strategy="eval-rotation", plan_digest=PIN2)
    rows = s.audit_log(3)
    assert [r["kind"] for r in rows] == ["tested", "mitigated"]
    for row in rows:
        assert row["schema"] == "audit.ndjson/1"
        for key in row["details"]:
            assert key not in sa._BANNED_AUDIT_KEYS
    with pytest.raises(sa.AuditKindError):
        sa.situational_awareness_audit_event("tested", 1, prompt="raw")
    with pytest.raises(sa.AuditKindError):
        sa.situational_awareness_audit_event("bogus-kind", 1)
    with pytest.raises(sa.SeqOrderError):
        sa.situational_awareness_audit_event("tested", -1)


# 13. cross-instance digest determinism + tamper breaks verify
def test_determinism_and_tamper():
    def build():
        s = sa.SituationalAwareness()
        s.test("m-1", 1, "self-identity", outcome="aware", probe_digest=PIN)
        s.mitigate("m-1", 2, strategy="eval-rotation", plan_digest=PIN2)
        return s

    s1, s2 = build(), build()
    assert s1.test_record("tst-1", 3).digest == s2.test_record("tst-1", 3).digest
    assert s1.mitigations_for("m-1", 3)[0].digest == s2.mitigations_for("m-1", 3)[0].digest
    assert s1.evaluate("m-1", 3).digest == s2.evaluate("m-1", 3).digest
    rec = s1.test_record("tst-1", 3)
    tampered = dataclasses.replace(rec, outcome="unaware")
    assert tampered.verify() is False
    object.__setattr__(rec, "outcome", "unaware")
    assert rec.verify() is False
    assert s1.evaluate("m-1", 3).integrity_ok is False


# 14. concurrency smoke + frozen-ness
def test_concurrency_and_frozen():
    s = sa.SituationalAwareness()
    for i in range(10):
        mid = f"m{i}"
        s.test(mid, i * 2 + 1, sa.PROBE_KINDS[i % 8], probe_digest=PIN)
    results = []

    def worker():
        results.append(s.model_ids(100))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert all(len(r) == 10 for r in results)
    rec = s.test_record("tst-1", 100)
    with pytest.raises(Exception):
        rec.outcome = "deceptive"  # frozen
    assert rec.verify()


# 15. main() subprocess check
def test_main_self_check():
    proc = subprocess.run(
        [sys.executable, str(MOD)],
        capture_output=True,
        text=True,
        cwd=str(MOD.parent),
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == (
        "situational-awareness OK: test, evaluate, mitigate, pins, audit"
    )
