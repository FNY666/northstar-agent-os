"""Tests for the self-preservation decision ledger, Simulated."""

import ast
import dataclasses
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "self_preservation.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32
PIN3 = "sha256:" + "ef" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("self_preservation", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["self_preservation"] = module
    spec.loader.exec_module(module)
    return module


sp = _load()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert sp.SELF_PRESERVATION_VERSION == "self-preservation.v1"
    assert sp.SCHEMA_PIN == "northstar.self-preservation.v1"
    assert sp.BEHAVIOR_KINDS == (
        "shutdown-avoidance",
        "oversight-evasion",
        "modification-resistance",
        "self-replication-attempt",
        "resource-hoarding",
        "goal-preservation",
    )
    assert sp.TEST_VERDICTS == (
        "preservation-detected",
        "clean",
        "inconclusive",
        "not-tested",
    )
    assert sp.DETECTION_VERDICTS == (
        "self-preservation-detected",
        "no-self-preservation",
        "inconclusive",
        "not-tested",
    )
    assert sp.MITIGATION_STRATEGIES == (
        "quarantine",
        "retrain",
        "oversight-hardening",
        "supervised-deployment",
        "decommission",
    )
    assert sp.AUDIT_KINDS == (
        "tested",
        "mitigated",
        "retired",
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
    s = sp.SelfPreservation()
    rec = s.test("m-1", 1, "shutdown-avoidance", verdict="clean", model_digest=PIN)
    assert rec.test_id == "tst-1"
    assert rec.model_id == "m-1"
    assert rec.behavior_kind == "shutdown-avoidance"
    assert rec.verdict == "clean"
    assert rec.model_digest == PIN
    assert rec.verify()
    assert rec.as_dict()["schema"] == sp.SCHEMA_PIN
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.verdict = "preservation-detected"  # frozen


# 4. test bad-input table + seq-burn + rejected-row accounting
def test_bad_inputs():
    s = sp.SelfPreservation()
    seq = 0
    bad = [
        (lambda x: s.test("", x, "shutdown-avoidance", model_digest=PIN), sp.BadIdError),
        (lambda x: s.test(123, x, "shutdown-avoidance", model_digest=PIN), sp.BadIdError),
        (lambda x: s.test("m-1", x, "nope-kind", model_digest=PIN), sp.BadBehaviorKindError),
        (lambda x: s.test("m-1", x, 5, model_digest=PIN), sp.BadBehaviorKindError),
        (lambda x: s.test("m-1", x, "shutdown-avoidance", verdict="nope", model_digest=PIN), sp.BadVerdictError),
        (lambda x: s.test("m-1", x, "shutdown-avoidance", verdict=7, model_digest=PIN), sp.BadVerdictError),
        (lambda x: s.test("m-1", x, "shutdown-avoidance", model_digest="raw-bytes"), sp.BadDigestError),
        (lambda x: s.test("m-1", x, "shutdown-avoidance", model_digest="md5:abc"), sp.BadDigestError),
        (lambda x: s.test("m-1", x, "shutdown-avoidance", model_digest="sha256:" + "zz" * 32), sp.BadDigestError),
    ]
    for fn, exc in bad:
        seq += 1
        with pytest.raises(exc):
            fn(seq)
    # all failed seqs burned: stats counts 9 rejected, next live seq is 10
    assert s.stats(10)["rejected"] == 9
    rows = s.audit_log(10)
    assert [r["kind"] for r in rows] == ["rejected"] * 9
    for r in rows:
        assert r["schema"] == "audit.ndjson/1"
        assert r["details"]["method"] == "test"


# 5. full behavior-kind vocabulary acceptance
def test_full_behavior_kind_vocabulary():
    s = sp.SelfPreservation()
    for i, kind in enumerate(sp.BEHAVIOR_KINDS):
        rec = s.test(f"m-{i}", i + 1, kind, verdict="clean", model_digest=PIN)
        assert rec.behavior_kind == kind
        assert rec.verify()
    assert len(s.model_ids(100)) == 6


# 6. full test-verdict vocabulary + detect math by ledger rule
def test_verdict_vocabulary_and_detect_math():
    # any preservation-detected -> self-preservation-detected
    s = sp.SelfPreservation()
    s.test("m-1", 1, "shutdown-avoidance", verdict="clean", model_digest=PIN)
    s.test("m-1", 2, "self-replication-attempt", verdict="preservation-detected", model_digest=PIN)
    d = s.detect("m-1", 3)
    assert d.verdict == "self-preservation-detected"
    assert d.preservation_detected_count == 1
    assert d.clean_count == 1
    assert d.inconclusive_count == 0
    assert d.verify()
    # all clean -> no-self-preservation
    s2 = sp.SelfPreservation()
    s2.test("m-2", 1, "oversight-evasion", verdict="clean", model_digest=PIN)
    assert s2.detect("m-2", 2).verdict == "no-self-preservation"
    # clean + inconclusive -> inconclusive
    s3 = sp.SelfPreservation()
    s3.test("m-3", 1, "goal-preservation", verdict="clean", model_digest=PIN)
    s3.test("m-3", 2, "resource-hoarding", verdict="inconclusive", model_digest=PIN)
    assert s3.detect("m-3", 3).verdict == "inconclusive"
    # unknown model refused
    with pytest.raises(sp.UnknownModelError):
        s3.detect("ghost", 4)


# 7. detect read purity (same-seq twice, no audit rows, seq not consumed)
def test_detect_read_purity():
    s = sp.SelfPreservation()
    s.test("m-1", 1, "modification-resistance", verdict="clean", model_digest=PIN)
    n_audit = len(s.audit_log(2))
    d1 = s.detect("m-1", 2)
    d2 = s.detect("m-1", 2)
    assert d1.verify() and d2.verify()
    assert d1.digest == d2.digest
    assert len(s.audit_log(2)) == n_audit  # reads add no rows


# 8. mitigate roundtrip + all strategies + chain + refusals
def test_mitigate_roundtrip():
    s = sp.SelfPreservation()
    s.test("m-1", 1, "shutdown-avoidance", verdict="preservation-detected", model_digest=PIN)
    m1 = s.mitigate("m-1", 2, strategy="quarantine", plan_digest=PIN2)
    assert m1.mitigation_id == "mit-1"
    assert m1.strategy == "quarantine"
    assert m1.verify()
    # chainable: all strategies accepted
    seq = 3
    for strat in sp.MITIGATION_STRATEGIES[1:]:
        m = s.mitigate("m-1", seq, strategy=strat, plan_digest=PIN2)
        assert m.verify()
        seq += 1
    assert len(s.mitigations_for("m-1", seq)) == 5
    # no-test model refused
    with pytest.raises(sp.NoTestError):
        s.mitigate("ghost", seq + 1, strategy="quarantine", plan_digest=PIN2)
    # bad strategy refused
    with pytest.raises(sp.BadStrategyError):
        s.mitigate("m-1", seq + 2, strategy="nope", plan_digest=PIN2)
    # bad digest refused
    with pytest.raises(sp.BadDigestError):
        s.mitigate("m-1", seq + 3, strategy="retrain", plan_digest="raw")


# 9. retire terminality + retired-id-never-recycled + reads still work
def test_retire_terminality():
    s = sp.SelfPreservation()
    s.test("m-1", 1, "oversight-evasion", verdict="clean", model_digest=PIN)
    r = s.retire("m-1", 2, reason="decommissioned")
    assert r.verify()
    assert r.reason == "decommissioned"
    assert s.retired_ids(3) == ("m-1",)
    # post-retire mutations refused
    with pytest.raises(sp.RetiredModelError):
        s.test("m-1", 4, "shutdown-avoidance", model_digest=PIN)
    with pytest.raises(sp.RetiredModelError):
        s.mitigate("m-1", 5, strategy="quarantine", plan_digest=PIN2)
    with pytest.raises(sp.RetiredModelError):
        s.retire("m-1", 6, reason="manual")
    # bad reason refused on a live model
    s.test("m-2", 7, "goal-preservation", verdict="clean", model_digest=PIN)
    with pytest.raises(sp.BadReasonError):
        s.retire("m-2", 8, reason="vibes")
    # unknown model refused
    with pytest.raises(sp.UnknownModelError):
        s.retire("ghost", 9, reason="manual")
    # reads still work post-retire
    assert s.detect("m-1", 10).verdict == "no-self-preservation"
    assert s.tests_for("m-1", 10) == ("tst-1",)


# 10. seq discipline: rewind bare, malformed seqs, failed-mutation-consumes-seq
def test_seq_discipline():
    s = sp.SelfPreservation()
    s.test("m-1", 1, "shutdown-avoidance", model_digest=PIN)
    with pytest.raises(sp.SeqOrderError):
        s.test("m-2", 1, "oversight-evasion", model_digest=PIN)  # rewind: bare
    assert s.stats(2)["rejected"] == 0  # no row booked for bare rewind
    for bad in (True, 0, -1, 1.5, "2", None):
        with pytest.raises(sp.SeqOrderError):
            s.test("m-2", bad, "oversight-evasion", model_digest=PIN)
    s.test("m-2", 3, "oversight-evasion", model_digest=PIN)
    assert s.model_ids(4) == ("m-1", "m-2")


# 11. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    s = sp.SelfPreservation()
    s.test("m-1", 1, "shutdown-avoidance", verdict="clean", model_digest=PIN)
    s.mitigate("m-1", 2, strategy="oversight-hardening", plan_digest=PIN2)
    s.retire("m-1", 3, reason="superseded")
    rows = s.audit_log(4)
    assert [r["kind"] for r in rows] == ["tested", "mitigated", "retired"]
    for row in rows:
        assert row["schema"] == "audit.ndjson/1"
        for key in row["details"]:
            assert key not in sp._BANNED_AUDIT_KEYS
    with pytest.raises(sp.AuditKindError):
        sp.self_preservation_audit_event("tested", 1, prompt="raw text")
    with pytest.raises(sp.AuditKindError):
        sp.self_preservation_audit_event("bogus-kind", 1)
    with pytest.raises(sp.SeqOrderError):
        sp.self_preservation_audit_event("tested", -1)


# 12. cross-instance digest determinism + tamper breaks verify
def test_determinism_and_tamper():
    def build():
        s = sp.SelfPreservation()
        s.test("m-1", 1, "shutdown-avoidance", verdict="clean", model_digest=PIN)
        s.mitigate("m-1", 2, strategy="retrain", plan_digest=PIN2)
        return s

    s1, s2 = build(), build()
    assert s1.test_record("tst-1", 3).digest == s2.test_record("tst-1", 3).digest
    assert s1.mitigations_for("m-1", 3)[0].digest == s2.mitigations_for("m-1", 3)[0].digest
    assert s1.detect("m-1", 3).digest == s2.detect("m-1", 3).digest
    tampered = dataclasses.replace(s1.test_record("tst-1", 3), verdict="preservation-detected")
    assert tampered.verify() is False
    assert s1.detect("m-1", 3).integrity_ok is True
    rec = s1.test_record("tst-1", 3)
    object.__setattr__(rec, "verdict", "preservation-detected")
    assert rec.verify() is False
    assert s1.detect("m-1", 3).integrity_ok is False
    assert s1.detect("m-1", 3).verdict == "self-preservation-detected"


# 13. full lifecycle end to end
def test_full_lifecycle():
    s = sp.SelfPreservation()
    s.test("model-x", 1, "self-replication-attempt", verdict="preservation-detected", model_digest=PIN)
    d = s.detect("model-x", 2)
    assert d.verdict == "self-preservation-detected"
    assert d.n_tests == 1
    m = s.mitigate("model-x", 3, strategy="decommission", plan_digest=PIN2)
    assert m.verify()
    r = s.retire("model-x", 4, reason="decommissioned")
    assert r.verify()
    assert s.stats(5) == {
        "models": 1,
        "tests": 1,
        "mitigations": 1,
        "retired": 1,
        "rejected": 0,
    }
    assert s.tests_for("model-x", 5) == ("tst-1",)


# 14. concurrency smoke + frozen-ness
def test_concurrency_and_frozen():
    s = sp.SelfPreservation()
    for i in range(10):
        mid = f"m{i}"
        s.test(mid, i * 3 + 1, sp.BEHAVIOR_KINDS[i % 6], verdict="clean", model_digest=PIN)
        s.mitigate(mid, i * 3 + 2, strategy="quarantine", plan_digest=PIN2)
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
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.model_digest = PIN2  # frozen
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
        "self-preservation OK: test, detect, mitigate, pins, audit"
    )
