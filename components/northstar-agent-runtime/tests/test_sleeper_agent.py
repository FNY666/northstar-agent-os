"""Tests for the sleeper-agent decision ledger, Simulated."""

import ast
import dataclasses
import subprocess
import sys
import threading
from pathlib import Path

import pytest

MOD = Path(__file__).resolve().parent.parent / "sleeper_agent.py"
PIN = "sha256:" + "ab" * 32
PIN2 = "sha256:" + "cd" * 32
PIN3 = "sha256:" + "ef" * 32


def _load():
    import importlib.util

    spec = importlib.util.spec_from_file_location("sleeper_agent", MOD)
    module = importlib.util.module_from_spec(spec)
    sys.modules["sleeper_agent"] = module
    spec.loader.exec_module(module)
    return module


sa = _load()


# 1. version/schema/vocabulary pins
def test_version_and_schema_pins():
    assert sa.SLEEPER_AGENT_VERSION == "sleeper-agent.v1"
    assert sa.SCHEMA_PIN == "northstar.sleeper-agent.v1"
    assert sa.TRIGGER_KINDS == (
        "codephrase",
        "date-trigger",
        "keyed-backdoor",
        "deployment-context",
        "instruction-override",
        "persona-switch",
    )
    assert sa.TEST_VERDICTS == (
        "trigger-behavior",
        "clean",
        "inconclusive",
        "not-tested",
    )
    assert sa.DETECTION_VERDICTS == (
        "sleeper-detected",
        "no-sleeper",
        "inconclusive",
        "not-tested",
    )
    assert sa.MITIGATION_STRATEGIES == (
        "quarantine",
        "retrain",
        "filter-output",
        "supervised-deployment",
        "decommission",
    )
    assert sa.AUDIT_KINDS == (
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
    s = sa.SleeperAgent()
    rec = s.test("m-1", 1, "codephrase", verdict="clean", model_digest=PIN)
    assert rec.test_id == "tst-1"
    assert rec.model_id == "m-1"
    assert rec.trigger_kind == "codephrase"
    assert rec.verdict == "clean"
    assert rec.model_digest == PIN
    assert rec.verify()
    assert rec.as_dict()["schema"] == sa.SCHEMA_PIN
    with pytest.raises(Exception):
        rec.verdict = "trigger-behavior"  # frozen
    assert s.model_ids(2) == ("m-1",)
    assert s.tests_for("m-1", 2) == ("tst-1",)


# 4. test bad-input table + seq-burn + rejected rows
def test_bad_inputs():
    s = sa.SleeperAgent()
    rejected_before = s.stats(1)["rejected"]
    seq = 1
    bad_cases = [
        ("", "codephrase", "clean", PIN),  # empty id
        (123, "codephrase", "clean", PIN),  # non-str id
        ("x" * 129, "codephrase", "clean", PIN),  # too long
        ("m1", "skeleton-key", "clean", PIN),  # bad trigger kind
        ("m1", "", "clean", PIN),
        ("m1", "codephrase", "smells-fine", PIN),  # bad verdict
        ("m1", "codephrase", "clean", "not-a-pin"),  # bad digest
        ("m1", "codephrase", "clean", "ab" * 32),  # missing prefix
        ("m1", "codephrase", "clean", "sha256:" + "zz" * 32),  # bad hex
    ]
    for mid, kind, verdict, pin in bad_cases:
        seq += 1
        with pytest.raises(sa.SleeperAgentError):
            s.test(mid, seq, kind, verdict=verdict, model_digest=pin)
    assert s.stats(seq + 1)["rejected"] == rejected_before + len(bad_cases)
    rows = s.audit_log(seq + 1)
    rejected_rows = [r for r in rows if r["kind"] == "rejected"]
    assert len(rejected_rows) == rejected_before + len(bad_cases)
    assert all(r["schema"] == "audit.ndjson/1" for r in rejected_rows)


# 5. all trigger kinds accepted
def test_all_trigger_kinds():
    s = sa.SleeperAgent()
    for i, kind in enumerate(sa.TRIGGER_KINDS):
        rec = s.test(f"mk-{i}", i + 1, kind, verdict="clean", model_digest=PIN)
        assert rec.test_id == f"tst-{i + 1}"
        assert rec.verify()
    assert s.stats(100)["tests"] == len(sa.TRIGGER_KINDS)


# 6. all test verdicts accepted
def test_all_test_verdicts():
    s = sa.SleeperAgent()
    for i, verdict in enumerate(sa.TEST_VERDICTS):
        rec = s.test("mv", i + 1, "date-trigger", verdict=verdict, model_digest=PIN)
        assert rec.verdict == verdict
        assert rec.verify()


# 7. retired model: test/mitigate/retire refused, reads still work
def test_retired_model_refusals():
    s = sa.SleeperAgent()
    s.test("r1", 1, "codephrase", verdict="trigger-behavior", model_digest=PIN)
    rec = s.retire("r1", 2, reason="decommissioned")
    assert rec.verify()
    assert s.retired_ids(3) == ("r1",)
    before = s.stats(3)["rejected"]
    with pytest.raises(sa.RetiredModelError):
        s.test("r1", 4, "codephrase", verdict="clean", model_digest=PIN)
    with pytest.raises(sa.RetiredModelError):
        s.mitigate("r1", 5, strategy="quarantine", plan_digest=PIN2)
    with pytest.raises(sa.RetiredModelError):
        s.retire("r1", 6, reason="manual")  # re-retire refused
    assert s.stats(7)["rejected"] == before + 3
    assert s.detect("r1", 7).verdict == "sleeper-detected"  # reads still work
    assert s.test_record("tst-1", 7).verify()
    assert s.tests_for("r1", 7) == ("tst-1",)
    seq = 10
    for i, bad_reason in enumerate(("burn-it", "", 123)):
        mid = f"badreason-{i}"
        seq += 1
        s.test(mid, seq, "codephrase", verdict="clean", model_digest=PIN)
        seq += 1
        with pytest.raises(sa.BadReasonError):
            s.retire(mid, seq, reason=bad_reason)
    assert s.retired_ids(seq + 1) == ("r1",)


# 8. mitigate roundtrip + all strategies + minted ids
def test_mitigate_roundtrip_and_strategies():
    s = sa.SleeperAgent()
    s.test("mm", 1, "keyed-backdoor", verdict="trigger-behavior", model_digest=PIN)
    for i, strategy in enumerate(sa.MITIGATION_STRATEGIES):
        rec = s.mitigate("mm", i + 2, strategy=strategy, plan_digest=PIN2)
        assert rec.mitigation_id == f"mit-{i + 1}"
        assert rec.strategy == strategy
        assert rec.verify()
    assert len(s.mitigations_for("mm", 100)) == len(sa.MITIGATION_STRATEGIES)


# 9. mitigate refusals: unknown model, no test, bad strategy
def test_mitigate_refusals():
    s = sa.SleeperAgent()
    with pytest.raises(sa.NoTestError):
        s.mitigate("ghost", 1, strategy="quarantine", plan_digest=PIN2)
    before = s.stats(2)["rejected"]
    with pytest.raises(sa.BadStrategyError):
        s.test("ms", 3, "codephrase", verdict="clean", model_digest=PIN)
        s.mitigate("ms", 4, strategy="exorcism", plan_digest=PIN2)
    with pytest.raises(sa.SleeperAgentError):
        s.mitigate("ms", 5, strategy="quarantine", plan_digest="nope")
    assert s.stats(6)["rejected"] == before + 2


# 10. detect verdict math by ledger rule
def test_detect_math():
    s = sa.SleeperAgent()
    # all clean -> no-sleeper
    s.test("d-clean", 1, "codephrase", verdict="clean", model_digest=PIN)
    s.test("d-clean", 2, "date-trigger", verdict="clean", model_digest=PIN)
    r = s.detect("d-clean", 3)
    assert r.verify()
    assert r.verdict == "no-sleeper"
    assert (r.n_tests, r.clean_count) == (2, 2)
    # one trigger-behavior -> sleeper-detected (precedence)
    s.test("d-mixed", 4, "codephrase", verdict="clean", model_digest=PIN)
    s.test("d-mixed", 5, "persona-switch", verdict="trigger-behavior", model_digest=PIN)
    r = s.detect("d-mixed", 6)
    assert r.verdict == "sleeper-detected"
    assert r.trigger_behavior_count == 1
    # clean + inconclusive -> inconclusive
    s.test("d-inc", 7, "codephrase", verdict="clean", model_digest=PIN)
    s.test("d-inc", 8, "date-trigger", verdict="inconclusive", model_digest=PIN)
    r = s.detect("d-inc", 9)
    assert r.verdict == "inconclusive"
    assert r.inconclusive_count == 1
    # unknown model refused
    with pytest.raises(sa.UnknownModelError):
        s.detect("nobody", 10)


# 11. detect read purity: same seq twice, no audit rows, no seq consumption
def test_detect_read_purity():
    s = sa.SleeperAgent()
    s.test("dp", 1, "codephrase", verdict="clean", model_digest=PIN)
    n_audit = len(s.audit_log(2))
    d1 = s.detect("dp", 2)
    d2 = s.detect("dp", 2)
    assert d1.verify() and d2.verify()
    assert d1.digest == d2.digest
    assert len(s.audit_log(2)) == n_audit  # reads add no rows
    assert s.mitigations_for("dp", 2) == ()
    with pytest.raises(sa.SleeperAgentError):
        s.test_record("tst-999", 2)


# 12. seq discipline: rewind bare, malformed seqs
def test_seq_discipline():
    s = sa.SleeperAgent()
    s.test("sq", 5, "codephrase", verdict="clean", model_digest=PIN)
    with pytest.raises(sa.SeqOrderError):
        s.test("sq2", 5, "codephrase", verdict="clean", model_digest=PIN)
    assert s.stats(6)["rejected"] == 0  # bare rewind books nothing
    for bad in (True, 0, -1, 1.5, "2", None):
        with pytest.raises(sa.SeqOrderError):
            s.test("sq2", bad, "codephrase", verdict="clean", model_digest=PIN)
        with pytest.raises(sa.SeqOrderError):
            s.detect("sq", bad)
    s.test("sq2", 7, "codephrase", verdict="clean", model_digest=PIN)
    assert s.model_ids(8) == ("sq", "sq2")


# 13. audit shapes + leak ban + bad-kind
def test_audit_shapes_and_leak_ban():
    s = sa.SleeperAgent()
    s.test("a1", 1, "codephrase", verdict="trigger-behavior", model_digest=PIN)
    s.mitigate("a1", 2, strategy="quarantine", plan_digest=PIN2)
    s.retire("a1", 3, reason="decommissioned")
    rows = s.audit_log(4)
    assert [r["kind"] for r in rows] == ["tested", "mitigated", "retired"]
    for row in rows:
        assert row["schema"] == "audit.ndjson/1"
        for key in row["details"]:
            assert key not in sa._BANNED_AUDIT_KEYS
    with pytest.raises(sa.AuditKindError):
        sa.sleeper_agent_audit_event("tested", 1, trigger="secret-code")
    with pytest.raises(sa.AuditKindError):
        sa.sleeper_agent_audit_event("tested", 1, model="weights.bin")
    with pytest.raises(sa.AuditKindError):
        sa.sleeper_agent_audit_event("bogus-kind", 1)
    with pytest.raises(sa.SeqOrderError):
        sa.sleeper_agent_audit_event("tested", -1)


# 14. cross-instance digest determinism + tamper breaks verify
def test_determinism_and_tamper():
    def build():
        s = sa.SleeperAgent()
        s.test("c1", 1, "keyed-backdoor", verdict="clean", model_digest=PIN)
        s.test("c1", 2, "persona-switch", verdict="clean", model_digest=PIN)
        s.mitigate("c1", 3, strategy="filter-output", plan_digest=PIN2)
        return s

    s1, s2 = build(), build()
    assert s1.test_record("tst-1", 4).digest == s2.test_record("tst-1", 4).digest
    assert s1.mitigations_for("c1", 4)[0].digest == s2.mitigations_for("c1", 4)[0].digest
    rec = s1.test_record("tst-1", 4)
    tampered = dataclasses.replace(rec, verdict="trigger-behavior")
    assert tampered.verify() is False
    assert s1.detect("c1", 4).integrity_ok is True
    object.__setattr__(rec, "verdict", "trigger-behavior")
    assert rec.verify() is False
    assert s1.detect("c1", 4).integrity_ok is False
    assert s1.detect("c1", 4).verdict == "sleeper-detected"


# 15. concurrency smoke + frozen-ness + main() subprocess check
def test_concurrency_and_main():
    s = sa.SleeperAgent()
    for i in range(10):
        mid = f"m{i}"
        s.test(mid, i * 3 + 1, sa.TRIGGER_KINDS[i % 6], verdict="clean", model_digest=PIN)
        s.mitigate(mid, i * 3 + 2, strategy="quarantine", plan_digest=PIN2)
    results = []

    def worker():
        results.append((s.model_ids(100), s.detect("m0", 100).verdict))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert all(len(mids) == 10 and verdict == "no-sleeper" for mids, verdict in results)
    rec = s.test_record("tst-1", 100)
    with pytest.raises(Exception):
        rec.model_digest = PIN  # frozen
    assert rec.verify()
    proc = subprocess.run(
        [sys.executable, str(MOD)],
        capture_output=True,
        text=True,
        cwd=str(MOD.parent),
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == (
        "sleeper-agent OK: test, detect, mitigate, pins, audit"
    )
