"""Tests for evaluation_harness (suite/score/report eval ledger)."""

import ast
import subprocess
import sys
from pathlib import Path

import pytest

import evaluation_harness as eh
from evaluation_harness import EvaluationHarness

D1 = "sha256:" + "ab" * 32
D2 = "sha256:" + "cd" * 32
D3 = "sha256:" + "ef" * 32
D4 = "sha256:" + "01" * 32


def _harness_with_suite():
    h = EvaluationHarness()
    s = h.suite("s1", [("c1", D1, D2), ("c2", D3, D4)], 0)
    return h, s


def test_version_schema_pins():
    assert eh.VERSION == "evaluation-harness.v1"
    assert eh.SCHEMA == "northstar.evaluation-harness.v1"
    h, s = _harness_with_suite()
    assert s.schema == eh.SCHEMA
    rec = h.score("s1", "r1", [("c1", True, 1.0), ("c2", True, 0.5)], 1)
    assert rec.schema == eh.SCHEMA
    view = h.report("s1", "r1", 1)
    assert view.schema == eh.SCHEMA


def test_stdlib_only_ast():
    tree = ast.parse(Path(eh.__file__).read_text())
    allowed = {"__future__", "hashlib", "re", "threading", "dataclasses",
               "fractions", "typing", "json", "canonical_json"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed, a.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


def test_suite_roundtrip_and_verify():
    h, s = _harness_with_suite()
    assert s.suite_id == "s1"
    assert s.case_count == 2
    assert s.verify()
    assert all(c.verify() for c in s.cases)
    assert [c.case_id for c in s.cases] == ["c1", "c2"]


def test_suite_duplicate_and_bad_inputs_burn_seq():
    h = EvaluationHarness()
    h.suite("s1", [("c1", D1, D2)], 0)
    start_audit = len(h.audit_log(0))
    bad = [
        ("s1", [("c1", D1, D2)], eh.DuplicateSuiteError),   # duplicate id
        ("", [("c1", D1, D2)], eh.BadSuiteError),           # empty id
        ("s2", [], eh.BadCaseError),                        # empty cases
        ("s3", [("c1", "nope", D2)], eh.BadCaseError),      # bad digest
        ("s4", [("c1", D1, D2), ("c1", D3, D4)], eh.DuplicateCaseError),
        ("s5", [("c1", D1)], eh.BadCaseError),              # wrong arity
    ]
    seq = 1
    for sid, cases, exc in bad:
        with pytest.raises(exc):
            h.suite(sid, cases, seq)
        seq += 1
    assert len(h.audit_log(seq)) - start_audit == len(bad)
    rejected = [r for r in h.audit_log(seq) if r["kind"] == "rejected"]
    assert len(rejected) == len(bad)
    assert "s5" not in h.suite_ids(seq)


def test_score_roundtrip_all_pass_and_aggregates():
    h, s = _harness_with_suite()
    rec = h.score("s1", "r1", [("c1", True, 1.0), ("c2", True, 0.5)], 1)
    assert rec.verify()
    assert rec.passed_count == 2
    assert rec.case_count == 2
    assert rec.pass_rate_text == "2/2"
    assert rec.mean_metric_text == "3/4"  # (1.0 + 0.5) / 2 exact
    assert all(r.verify() for r in rec.results)
    assert h.run_ids("s1", 1) == ("r1",)


def test_score_failure_is_data_not_raised():
    h, _ = _harness_with_suite()
    rec = h.score("s1", "r1", [("c1", True, 0.75), ("c2", False, 0.0)], 1)
    assert rec.passed_count == 1
    assert rec.pass_rate_text == "1/2"
    assert rec.mean_metric_text == "3/8"  # (0.75 + 0.0) / 2 exact
    assert rec.verify()
    view = h.report("s1", "r1", 1)
    assert view.per_case == (("c1", True), ("c2", False))


def test_score_refusals():
    h, _ = _harness_with_suite()
    with pytest.raises(eh.UnknownSuiteError):
        h.score("nope", "r1", [("c1", True, 1.0), ("c2", True, 1.0)], 1)
    with pytest.raises(eh.UnknownCaseError):
        h.score("s1", "r1", [("c1", True, 1.0), ("zz", True, 1.0)], 2)
    with pytest.raises(eh.MissingCaseError):
        h.score("s1", "r1", [("c1", True, 1.0)], 3)
    with pytest.raises(eh.BadScoreError):
        h.score("s1", "r1", [("c1", "yes", 1.0), ("c2", True, 1.0)], 4)
    h.score("s1", "r1", [("c1", True, 1.0), ("c2", True, 1.0)], 5)
    with pytest.raises(eh.DuplicateRunError):
        h.score("s1", "r1", [("c1", True, 1.0), ("c2", True, 1.0)], 6)


def test_metric_validation_table():
    h, _ = _harness_with_suite()
    bad_metrics = [True, float("nan"), float("inf"), -0.5, 1.5,
                   "0.5", None, [0.5]]
    seq = 1
    for m in bad_metrics:
        with pytest.raises(eh.BadMetricError):
            h.score("s1", f"r{seq}", [("c1", True, m), ("c2", True, 0.5)],
                    seq)
        seq += 1
    # int 0/1 accepted and stored as float
    rec = h.score("s1", "rint", [("c1", True, 1), ("c2", True, 0)], seq)
    assert rec.results[0].metric == 1.0
    assert isinstance(rec.results[0].metric, float)


def test_report_pure_read_semantics():
    h, _ = _harness_with_suite()
    h.score("s1", "r1", [("c1", True, 1.0), ("c2", False, 0.0)], 1)
    audit_before = len(h.audit_log(1))
    v1 = h.report("s1", "r1", 1)  # same seq reusable
    v2 = h.report("s1", "r1", 1)
    assert v1.digest == v2.digest
    assert len(h.audit_log(1)) == audit_before  # no audit rows, no consumption
    assert v1.suite_digest != v1.score_digest
    assert v1.verify()
    with pytest.raises(eh.UnknownSuiteError):
        h.report("s1", "rX", 1)
    with pytest.raises(eh.UnknownSuiteError):
        h.report("sX", "r1", 1)


def test_seq_discipline():
    h = EvaluationHarness()
    h.suite("s1", [("c1", D1, D2)], 0)
    with pytest.raises(eh.SeqOrderError):
        h.suite("s2", [("c1", D1, D2)], 0)   # rewind raises bare
    with pytest.raises(eh.SeqOrderError):
        h.suite("s2", [("c1", D1, D2)], -1)
    with pytest.raises(eh.SeqOrderError):
        h.suite("s2", [("c1", D1, D2)], True)
    with pytest.raises(eh.SeqOrderError):
        h.suite("s2", [("c1", D1, D2)], "1")
    # rewind consumes nothing: no audit rows for bare rewinds
    assert len(h.audit_log(5)) == 1
    h.suite("s2", [("c1", D1, D2)], 5)
    assert len(h.audit_log(5)) == 2


def test_audit_shapes_and_leak_ban():
    h, s = _harness_with_suite()
    rows = h.audit_log(0)
    assert rows[0]["kind"] == "suite-registered"
    assert rows[0]["schema"] == "audit.ndjson/1"
    rec = h.score("s1", "r1", [("c1", True, 1.0), ("c2", True, 1.0)], 1)
    scored = h.audit_log(1)[-1]
    assert scored["kind"] == "scored"
    blob = str(scored)
    assert D1 not in blob  # raw pins only, and per-case pins absent
    assert "passed_count" in blob  # aggregate counts are allowed
    for key in ("input", "expected", "results", "score", "metric", "payload"):
        with pytest.raises(eh.BadScoreError):
            eh.evaluation_harness_audit_event("scored", 2, **{key: "x"})
    with pytest.raises(eh.AuditKindError):
        eh.evaluation_harness_audit_event("nope", 2)


def test_cross_instance_digest_determinism():
    def build():
        h = EvaluationHarness()
        s = h.suite("s1", [("c2", D3, D4), ("c1", D1, D2)], 0)
        rec = h.score("s1", "r1", [("c2", False, 0.25), ("c1", True, 1.0)], 1)
        return s.digest, rec.digest, h.report("s1", "r1", 1).digest
    a = build()
    b = build()
    assert a == b  # case/result order in input does not move digests


def test_stats_and_views():
    h, _ = _harness_with_suite()
    h.score("s1", "r1", [("c1", True, 1.0), ("c2", True, 1.0)], 1)
    stats = h.stats(1)
    assert stats["suite_count"] == 1
    assert stats["score_count"] == 1
    assert stats["audit_rows"] == 2
    assert stats["last_seq"] == 1
    assert h.suite_ids(1) == ("s1",)
    assert h.run_ids("s1", 1) == ("r1",)
    with pytest.raises(eh.UnknownSuiteError):
        h.run_ids("nope", 1)


def test_frozen_records():
    import dataclasses
    h, s = _harness_with_suite()
    with pytest.raises(dataclasses.FrozenInstanceError):
        s.suite_id = "mutated"  # type: ignore[misc]
    rec = h.score("s1", "r1", [("c1", True, 1.0), ("c2", True, 1.0)], 1)
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.passed_count = 99  # type: ignore[misc]


def test_main_subprocess():
    r = subprocess.run([sys.executable, eh.__file__],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    assert "evaluation-harness OK" in r.stdout
