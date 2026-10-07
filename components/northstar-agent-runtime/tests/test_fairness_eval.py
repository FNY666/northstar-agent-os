"""Targeted tests for fairness_eval (bias-testing bookkeeping)."""

import ast
import hashlib
import json
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import fairness_eval
from fairness_eval import FairnessEval, fairness_eval_audit_event, VERSION, SCHEMA

MODULE_PATH = Path(fairness_eval.__file__)
STDLIB_OK = {
    "__future__", "hashlib", "json", "threading", "dataclasses",
    "typing", "canonical_json",
}


def new_pair():
    fe = FairnessEval()
    fe.group("g-a", 1)
    fe.group("g-b", 2)
    return fe


# 1. pins
def test_version_schema_pins():
    assert VERSION == "fairness-eval.v1"
    assert SCHEMA == "northstar.fairness-eval.v1"
    assert fe_stats_schema()


def fe_stats_schema():
    return FairnessEval().stats()["schema"] == SCHEMA


# 2. stdlib only
def test_stdlib_only():
    tree = ast.parse(MODULE_PATH.read_text())
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.add((node.module or "").split(".")[0])
    assert imports <= STDLIB_OK, imports - STDLIB_OK


# 3. group roundtrip + verify
def test_group_roundtrip():
    fe = FairnessEval()
    rec = fe.group("g-a", 1, description="young", attributes={"age": "young"})
    assert rec.group_id == "g-a"
    assert rec.verify()
    assert fe.group_record("g-a") == rec
    assert fe.group_ids() == ("g-a",)
    # raw values pinned, not present
    assert "young" not in json.dumps(fe.audit_log())


# 4. group duplicates / bad inputs
def test_group_refusals():
    fe = FairnessEval()
    fe.group("g-a", 1)
    with pytest.raises(fairness_eval.DuplicateGroupError):
        fe.group("g-a", 2)
    for bad in ["", "   ", 123, None, "x" * 129]:
        with pytest.raises(fairness_eval.BadGroupError):
            fe.group(bad, fe._last_seq + 1)
    rejected = [r for r in fe.audit_log() if r["kind"] == "rejected"]
    assert len(rejected) == 6
    assert fe.stats()["groups"] == 1


# 5. disparity disparate-impact math
def test_disparate_impact_math():
    fe = new_pair()
    r = fe.disparity("g-a", "g-b", "disparate-impact", 0.8, 0.9, 3)
    assert r.verify()
    # min/max ratio: 0.8/0.9 >= 4/5 -> no adverse impact
    assert (r.ratio_num, r.ratio_den) == (800000, 900000)
    assert r.verdict == "no-adverse-impact"
    r2 = fe.disparity("g-a", "g-b", "disparate-impact", 0.5, 0.9, 4)
    assert r2.verdict == "adverse-impact"


# 6. statistical parity + equalized odds
def test_parity_and_odds_verdicts():
    fe = new_pair()
    p = fe.disparity("g-a", "g-b", "statistical-parity", 0.5, 0.55, 3)
    assert p.verdict == "parity"
    p2 = fe.disparity("g-a", "g-b", "statistical-parity", 0.5, 0.7, 4)
    assert p2.verdict == "disparity"
    e = fe.disparity("g-a", "g-b", "equalized-odds", 0.5, 0.52, 5)
    assert e.verdict == "odds-equal"
    e2 = fe.disparity("g-a", "g-b", "equalized-odds", 0.2, 0.9, 6)
    assert e2.verdict == "odds-unequal"


# 7. disparity refusals
def test_disparity_refusals():
    fe = new_pair()
    with pytest.raises(fairness_eval.BadMetricError):
        fe.disparity("g-a", "g-b", "demographic-magic", 0.5, 0.6, 3)
    with pytest.raises(fairness_eval.UnknownGroupError):
        fe.disparity("g-a", "nope", "statistical-parity", 0.5, 0.6, 4)
    with pytest.raises(fairness_eval.BadGroupError):
        fe.disparity("g-a", "g-a", "statistical-parity", 0.5, 0.6, 5)
    for bad in [True, -0.1, 1.5, "x", None, float("nan")]:
        with pytest.raises(fairness_eval.BadRateError):
            fe.disparity("g-a", "g-b", "statistical-parity", bad, 0.5, fe._last_seq + 1)
    assert len(fe.report_ids()) == 0


# 8. mitigate roundtrip + vocabulary
def test_mitigate_roundtrip():
    fe = new_pair()
    for s in ("reweight", "resample", "threshold-optimize", "constrain"):
        mit = fe.mitigate("g-a", "g-b", s, fe._last_seq + 1)
        assert mit.verify()
    assert len(fe.mitigation_ids()) == 4
    with pytest.raises(fairness_eval.BadStrategyError):
        fe.mitigate("g-a", "g-b", "delete-the-data", fe._last_seq + 1)
    with pytest.raises(fairness_eval.UnknownGroupError):
        fe.mitigate("g-a", "ghost", "reweight", fe._last_seq + 1)


# 9. zero rates are data, not errors
def test_zero_rates_as_data():
    fe = new_pair()
    r = fe.disparity("g-a", "g-b", "disparate-impact", 0.0, 0.0, 3)
    assert r.verify()
    assert (r.ratio_num, r.ratio_den) == (1, 1)
    assert r.verdict == "no-adverse-impact"
    r2 = fe.disparity("g-a", "g-b", "disparate-impact", 0.0, 0.5, 4)
    assert (r2.ratio_num, r2.ratio_den) == (0, 500000)
    assert r2.verdict == "adverse-impact"


# 10. seq discipline
def test_seq_discipline():
    fe = new_pair()
    with pytest.raises(fairness_eval.SeqOrderError):
        fe.group("g-c", 1)  # rewind raises bare, no audit row consumed
    assert "g-c" not in fe.group_ids()
    with pytest.raises(fairness_eval.SeqOrderError):
        fe.group("g-d", True)
    # failed mutation consumes seq and books rejected
    try:
        fe.disparity("g-a", "g-b", "bogus", 0.5, 0.6, 3)
    except fairness_eval.BadMetricError:
        pass
    with pytest.raises(fairness_eval.SeqOrderError):
        fe.disparity("g-a", "g-b", "statistical-parity", 0.5, 0.6, 3)


# 11. audit shapes + leak ban + bad kind
def test_audit_shapes():
    fe = new_pair()
    fe.disparity("g-a", "g-b", "statistical-parity", 0.5, 0.6, 3)
    fe.mitigate("g-a", "g-b", "reweight", 4)
    kinds = [r["kind"] for r in fe.audit_log()]
    assert kinds == ["group-registered", "group-registered",
                     "disparity-measured", "mitigation-booked"]
    blob = json.dumps(fe.audit_log())
    assert "young" not in blob
    with pytest.raises(fairness_eval.AuditKindError):
        fairness_eval_audit_event("bogus-kind")


# 12. cross-instance determinism
def test_cross_instance_determinism():
    def build():
        fe = FairnessEval()
        fe.group("g-a", 1, attributes={"k": "v"})
        fe.group("g-b", 2)
        return fe.disparity("g-a", "g-b", "disparate-impact", 0.8, 0.9, 3).digest
    assert build() == build()


# 13. report lookup
def test_report_lookup():
    fe = new_pair()
    r = fe.disparity("g-a", "g-b", "statistical-parity", 0.5, 0.6, 3)
    assert fe.disparity_report(r.report_id) == r
    assert fe.report_ids() == (r.report_id,)
    with pytest.raises(fairness_eval.UnknownGroupError):
        fe.disparity_report("dsp-999")


# 14. concurrency smoke
def test_concurrency_smoke():
    fe = new_pair()
    errors = []

    def worker(i):
        try:
            fe.disparity("g-a", "g-b", "statistical-parity", 0.4, 0.5 + (i % 5) / 100,
                         3 + i)
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert fe.stats()["reports"] == 8


# 15. main() subprocess
def test_main_subprocess():
    proc = subprocess.run(
        [sys.executable, str(MODULE_PATH)],
        capture_output=True, text=True, cwd="/tmp", timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert "fairness-eval OK" in proc.stdout
