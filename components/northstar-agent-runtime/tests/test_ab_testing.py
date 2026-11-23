"""Tests for ab_testing: 16 cases."""

import ast
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import ab_testing
from ab_testing import (
    ABTesting,
    BadExperimentError,
    DuplicateExperimentError,
    UnknownExperimentError,
    ab_testing_audit_event,
)


def _ab():
    return ABTesting()


def _variants():
    return {"control": 1, "treatment": 1}


def test_01_version_and_schema_pins():
    assert ab_testing.AB_TESTING_VERSION == "ab-testing.v1"
    assert ab_testing.AB_TESTING_SCHEMA == "northstar.ab-testing.v1"
    assert ab_testing.AUDIT_SCHEMA == "audit.ndjson/1"


def test_02_stdlib_only():
    path = os.path.join(os.path.dirname(__file__), "..", "ab_testing.py")
    tree = ast.parse(open(path, encoding="utf-8").read())
    allowed = {
        "hashlib", "math", "threading", "dataclasses", "typing",
        "__future__", "canonical_json", "json",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


def test_03_create_happy_path_and_auto_id():
    ab = _ab()
    exp = ab.create("checkout-cta", _variants(), seq=1)
    assert exp.experiment_id == "exp-1"
    assert exp.name == "checkout-cta"
    assert exp.variant_ids() == ("control", "treatment")
    assert exp.total_weight() == 2.0
    assert exp.digest.startswith("sha256:")
    assert exp.version == "ab-testing.v1"
    exp2 = ab.create("other", _variants(), seq=2)
    assert exp2.experiment_id == "exp-2"


def test_04_create_explicit_id_and_duplicate_refused():
    ab = _ab()
    ab.create("x", _variants(), seq=1, experiment_id="e1")
    try:
        ab.create("x", _variants(), seq=2, experiment_id="e1")
    except DuplicateExperimentError:
        pass
    else:
        raise AssertionError("duplicate experiment_id must raise")
    assert ab.experiment("e1").name == "x"


def test_05_create_bad_name_refused():
    ab = _ab()
    for bad in ("", 123, None, True):
        try:
            ab.create(bad, _variants(), seq=1)
        except (TypeError, ValueError):
            pass
        else:
            raise AssertionError(f"bad name {bad!r} must raise")


def test_06_create_bad_variants_refused():
    ab = _ab()
    # fewer than two variants
    for bad in ({"only": 1}, {}, [], [("a", 1)]):
        try:
            ab.create("x", bad, seq=1)
        except BadExperimentError:
            pass
        else:
            raise AssertionError(f"bad variants {bad!r} must raise")
    # duplicate ids
    try:
        ab.create("x", [("a", 1), ("a", 2)], seq=1)
    except BadExperimentError:
        pass
    else:
        raise AssertionError("duplicate variant id must raise")
    # negative weight, zero total, bool weight, NaN weight
    for bad in ({"a": -1, "b": 1}, {"a": 0, "b": 0},
                {"a": True, "b": 1}, {"a": float("nan"), "b": 1},
                {"a": float("inf"), "b": 1}):
        try:
            ab.create("x", bad, seq=1)
        except (TypeError, ValueError, BadExperimentError):
            pass
        else:
            raise AssertionError(f"bad weights {bad!r} must raise")
    # empty variant id / non-mapping junk
    for bad in ({"": 1, "b": 1}, 42, "nope"):
        try:
            ab.create("x", bad, seq=1)
        except (TypeError, ValueError, BadExperimentError):
            pass
        else:
            raise AssertionError(f"bad variants {bad!r} must raise")


def test_07_assign_happy_path_and_deterministic_across_instances():
    ab1, ab2 = _ab(), _ab()
    e1 = ab1.create("x", {"a": 1, "b": 3}, seq=1)
    e2 = ab2.create("x", {"a": 1, "b": 3}, seq=1)
    r1 = ab1.assign(e1.experiment_id, "subject-9", seq=2)
    r2 = ab2.assign(e2.experiment_id, "subject-9", seq=2)
    assert r1.variant_id == r2.variant_id  # pure function of (digest, subject)
    assert r1.variant_id in ("a", "b")
    assert r1.digest == r2.digest
    assert r1.bucket == r2.bucket


def test_08_assign_sticky_idempotent():
    ab = _ab()
    exp = ab.create("x", _variants(), seq=1)
    first = ab.assign(exp.experiment_id, "s", seq=2)
    again = ab.assign(exp.experiment_id, "s", seq=99)
    assert again == first  # original record returned, never re-randomized
    assert again.seq == 2


def test_09_assign_unknown_experiment_and_bad_subject_refused():
    ab = _ab()
    try:
        ab.assign("nope", "s", seq=1)
    except UnknownExperimentError:
        pass
    else:
        raise AssertionError("unknown experiment must raise")
    exp = ab.create("x", _variants(), seq=1)
    for bad in ("", 12, None):
        try:
            ab.assign(exp.experiment_id, bad, seq=2)
        except (TypeError, ValueError):
            pass
        else:
            raise AssertionError(f"bad subject {bad!r} must raise")


def test_10_results_counts_and_shares():
    ab = _ab()
    exp = ab.create("x", {"a": 1, "b": 1}, seq=1)
    seen = {}
    for i in range(50):
        r = ab.assign(exp.experiment_id, f"user-{i}", seq=2 + i)
        seen[r.variant_id] = seen.get(r.variant_id, 0) + 1
    report = ab.results(exp.experiment_id, seq=100)
    assert report.total_subjects == 50
    for vr in report.variant_results:
        assert vr.assigned == seen[vr.variant_id]
        assert vr.expected_share == 0.5
        assert vr.assigned > 0  # 50/50 split must hit both buckets
    assert abs(sum(vr.observed_share for vr in report.variant_results) - 1.0) < 1e-9
    assert report.count_for("a") == seen["a"]
    assert report.digest.startswith("sha256:")


def test_11_results_empty_experiment():
    ab = _ab()
    exp = ab.create("x", _variants(), seq=1)
    report = ab.results(exp.experiment_id, seq=2)
    assert report.total_subjects == 0
    assert all(vr.assigned == 0 for vr in report.variant_results)
    assert all(vr.observed_share == 0.0 for vr in report.variant_results)


def test_12_results_unknown_experiment_refused():
    ab = _ab()
    try:
        ab.results("nope", seq=1)
    except UnknownExperimentError:
        pass
    else:
        raise AssertionError("unknown experiment must raise")


def test_13_seq_validation():
    ab = _ab()
    for bad in (True, -1, 1.5, "2", None):
        try:
            ab.create("x", _variants(), seq=bad)
        except (TypeError, ValueError):
            pass
        else:
            raise AssertionError(f"bad seq {bad!r} must raise")
    exp = ab.create("x", _variants(), seq=0)  # zero is fine
    for bad in (False, -3):
        try:
            ab.assign(exp.experiment_id, "s", seq=bad)
        except (TypeError, ValueError):
            pass
        else:
            raise AssertionError(f"bad seq {bad!r} must raise")


def test_14_audit_shapes_and_unknown_kind_refused():
    ev = ab_testing_audit_event("experiment-created", 1, experiment_id="exp-1")
    assert ev["event"] == "ab-testing"
    assert ev["kind"] == "experiment-created"
    assert ev["schema"] == "audit.ndjson/1"
    assert ev["experiment_id"] == "exp-1"
    try:
        ab_testing_audit_event("bogus", 1)
    except ValueError:
        pass
    else:
        raise AssertionError("unknown audit kind must raise")
    ab = _ab()
    exp = ab.create("x", _variants(), seq=1)
    ab.assign(exp.experiment_id, "s", seq=2)
    ab.results(exp.experiment_id, seq=3)
    kinds = [e["kind"] for e in ab.audit_log()]
    assert kinds == ["experiment-created", "subject-assigned", "results-reported"]


def test_15_views_and_snapshot():
    ab = _ab()
    exp = ab.create("x", _variants(), seq=1)
    assert ab.experiment(exp.experiment_id) == exp
    assert ab.experiment_ids() == (exp.experiment_id,)
    assert ab.assignment(exp.experiment_id, "nobody") is None
    r = ab.assign(exp.experiment_id, "s1", seq=2)
    assert ab.assignment(exp.experiment_id, "s1") == r
    snap = ab.as_dict()
    assert snap["schema"] == "northstar.ab-testing.v1"
    assert len(snap["experiments"]) == 1
    assert len(snap["assignments"]) == 1
    # frozen records
    try:
        exp.name = "mutated"  # type: ignore[misc]
    except Exception:
        pass
    else:
        raise AssertionError("ExperimentRecord must be frozen")


def test_16_main_self_check():
    ab_testing.main()


if __name__ == "__main__":
    test_01_version_and_schema_pins()
    test_02_stdlib_only()
    test_03_create_happy_path_and_auto_id()
    test_04_create_explicit_id_and_duplicate_refused()
    test_05_create_bad_name_refused()
    test_06_create_bad_variants_refused()
    test_07_assign_happy_path_and_deterministic_across_instances()
    test_08_assign_sticky_idempotent()
    test_09_assign_unknown_experiment_and_bad_subject_refused()
    test_10_results_counts_and_shares()
    test_11_results_empty_experiment()
    test_12_results_unknown_experiment_refused()
    test_13_seq_validation()
    test_14_audit_shapes_and_unknown_kind_refused()
    test_15_views_and_snapshot()
    test_16_main_self_check()
    print("16 tests OK")
