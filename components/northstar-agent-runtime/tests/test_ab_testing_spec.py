"""Tests for the ab_testing spec API (variant/analyze), additive extension."""

import ast
import math
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import ab_testing
from ab_testing import (
    ABTesting,
    AnalysisReport,
    UnknownExperimentError,
    UnknownVariantError,
    VariantAnalysis,
    VariantView,
    ab_testing_audit_event,
)


def _ab_two_variants():
    ab = ABTesting()
    exp = ab.create("landing", {"control": 1, "treatment": 1}, seq=1)
    return ab, exp


def test_01_spec_api_present():
    ab, _ = _ab_two_variants()
    assert callable(ab.variant)
    assert callable(ab.assign)  # pre-existing
    assert callable(ab.analyze)


def test_02_version_and_schema_pins():
    assert ab_testing.AB_TESTING_VERSION == "ab-testing.v1"
    assert ab_testing.AB_TESTING_SCHEMA == "northstar.ab-testing.v1"
    assert "analysis-reported" in ab_testing._KINDS


def test_03_stdlib_only():
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


def test_04_variant_roundtrip():
    ab, exp = _ab_two_variants()
    view = ab.variant(exp.experiment_id, "control")
    assert isinstance(view, VariantView)
    assert view.experiment_id == exp.experiment_id
    assert view.variant_id == "control"
    assert view.weight == 1
    assert view.expected_share == 0.5
    assert view.assigned == 0
    assert view.version == "ab-testing.v1"
    assert view.schema == "northstar.ab-testing.v1"


def test_05_variant_assigned_count_tracks():
    ab, exp = _ab_two_variants()
    ab.assign(exp.experiment_id, "u-1", seq=2)
    ab.assign(exp.experiment_id, "u-2", seq=3)
    total = sum(ab.variant(exp.experiment_id, vid).assigned
                for vid in exp.variant_ids())
    assert total == 2


def test_06_variant_is_pure_read():
    ab, exp = _ab_two_variants()
    before = len(ab.audit_log())
    ab.variant(exp.experiment_id, "control")
    ab.variant(exp.experiment_id, "treatment")
    assert len(ab.audit_log()) == before  # no seq, no audit row


def test_07_variant_unknown_experiment():
    ab, _ = _ab_two_variants()
    try:
        ab.variant("nope", "control")
    except UnknownExperimentError:
        pass
    else:
        raise AssertionError("expected UnknownExperimentError")


def test_08_variant_unknown_variant():
    ab, exp = _ab_two_variants()
    for bad in ("nope", "", 123, None, b"control"):
        try:
            ab.variant(exp.experiment_id, bad)
        except UnknownVariantError:
            pass
        else:
            raise AssertionError(f"expected UnknownVariantError for {bad!r}")


def test_09_analyze_roundtrip_and_verify():
    ab, exp = _ab_two_variants()
    ab.assign(exp.experiment_id, "u-1", seq=2)
    ab.assign(exp.experiment_id, "u-2", seq=3)
    report = ab.analyze(exp.experiment_id, seq=4)
    assert isinstance(report, AnalysisReport)
    assert report.experiment_id == exp.experiment_id
    assert report.total_subjects == 2
    assert report.verify()
    assert report.verdict in ("balanced", "imbalanced", "no-data")
    d = report.as_dict()
    assert d["version"] == "ab-testing.v1"
    assert d["schema"] == "northstar.ab-testing.v1"


def test_10_analyze_no_data_on_empty_experiment():
    ab, exp = _ab_two_variants()
    report = ab.analyze(exp.experiment_id, seq=2)
    assert report.total_subjects == 0
    assert report.verdict == "no-data"
    assert report.chi_square == 0.0
    for va in report.variant_analyses:
        assert isinstance(va, VariantAnalysis)
        assert va.observed_share == 0.0
        assert va.deviation == -va.expected_share


def test_11_analyze_deviation_and_chi_square_math():
    ab = ABTesting()
    # Uneven weights make the math hand-checkable.
    exp = ab.create("w", {"a": 3, "b": 1}, seq=1)
    ab.assign(exp.experiment_id, "s-1", seq=2)  # lands somewhere, count it
    report = ab.analyze(exp.experiment_id, seq=3)
    counts = {va.variant_id: va.assigned for va in report.variant_analyses}
    total = sum(counts.values())
    assert total == 1
    expected = 0.0
    for va in report.variant_analyses:
        exp_share = {"a": 0.75, "b": 0.25}[va.variant_id]
        assert va.expected_share == exp_share
        assert va.observed_share == counts[va.variant_id] / total
        assert va.deviation == va.observed_share - va.expected_share
        ec = total * exp_share
        expected += (counts[va.variant_id] - ec) ** 2 / ec
    assert math.isclose(report.chi_square, expected, rel_tol=1e-9)


def test_12_analyze_books_audit_row():
    ab, exp = _ab_two_variants()
    before = len(ab.audit_log())
    ab.analyze(exp.experiment_id, seq=2)
    rows = ab.audit_log()[before:]
    assert len(rows) == 1
    assert rows[0]["kind"] == "analysis-reported"
    assert rows[0]["experiment_id"] == exp.experiment_id
    # The builder accepts the new kind too.
    ev = ab_testing_audit_event("analysis-reported", 7,
                                experiment_id=exp.experiment_id)
    assert ev["kind"] == "analysis-reported"


def test_13_analyze_unknown_experiment():
    ab, _ = _ab_two_variants()
    try:
        ab.analyze("nope", seq=2)
    except UnknownExperimentError:
        pass
    else:
        raise AssertionError("expected UnknownExperimentError")


def test_14_analyze_bad_seq_refused():
    ab, exp = _ab_two_variants()
    for bad in (True, -1, "2", 2.0):
        try:
            ab.analyze(exp.experiment_id, bad)
        except (TypeError, ValueError):
            pass
        else:
            raise AssertionError(f"expected seq refusal for {bad!r}")


def test_15_main_self_check():
    mod = ab_testing.__file__
    out = subprocess.run([sys.executable, mod], capture_output=True,
                         text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    assert "variant, analyze" in out.stdout
