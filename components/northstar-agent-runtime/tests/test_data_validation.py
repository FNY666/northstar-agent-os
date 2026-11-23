"""Tests for data_validation.py (Great Expectations-shaped suite bookkeeping)."""

import ast
import json
import subprocess
import sys
from pathlib import Path

import pytest

import data_validation
from data_validation import (
    BadBatchError,
    BadKwargError,
    BadSuiteError,
    BadTypeError,
    DataValidation,
    DuplicateExpectationError,
    DuplicateSuiteError,
    SeqOrderError,
    UnknownSuiteError,
    data_validation_audit_event,
)

MODULE_PATH = Path(data_validation.__file__)


def _dv_with_suite():
    dv = DataValidation()
    dv.suite("s", 1)
    return dv


# 1. version / schema pins
def test_version_schema_pins():
    assert data_validation.DATA_VALIDATION_VERSION == "data-validation.v1"
    assert data_validation.SCHEMA_PIN == "northstar.data-validation.v1"
    assert data_validation.AUDIT_SCHEMA == "audit.ndjson/1"
    for t in data_validation.EXPECTATION_TYPES:
        assert t.startswith("expect_")


# 2. stdlib-only
def test_stdlib_only():
    tree = ast.parse(MODULE_PATH.read_text())
    allowed = {
        "hashlib", "json", "re", "threading", "dataclasses",
        "fractions", "__future__", "typing", "builtins",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed, a.name
        elif isinstance(node, ast.ImportFrom):
            assert node.module is None or node.module.split(".")[0] in allowed, node.module


# 3. suite roundtrip + verify + frozen
def test_suite_roundtrip():
    dv = DataValidation()
    record = dv.suite("orders", 1)
    assert record.suite_id == "orders"
    assert record.verify()
    assert record.as_dict()["digest"] == record.digest
    fetched = dv.suite_record("orders", 2)
    assert fetched == record
    assert dv.suite_record("missing", 2) is None
    assert dv.suite_ids(2) == ("orders",)
    try:
        record.suite_id = "x"  # type: ignore[misc]
    except Exception:
        pass
    else:
        raise AssertionError("SuiteRecord must be frozen")


# 4. suite duplicate + bad ids consume seq (failed mutation burns seq)
def test_suite_duplicate_and_bad_ids():
    dv = _dv_with_suite()
    with pytest.raises(DuplicateSuiteError):
        dv.suite("s", 2)
    # seq 2 was consumed by the failed mutation
    with pytest.raises(SeqOrderError):
        dv.suite("other", 2)
    for bad in ("", "  ", "has space", "x" * 257):
        with pytest.raises(BadSuiteError):
            dv.suite(bad, dv._seq + 1)
    kinds = [r["kind"] for r in dv.audit_log()]
    assert kinds.count("rejected") == 5


# 5. expect roundtrip + verify + kwargs replay + digest determinism
def test_expect_roundtrip():
    dv = _dv_with_suite()
    record = dv.expect(
        "s", "e1", "expect_column_values_to_be_in_set",
        {"column": "status", "value_set": ["a", "b"]}, 2,
    )
    assert record.verify()
    assert record.kwargs() == {"column": "status", "value_set": ["a", "b"]}
    fetched = dv.expectation_record("s", "e1", 3)
    assert fetched == record
    assert dv.expectation_ids("s", 3) == ("e1",)
    # deterministic across instances
    dv2 = DataValidation()
    dv2.suite("s", 1)
    record2 = dv2.expect(
        "s", "e1", "expect_column_values_to_be_in_set",
        {"column": "status", "value_set": ["a", "b"]}, 2,
    )
    assert record2.digest == record.digest


# 6. expect bad-type vocabulary (pinned)
def test_expect_bad_type_vocabulary():
    dv = _dv_with_suite()
    with pytest.raises(BadTypeError):
        dv.expect("s", "e", "expect_anything_at_all", {}, 2)
    with pytest.raises(BadTypeError):
        dv.expect("s", "e", 123, {}, 3)


# 7. expect bad-kwargs per-type contract
def test_expect_bad_kwargs():
    dv = _dv_with_suite()
    seq = 2
    bad_cases = [
        ("expect_column_values_to_be_between", {"column": "a"}, 1),  # missing max
        ("expect_column_values_to_be_between",
         {"column": "a", "min_value": 5, "max_value": 1}, 1),  # min > max
        ("expect_column_values_to_be_between",
         {"column": "a", "min_value": True, "max_value": 1}, 1),  # bool bound
        ("expect_column_values_to_be_in_set", {"column": "a", "value_set": []}, 1),
        ("expect_column_values_to_be_in_set",
         {"column": "a", "value_set": [object()]}, 1),  # unserializable
        ("expect_column_values_to_match_regex",
         {"column": "a", "regex": "([a-z"}, 1),  # bad regex
        ("expect_column_values_to_match_regex", {"column": "a"}, 1),  # missing
        ("expect_column_values_to_be_between",
         {"column": "", "min_value": 0, "max_value": 1}, 1),  # empty column
        ("expect_column_to_exist", "not-a-dict", 1),  # kwargs not a mapping
    ]
    for etype, kwargs, _ in bad_cases:
        with pytest.raises(BadKwargError):
            dv.expect("s", f"e-{seq}", etype, kwargs, seq)
        seq += 1


# 8. expect duplicate + unknown suite
def test_expect_duplicate_and_unknown_suite():
    dv = _dv_with_suite()
    dv.expect("s", "e1", "expect_column_to_exist", {"column": "c"}, 2)
    with pytest.raises(DuplicateExpectationError):
        dv.expect("s", "e1", "expect_column_to_exist", {"column": "c"}, 3)
    with pytest.raises(UnknownSuiteError):
        dv.expect("nope", "e", "expect_column_to_exist", {"column": "c"}, 4)


# 9. validate success across all eight expectation types
def test_validate_success_all_types():
    dv = DataValidation()
    dv.suite("s", 1)
    dv.expect("s", "e1", "expect_column_to_exist", {"column": "name"}, 2)
    dv.expect("s", "e2", "expect_column_values_to_not_be_null", {"column": "name"}, 3)
    dv.expect("s", "e3", "expect_column_values_to_be_in_set",
               {"column": "role", "value_set": ["admin", "user"]}, 4)
    dv.expect("s", "e4", "expect_column_values_to_be_between",
               {"column": "age", "min_value": 0, "max_value": 150}, 5)
    dv.expect("s", "e5", "expect_column_values_to_match_regex",
               {"column": "code", "regex": r"[A-Z]{2}[0-9]+"}, 6)
    dv.expect("s", "e6", "expect_table_row_count_to_be_between",
               {"min_value": 1, "max_value": 10}, 7)
    dv.expect("s", "e7", "expect_column_mean_to_be_between",
               {"column": "age", "min_value": 20, "max_value": 40}, 8)
    dv.expect("s", "e8", "expect_column_values_to_be_unique", {"column": "name"}, 9)
    rows = [
        {"name": "a", "role": "admin", "age": 30, "code": "AB12"},
        {"name": "b", "role": "user", "age": 40, "code": "CD34"},
    ]
    report = dv.validate("s", "b1", rows, 10)
    assert report.success
    assert len(report.results) == 8
    assert all(r.success for r in report.results)
    assert report.verify()
    assert report.as_dict()["success"] is True
    fetched = dv.validation_report("s", "b1", 11)
    assert fetched == report


# 10. validate failure is data, never raised
def test_validate_failure_is_data():
    dv = DataValidation()
    dv.suite("s", 1)
    dv.expect("s", "e1", "expect_column_values_to_not_be_null", {"column": "name"}, 2)
    dv.expect("s", "e2", "expect_column_values_to_be_unique", {"column": "name"}, 3)
    rows = [{"name": "x"}, {"name": "x"}, {"other": 1}]
    report = dv.validate("s", "b1", rows, 4)
    assert not report.success
    by_id = {r.expectation_id: r for r in report.results}
    assert not by_id["e1"].success  # missing column counts as unexpected
    assert dict(by_id["e1"].observed)["unexpected"] == 1
    assert not by_id["e2"].success  # duplicates + missing column
    observed = dict(by_id["e2"].observed)
    assert observed["unexpected"] == 2
    assert report.verify()


# 11. validate unknown suite + bad batch shapes
def test_validate_unknown_suite_and_bad_batch():
    dv = _dv_with_suite()
    with pytest.raises(UnknownSuiteError):
        dv.validate("nope", "b", [], 2)
    with pytest.raises(BadBatchError):
        dv.validate("s", "b", "not-a-list", 3)
    with pytest.raises(BadBatchError):
        dv.validate("s", "b", [{"a": 1}, 42], 4)
    with pytest.raises(BadBatchError):
        dv.validate("s", "", [], 5)


# 12. empty batch: column expectations vacuously succeed; row-count evaluates
def test_validate_empty_batch():
    dv = DataValidation()
    dv.suite("s", 1)
    dv.expect("s", "e1", "expect_column_values_to_not_be_null", {"column": "c"}, 2)
    dv.expect("s", "e2", "expect_table_row_count_to_be_between",
               {"min_value": 1, "max_value": 5}, 3)
    report = dv.validate("s", "b", [], 4)
    by_id = {r.expectation_id: r for r in report.results}
    assert by_id["e1"].success  # vacuous
    assert not by_id["e2"].success  # 0 rows out of range
    assert not report.success
    assert report.verify()


# 13. seq ordering: rewind raises bare, views never consume
def test_seq_ordering():
    dv = _dv_with_suite()
    with pytest.raises(SeqOrderError):
        dv.suite("x", 1)  # rewind (1 <= 1) raises without consuming
    for bad in (True, -1, "1", 1.0, None):
        with pytest.raises(SeqOrderError):
            dv.suite("x", bad)
    # views accept any well-formed seq, including rewinds, consuming nothing
    assert dv.suite_ids(0) == ("s",)
    assert dv.stats(0)["seq"] == 1
    assert dv.stats(1)["seq"] == 1
    assert not any(r["kind"] == "rejected" for r in dv.audit_log())


# 14. audit shapes + banned keys + bad kind
def test_audit_shapes():
    dv = DataValidation()
    dv.suite("s", 1)
    dv.expect("s", "e", "expect_column_to_exist", {"column": "c"}, 2)
    dv.validate("s", "b", [{"c": 1}], 3)
    rows = dv.audit_log()
    assert [r["kind"] for r in rows] == ["suite-created", "expectation-added", "validated"]
    for row in rows:
        assert row["schema"] == "audit.ndjson/1"
        assert row["module"] == "data-validation.v1"
    event = data_validation_audit_event("validated", {"success": True}, 4)
    assert event["detail"] == {"success": True}
    with pytest.raises(data_validation.AuditKindError):
        data_validation_audit_event("nope", {}, 5)
    with pytest.raises(data_validation.AuditKindError):
        data_validation_audit_event("validated", {"rows": []}, 5)
    with pytest.raises(data_validation.AuditKindError):
        data_validation_audit_event("validated", {"value": 1}, 5)
    with pytest.raises(data_validation.AuditKindError):
        data_validation_audit_event("suite-created", {"payload": "x"}, 5)


# 15. main() self-check via subprocess
def test_main_self_check():
    result = subprocess.run(
        [sys.executable, str(MODULE_PATH)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert "data-validation OK" in result.stdout
