"""Targeted tests for output_parser (15 tests)."""

import ast
import json
import subprocess
import sys
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

import output_parser
from output_parser import (
    OUTPUT_PARSER_VERSION,
    SCHEMA_PIN,
    PARSER_TYPES,
    AuditKindError,
    BadParserError,
    BadSpecError,
    BadTextError,
    BadTypeError,
    BadValueError,
    DuplicateParserError,
    OutputParser,
    SeqOrderError,
    UnknownParserError,
    output_parser_audit_event,
)

COMP_DIR = Path(__file__).resolve().parent.parent


def _fresh(n=0):
    op = OutputParser()
    op.register("cfg", "json-object", n + 1, {"required_keys": ["name"]})
    op.register("nums", "number", n + 2, {"kind": "int", "min": 0, "max": 9})
    op.register("lvl", "enum", n + 3, {"allowed": ["low", "high"]})
    return op


def test_version_and_schema_pins():
    assert OUTPUT_PARSER_VERSION == "output-parser.v1"
    assert SCHEMA_PIN == "northstar.output-parser.v1"
    assert PARSER_TYPES == (
        "json-object", "json-array", "csv-row", "number", "enum", "regex",
    )
    op = _fresh()
    rec = op.parser_record("cfg", 4)
    assert rec.parser_type == "json-object"
    assert rec.spec() == {"required_keys": ["name"]}


def test_stdlib_only():
    tree = ast.parse((COMP_DIR / "output_parser.py").read_text())
    allowed = {
        "hashlib", "json", "csv", "io", "re", "threading",
        "dataclasses", "typing", "__future__", "canonical_json",
    }
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                found.add(node.module.split(".")[0])
    assert found <= allowed, found - allowed


def test_register_roundtrip():
    op = OutputParser()
    rec = op.register("rx", "regex", 1, {"pattern": r"@(\w+)"})
    assert rec.verify()
    assert rec.as_dict()["parser_id"] == "rx"
    assert rec.spec() == {"pattern": r"@(\w+)", "group": 1}
    assert op.parser_ids(2) == ("rx",)
    assert op.parser_record("nope", 2) is None


def test_register_bad_inputs():
    op = OutputParser()
    with pytest.raises(BadParserError):
        op.register("", "json-object", 1)
    with pytest.raises(BadTypeError):
        op.register("a", "xml", 2)
    with pytest.raises(BadSpecError):
        op.register("a", "enum", 3)  # missing allowed
    with pytest.raises(BadSpecError):
        op.register("a", "enum", 4, {"allowed": []})
    with pytest.raises(BadSpecError):
        op.register("a", "regex", 5, {"pattern": "([unclosed"})
    with pytest.raises(BadSpecError):
        op.register("a", "number", 6, {"kind": "decimal"})
    with pytest.raises(BadSpecError):
        op.register("a", "number", 7, {"bogus": 1})
    op.register("dup", "json-array", 8)
    with pytest.raises(DuplicateParserError):
        op.register("dup", "json-array", 9)
    rejected = [r for r in op.audit_log() if r["kind"] == "rejected"]
    assert len(rejected) == 8
    assert [r["detail"]["reason"] for r in rejected][0] == "BadParserError"
    assert op.stats(10)["seq"] == 9  # failed mutations consumed their seqs


def test_parse_json_object():
    op = _fresh()
    good = op.parse("cfg", '{"name": "svc", "port": 8080}', 4)
    assert good.success and good.error_code == ""
    assert good.outcome_id == "parse-1"
    assert good.verify()
    assert json.loads(good.value_json) == {"name": "svc", "port": 8080}
    assert good.value_digest.startswith("sha256:")
    bad = op.parse("cfg", "not json", 5)
    assert not bad.success and bad.error_code == "bad-json"
    assert bad.value_json == "null"
    assert bad.verify()
    arr = op.parse("cfg", "[1, 2]", 6)
    assert not arr.success and arr.error_code == "not-an-object"
    with pytest.raises(UnknownParserError):
        op.parse("ghost", "{}", 7)
    with pytest.raises(BadTextError):
        op.parse("cfg", 123, 8)


def test_parse_other_types():
    op = OutputParser()
    op.register("row", "csv-row", 1, {"columns": 2})
    op.register("n", "number", 2)
    op.register("e", "enum", 3, {"allowed": ["a", "b"]})
    op.register("r", "regex", 4, {"pattern": r"order-(\d+)"})
    op.register("arr", "json-array", 5, {"max_items": 3})
    assert op.parse("row", '"x,y",z', 6).success  # quoted CSV cell
    assert json.loads(op.parse("row", '"x,y",z', 7).value_json) == ["x,y", "z"]
    assert op.parse("row", "only-one", 8).error_code == "bad-columns"
    assert json.loads(op.parse("n", "-42", 9).value_json) == -42
    assert op.parse("n", "1e3", 10).success
    assert json.loads(op.parse("n", "1e3", 11).value_json) == 1000.0
    assert op.parse("n", "abc", 12).error_code == "not-a-number"
    assert op.parse("n", "", 13).error_code == "empty-text"
    assert op.parse("e", "  b ", 14).success  # stripped
    assert op.parse("e", "c", 15).error_code == "unknown-enum"
    got = op.parse("r", "see order-42 now", 16)
    assert got.success and json.loads(got.value_json) == "42"
    assert op.parse("r", "nothing", 17).error_code == "no-match"
    assert op.parse("arr", "[1, 2]", 18).success
    assert op.parse("arr", '{"k": 1}', 19).error_code == "not-an-array"
    assert op.stats(20)["parses"] == 14


def test_validate_roundtrip():
    op = _fresh()
    ok = op.validate("cfg", {"name": "x"}, 4)
    assert ok.success and ok.errors == ()
    assert ok.verify()
    assert ok.value_digest.startswith("sha256:")
    missing = op.validate("cfg", {"other": 1}, 5)
    assert not missing.success and missing.errors == ("missing-keys",)
    assert missing.verify()
    assert op.validate("nums", 5, 6).success
    over = op.validate("nums", 99, 7)
    assert not over.success and over.errors == ("out-of-range",)
    wrong = op.validate("nums", "5", 8)
    assert not wrong.success and "wrong-type" in wrong.errors
    assert op.validate("lvl", "low", 9).success
    assert op.validate("lvl", "mid", 10).errors == ("not-allowed",)
    with pytest.raises(BadValueError):
        op.validate("cfg", {"nan": float("nan")}, 11)
    with pytest.raises(UnknownParserError):
        op.validate("ghost", {}, 12)


def test_schema_pure_read():
    op = _fresh()
    rep = op.schema("lvl", 4)
    assert rep.verify()
    assert rep.parser_type == "enum"
    assert rep.spec_digest.startswith("sha256:")
    assert "low, high" in rep.instructions
    assert rep.as_dict()["seq"] == 4
    audit_before = len(op.audit_log())
    op.schema("lvl", 4)  # same seq twice: pure read, no consumption
    op.schema("cfg", 4)
    assert op.stats(4)["seq"] == 3  # seq never consumed by views
    assert len(op.audit_log()) == audit_before  # no audit rows written
    with pytest.raises(UnknownParserError):
        op.schema("ghost", 4)


def test_seq_discipline():
    op = _fresh()
    for bad in (True, "4", 2.0, -1, None):
        with pytest.raises(SeqOrderError):
            op.register("x", "json-object", bad)
    with pytest.raises(SeqOrderError):
        op.register("x", "json-object", 3)  # rewind: 3 <= current 3
    assert op.stats(4)["seq"] == 3  # rewinds consume nothing
    with pytest.raises(SeqOrderError):
        op.schema("cfg", True)  # views validate shape too


def test_failed_mutation_consumes_seq():
    op = OutputParser()
    with pytest.raises(UnknownParserError):
        op.parse("ghost", "{}", 1)
    rec = op.register("ok", "json-object", 2)
    assert rec.seq == 2  # seq 1 was burned by the failed parse
    kinds = [r["kind"] for r in op.audit_log()]
    assert kinds == ["rejected", "parser-registered"]
    assert op.audit_log()[0]["seq"] == 1


def test_audit_shapes():
    op = _fresh()
    op.parse("cfg", '{"name": "x"}', 4)
    op.validate("cfg", {"name": "x"}, 5)
    kinds = [r["kind"] for r in op.audit_log()]
    assert kinds == [
        "parser-registered", "parser-registered", "parser-registered",
        "parsed", "validated",
    ]
    for row in op.audit_log():
        assert row["schema"] == "audit.ndjson/1"
        assert row["module"] == "output-parser.v1"
    parsed = op.audit_log()[3]["detail"]
    assert parsed["success"] is True and parsed["error_code"] == ""
    with pytest.raises(AuditKindError):
        output_parser_audit_event("parsed", {"text": "raw!"}, 6)
    with pytest.raises(AuditKindError):
        output_parser_audit_event("parsed", {"spec": {}}, 6)
    with pytest.raises(AuditKindError):
        output_parser_audit_event("nope", {}, 6)
    with pytest.raises(SeqOrderError):
        output_parser_audit_event("parsed", {"parser_id": "x"}, -1)


def test_cross_instance_determinism():
    def _run():
        op = OutputParser()
        op.register("e", "enum", 1, {"allowed": ["x", "y"]})
        o1 = op.parse("e", "x", 2)
        o2 = op.parse("e", "z", 3)
        v = op.validate("e", "x", 4)
        s = op.schema("e", 5)
        return o1.digest, o2.digest, v.digest, s.digest

    assert _run() == _run()


def test_frozen_records():
    op = _fresh()
    rec = op.parser_record("cfg", 4)
    out = op.parse("cfg", '{"name": "x"}', 4)
    with pytest.raises(FrozenInstanceError):
        rec.seq = 99  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        out.success = False  # type: ignore[misc]


def test_spec_digest_pins():
    op = OutputParser()
    op.register("a", "enum", 1, {"allowed": ["x"]})
    op.register("b", "enum", 2, {"allowed": ["y"]})
    ra = op.schema("a", 3)
    rb = op.schema("b", 3)
    assert ra.spec_digest != rb.spec_digest  # digests separate by content
    assert ra.verify() and rb.verify()
    assert op.parser_record("a", 3).digest != op.parser_record("b", 3).digest


def test_main_subprocess():
    proc = subprocess.run(
        [sys.executable, str(COMP_DIR / "output_parser.py")],
        capture_output=True, text=True, cwd=str(COMP_DIR), timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == (
        "output-parser OK: register, parse, validate, schema, pins, audit"
    )
