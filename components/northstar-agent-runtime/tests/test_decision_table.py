"""Tests for decision_table: DMN-shaped rule bookkeeping."""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

import decision_table
from decision_table import (
    AUDIT_SCHEMA,
    DECISION_TABLE_SCHEMA,
    DECISION_TABLE_VERSION,
    AuditKindError,
    BadInputError,
    BadRuleError,
    DecisionTable,
    DuplicateRuleError,
    SeqOrderError,
    UnknownRuleError,
    decision_table_audit_event,
)

THIS = Path(decision_table.__file__)
TESTS_DIR = Path(__file__).parent


def fresh() -> DecisionTable:
    return DecisionTable()


def add(table: DecisionTable, rule_id: str, conditions, output: str, seq: int):
    return table.add(rule_id, conditions, output, seq)


def test_version_and_schema_pins() -> None:
    assert DECISION_TABLE_VERSION == "decision-table.v1"
    assert DECISION_TABLE_SCHEMA == "northstar.decision-table.v1"
    assert AUDIT_SCHEMA == "audit.ndjson/1"


def test_stdlib_only() -> None:
    tree = ast.parse(THIS.read_text())
    allowed = {
        "hashlib", "threading", "dataclasses", "typing", "__future__",
        "json", "canonical_json", "pytest", "ast", "subprocess", "sys", "pathlib",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                assert node.module.split(".")[0] in allowed


def test_add_roundtrip_and_verify() -> None:
    table = fresh()
    record = add(table, "r1", (("age", ">=", 18),), "allow", 1)
    assert record.rule_id == "r1"
    assert record.conditions == (("age", ">=", 18),)
    assert record.output == "allow"
    assert record.output_digest.startswith("sha256:")
    assert record.verify() is True
    assert table.rule("r1") is record
    assert table.rule_ids() == ("r1",)
    view = table.rule_view("r1")
    assert view.rule_id == "r1"
    assert view.condition_count == 1
    assert view.output_digest == record.output_digest


def test_duplicate_add_refused_and_seq_burned() -> None:
    table = fresh()
    add(table, "r1", (), "x", 1)
    with pytest.raises(DuplicateRuleError):
        add(table, "r1", (), "y", 2)
    # failed mutation consumed seq 2: next add must use seq > 2
    with pytest.raises(SeqOrderError):
        add(table, "r2", (), "z", 2)
    record = add(table, "r2", (), "z", 3)
    assert record.rule_id == "r2"


def test_bad_rule_inputs_fail_closed() -> None:
    table = fresh()
    seq = 0
    bad = [
        (("", (("a", "==", 1),), "x")),          # empty id
        ((None, (("a", "==", 1),), "x")),        # non-str id
        (("r", (("a", "??", 1),), "x")),         # bad op
        (("r", (("a", "in", ()),), "x")),        # empty in-set
        (("r", (("a", "in", "ab"),), "x")),      # str is not a collection
        (("r", (("", "==", 1),), "x")),          # empty field
        (("r", (("a", "==", True),), "x")),      # bool rejected as number
        (("r", (("a", "==", float("nan")),), "x")),  # non-finite
        (("r", "not-a-list", "x")),              # conditions not a tuple/list
        (("r", (("a", "==", 1),), None)),        # None output
    ]
    for i, (rid, conds, out) in enumerate(bad, start=1):
        seq += 1
        with pytest.raises((BadRuleError, DuplicateRuleError)):
            table.add(rid, conds, out, seq)


def test_add_empty_conditions_is_catch_all() -> None:
    table = fresh()
    add(table, "fallback", (), "default", 1)
    assert table.hit({"anything": 1}).rule_id == "fallback"
    assert table.hit({}).rule_id == "fallback"


def test_hit_first_match_priority_order() -> None:
    table = fresh()
    add(table, "low", (("age", ">=", 0),), "low", 1)
    add(table, "high", (("age", ">=", 18),), "high", 2)
    assert table.hit({"age": 21}).rule_id == "low"  # add order wins
    report = table.evaluate({"age": 21}, 3)
    assert report.matched_rule_ids == ("low", "high")


def test_hit_no_match_returns_none() -> None:
    table = fresh()
    add(table, "r1", (("age", ">=", 18),), "allow", 1)
    assert table.hit({"age": 10}) is None
    assert table.hit({}) is None  # missing field: no-match as data
    with pytest.raises(BadInputError):
        table.hit("not-a-mapping")


def test_hit_is_pure_read() -> None:
    table = fresh()
    add(table, "r1", (("age", ">=", 18),), "allow", 1)
    assert table.hit({"age": 30}) is not None
    # no seq consumed: evaluate may still use seq 2
    report = table.evaluate({"age": 30}, 2)
    assert report.matched_rule_ids == ("r1",)
    kinds = [row["kind"] for row in table.audit_log()]
    assert kinds.count("decision-table.evaluated") == 1  # hit wrote no audit row


def test_operator_vocabulary() -> None:
    table = fresh()
    add(table, "r", (("n", "in", (1, 2, 3)), ("s", "!=", "x")), "hit", 1)
    assert table.hit({"n": 2, "s": "y"}) is not None
    assert table.hit({"n": 5, "s": "y"}) is None
    assert table.hit({"n": 2, "s": "x"}) is None
    table2 = fresh()
    table2.add("b", (("n", "not-in", (1, 2)),), "ok", 1)
    assert table2.hit({"n": 3}).rule_id == "b"
    assert table2.hit({"n": 1}) is None
    table3 = fresh()
    table3.add("lt", (("n", "<", 10), ("m", ">=", 5)), "ok", 1)
    assert table3.hit({"n": 3, "m": 5}) is not None
    assert table3.hit({"n": "str", "m": 5}) is None  # type mismatch: no-match, not raised
    assert table3.hit({"n": True, "m": 5}) is None  # bool is not a number


def test_evaluate_bad_inputs() -> None:
    table = fresh()
    add(table, "r1", (), "x", 1)
    with pytest.raises(BadInputError):
        table.evaluate(["not", "mapping"], 2)
    with pytest.raises(SeqOrderError):
        table.evaluate({}, 1)  # rewind
    with pytest.raises(SeqOrderError):
        table.evaluate({}, 0)
    report = table.evaluate({"k": "v"}, 3)
    assert report.matched_rule_ids == ("r1",)
    assert report.evaluated_rule_ids == ("r1",)
    assert report.seq == 3


def test_unknown_rule_lookup() -> None:
    table = fresh()
    with pytest.raises(UnknownRuleError):
        table.rule("nope")
    with pytest.raises(UnknownRuleError):
        table.rule_view("nope")


def test_audit_shapes_and_banned_keys() -> None:
    table = fresh()
    add(table, "r1", (("age", ">=", 18),), "allow", 1)
    table.evaluate({"age": 30}, 2)
    log = table.audit_log()
    kinds = {row["kind"] for row in log}
    assert "decision-table.rule-added" in kinds
    assert "decision-table.evaluated" in kinds
    for row in log:
        assert row["schema"] == "audit.ndjson/1"
        assert row["module"] == "decision-table.v1"
    for row in log:
        assert not (set(row["detail"]) & {"value", "payload", "inputs", "output", "condition"})
    with pytest.raises(AuditKindError):
        decision_table_audit_event("decision-table.rule-added", {"value": 1}, 3)
    with pytest.raises(AuditKindError):
        decision_table_audit_event("bogus-kind", {}, 3)


def test_stats_view() -> None:
    table = fresh()
    add(table, "a", (), "x", 1)
    add(table, "b", (("k", "==", 1),), "y", 2)
    table.evaluate({"k": 1}, 3)
    table.evaluate({"k": 2}, 4)
    stats = table.stats(5)
    assert stats.rule_count == 2
    assert stats.evaluation_count == 2
    assert stats.total_matches == 3  # catch-all a matches both, b matches once
    assert stats.seq == 5


def test_cross_instance_determinism() -> None:
    def build() -> DecisionTable:
        t = DecisionTable()
        t.add("r1", (("age", ">=", 18), ("tier", "in", ("gold", "silver"))), "allow", 1)
        return t

    a, b = build(), build()
    assert a.rule("r1").output_digest == b.rule("r1").output_digest
    assert a.hit({"age": 21, "tier": "gold"}).rule_id == b.hit({"age": 21, "tier": "gold"}).rule_id


def test_main_self_check() -> None:
    proc = subprocess.run(
        [sys.executable, str(THIS)],
        capture_output=True,
        text=True,
        cwd=str(TESTS_DIR.parent),
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.startswith("decision-table OK:")
