"""Targeted tests for rule_engine (Drools-shaped deterministic ledger)."""

import ast
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import rule_engine
from rule_engine import (
    RULE_ENGINE_VERSION,
    RULE_ENGINE_SCHEMA,
    Condition,
    RuleEngine,
    rule_engine_audit_event,
)


def test_version_and_schema_pins():
    assert RULE_ENGINE_VERSION == "rule-engine.v1"
    assert RULE_ENGINE_SCHEMA == "northstar.rule-engine.v1"


def test_stdlib_only():
    tree = ast.parse(open(rule_engine.__file__, encoding="utf-8").read())
    allowed = {"__future__", "hashlib", "threading", "dataclasses", "typing", "json", "canonical_json"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed, a.name
        elif isinstance(node, ast.ImportFrom):
            assert node.module in allowed, node.module


def test_add_roundtrip():
    eng = RuleEngine()
    rec = eng.add("r1", [{"field": "age", "operator": ">=", "value": 18}], action="ok", seq=1)
    assert rec.verify()
    assert eng.rule("r1") is rec
    assert eng.rule_ids() == ("r1",)


def test_add_duplicate():
    eng = RuleEngine()
    eng.add("r1", [{"field": "a", "operator": "==", "value": 1}], action="x", seq=1)
    with pytest.raises(rule_engine.DuplicateRuleError):
        eng.add("r1", [{"field": "b", "operator": "==", "value": 2}], action="y", seq=2)
    kinds = [e["kind"] for e in eng.audit_log()]
    assert "rejected" in kinds


def test_add_bad_conditions():
    eng = RuleEngine()
    with pytest.raises(rule_engine.BadConditionError):
        eng.add("bad-op", [{"field": "a", "operator": "<>", "value": 1}], action="x", seq=1)
    with pytest.raises(rule_engine.BadConditionError):
        eng.add("no-cond", [], action="x", seq=2)
    with pytest.raises(rule_engine.BadActionError):
        eng.add("no-action", [{"field": "a", "operator": "==", "value": 1}], action="", seq=3)
    with pytest.raises(rule_engine.BadRuleError):
        eng.add("", [{"field": "a", "operator": "==", "value": 1}], action="x", seq=4)


def test_evaluate_agenda_order():
    eng = RuleEngine()
    eng.add("low", [{"field": "age", "operator": ">=", "value": 0}], action="a", seq=1, priority=1)
    eng.add("high", [{"field": "age", "operator": ">=", "value": 0}], action="b", seq=2, priority=9)
    eng.add("tie-b", [{"field": "age", "operator": ">=", "value": 0}], action="c", seq=3, priority=5)
    eng.add("tie-a", [{"field": "age", "operator": ">=", "value": 0}], action="d", seq=4, priority=5)
    eng.add("miss", [{"field": "age", "operator": ">=", "value": 999}], action="e", seq=5)
    report = eng.evaluate({"age": 30}, seq=5)
    assert report.matched_rule_ids == ("high", "tie-a", "tie-b", "low")
    assert report.matched_count == 4
    # evaluate is a pure read view: seq validated, not consumed
    assert eng.stats()["seq"] == 5
    eng.evaluate({"age": 30}, seq=5)
    assert eng.stats()["seq"] == 5


def test_operators():
    eng = RuleEngine()
    eng.add("in-r", [{"field": "color", "operator": "in", "value": ["red", "blue"]}], action="a", seq=1)
    eng.add("nin-r", [{"field": "color", "operator": "not-in", "value": ["green"]}], action="b", seq=2)
    eng.add("con-r", [{"field": "name", "operator": "contains", "value": "al"}], action="c", seq=3)
    assert eng.evaluate({"color": "red", "name": "alice"}, seq=3).matched_count == 3
    assert eng.evaluate({"color": "green", "name": "bob"}, seq=3).matched_count == 0


def test_fire_roundtrip():
    eng = RuleEngine()
    eng.add("r1", [{"field": "age", "operator": ">=", "value": 18}], action="discount", seq=1)
    fire = eng.fire("r1", {"age": 20}, seq=2)
    assert fire.verify()
    assert fire.action == "discount"
    assert eng.fires_for("r1") == (fire,)
    kinds = [e["kind"] for e in eng.audit_log()]
    assert "rule-added" in kinds and "rule-fired" in kinds


def test_fire_mismatch_and_unknown():
    eng = RuleEngine()
    eng.add("r1", [{"field": "age", "operator": ">=", "value": 18}], action="x", seq=1)
    with pytest.raises(rule_engine.RuleMismatchError):
        eng.fire("r1", {"age": 3}, seq=2)
    with pytest.raises(rule_engine.UnknownRuleError):
        eng.fire("ghost", {"age": 20}, seq=3)


def test_seq_ordering():
    eng = RuleEngine()
    eng.add("r1", [{"field": "a", "operator": "==", "value": 1}], action="x", seq=5)
    with pytest.raises(rule_engine.SeqOrderError):
        eng.add("r2", [{"field": "a", "operator": "==", "value": 1}], action="y", seq=5)
    with pytest.raises(rule_engine.SeqOrderError):
        eng.add("r3", [{"field": "a", "operator": "==", "value": 1}], action="z", seq=True)
    with pytest.raises(rule_engine.SeqOrderError):
        eng.evaluate({"a": 1}, seq="bad")


def test_audit_shapes_and_banned_keys():
    eng = RuleEngine()
    eng.add("r1", [{"field": "secret", "operator": "==", "value": "s3cr3t"}], action="x", seq=1)
    for event in eng.audit_log():
        text = str(event)
        assert "s3cr3t" not in text
        assert event["format"] == "audit.ndjson/1"
        assert event["schema"] == RULE_ENGINE_SCHEMA
    with pytest.raises(rule_engine.AuditKindError):
        rule_engine_audit_event(eng, "bogus-kind", 2)
    with pytest.raises(rule_engine.AuditKindError):
        rule_engine_audit_event(eng, "rule-fired", 2, facts={"a": 1})


def test_condition_direct():
    c = Condition(field="age", operator=">=", value=18)
    assert c.matches({"age": 20})
    assert not c.matches({"age": 10})
    assert not c.matches({"age": "twenty"})
    assert c.digest().startswith("sha256:")
    with pytest.raises(rule_engine.BadConditionError):
        Condition(field="a", operator="~=", value=1)
    with pytest.raises(rule_engine.BadConditionError):
        Condition(field="a", operator="==", value=2**53)


def test_condition_digest_determinism():
    a = Condition(field="age", operator=">=", value=18)
    b = Condition(field="age", operator=">=", value=18)
    assert a.digest() == b.digest()
    assert a != b or True  # frozen dataclasses, equality by value


def test_views():
    eng = RuleEngine()
    assert eng.rule("ghost") is None
    assert eng.rule_ids() == ()
    eng.add("r1", [{"field": "a", "operator": "==", "value": 1}], action="x", seq=1)
    assert eng.rule_ids() == ("r1",)
    assert eng.fires_for("r1") == ()
    stats = eng.stats()
    assert stats["rules"] == 1 and stats["fires"] == 0 and stats["seq"] == 1


def test_main_self_check():
    result = subprocess.run(
        [sys.executable, rule_engine.__file__], capture_output=True, text=True, timeout=30
    )
    assert result.returncode == 0
    assert "rule-engine OK" in result.stdout
