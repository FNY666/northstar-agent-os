"""Tests for mcp_semantic_diff: semantic schema comparison, not hash equality."""
from __future__ import annotations

import unittest

import mcp_semantic_diff as msd
from mcp_semantic_diff import (
    MCP_SEMANTIC_DIFF_VERSION,
    ParsedSchema,
    SchemaField,
    SemanticChange,
    SemanticChangeKind,
    SemanticRiskAssessment,
    assess_semantic_risk,
    check_schema_drift,
    is_sensitive_tool,
    parse_schema,
    semantic_diff,
)


def _schema(props, required=()):
    return {"type": "object", "properties": props, "required": list(required)}


class VersionPinTests(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(MCP_SEMANTIC_DIFF_VERSION, "mcp-semantic-diff.v1")

    def test_parsed_schema_carries_version(self):
        self.assertEqual(parse_schema(None).version, MCP_SEMANTIC_DIFF_VERSION)


class ParseSchemaTests(unittest.TestCase):
    def test_none_schema_parses_empty(self):
        self.assertEqual(parse_schema(None).fields, ())

    def test_missing_properties_parses_empty(self):
        self.assertEqual(parse_schema({"type": "object"}).fields, ())

    def test_non_mapping_raises(self):
        with self.assertRaises(ValueError):
            parse_schema("not-a-schema")

    def test_non_mapping_properties_raises(self):
        with self.assertRaises(ValueError):
            parse_schema({"properties": ["x"]})

    def test_required_fields_extracted(self):
        p = parse_schema(_schema({"a": {"type": "string"},
                                  "b": {"type": "integer"}}, required=["a"]))
        m = p.field_map()
        self.assertTrue(m["a"].required)
        self.assertFalse(m["b"].required)

    def test_types_extracted(self):
        p = parse_schema(_schema({"s": {"type": "string"}, "i": {"type": "integer"}}))
        self.assertEqual(p.field_map()["s"].type, "string")
        self.assertEqual(p.field_map()["i"].type, "integer")

    def test_unknown_type_normalizes_to_any(self):
        p = parse_schema(_schema({"x": {"type": "weird"}}))
        self.assertEqual(p.field_map()["x"].type, "any")

    def test_constraints_extracted(self):
        p = parse_schema(_schema({"s": {"type": "string", "minLength": 2,
                                        "maxLength": 10}}))
        cmap = p.field_map()["s"].constraint_map()
        self.assertIn("minLength", cmap)
        self.assertIn("maxLength", cmap)

    def test_fields_sorted_deterministically(self):
        p = parse_schema(_schema({"z": {"type": "string"}, "a": {"type": "string"}}))
        self.assertEqual([f.name for f in p.fields], ["a", "z"])

    def test_frozen_dataclasses(self):
        f = SchemaField(name="x", type="string", required=False)
        with self.assertRaises(AttributeError):
            f.name = "y"  # type: ignore


class SemanticDiffTests(unittest.TestCase):
    def test_identical_schemas_no_change(self):
        s = _schema({"a": {"type": "string"}}, required=["a"])
        self.assertEqual(semantic_diff(s, s), [])

    def test_optional_field_added_non_breaking(self):
        old = _schema({"a": {"type": "string"}}, required=["a"])
        new = _schema({"a": {"type": "string"}, "b": {"type": "integer"}},
                      required=["a"])
        changes = semantic_diff(old, new)
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].kind, SemanticChangeKind.FIELD_ADDED)
        self.assertFalse(changes[0].breaking)

    def test_required_field_added_breaking(self):
        old = _schema({"a": {"type": "string"}}, required=["a"])
        new = _schema({"a": {"type": "string"}, "b": {"type": "integer"}},
                      required=["a", "b"])
        changes = semantic_diff(old, new)
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].kind, SemanticChangeKind.FIELD_ADDED)
        self.assertTrue(changes[0].breaking)

    def test_field_removed_breaking(self):
        old = _schema({"a": {"type": "string"}, "b": {"type": "integer"}},
                      required=["a"])
        new = _schema({"a": {"type": "string"}}, required=["a"])
        changes = semantic_diff(old, new)
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].kind, SemanticChangeKind.FIELD_REMOVED)
        self.assertTrue(changes[0].breaking)

    def test_type_narrowed(self):
        old = _schema({"x": {}})
        new = _schema({"x": {"type": "string"}})
        changes = semantic_diff(old, new)
        kinds = [c.kind for c in changes]
        self.assertIn(SemanticChangeKind.TYPE_NARROWED, kinds)

    def test_type_widened(self):
        old = _schema({"x": {"type": "string"}})
        new = _schema({"x": {}})
        changes = semantic_diff(old, new)
        kinds = [c.kind for c in changes]
        self.assertIn(SemanticChangeKind.TYPE_WIDENED, kinds)

    def test_integer_to_number_widened(self):
        old = _schema({"n": {"type": "integer"}})
        new = _schema({"n": {"type": "number"}})
        kinds = [c.kind for c in semantic_diff(old, new)]
        self.assertIn(SemanticChangeKind.TYPE_WIDENED, kinds)

    def test_incomparable_type_swap_is_narrowed(self):
        old = _schema({"x": {"type": "string"}})
        new = _schema({"x": {"type": "boolean"}})
        kinds = [c.kind for c in semantic_diff(old, new)]
        self.assertIn(SemanticChangeKind.TYPE_NARROWED, kinds)

    def test_constraint_tightened(self):
        old = _schema({"s": {"type": "string", "minLength": 1}})
        new = _schema({"s": {"type": "string", "minLength": 5}})
        changes = semantic_diff(old, new)
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].kind, SemanticChangeKind.CONSTRAINT_TIGHTENED)
        self.assertTrue(changes[0].breaking)

    def test_constraint_loosened(self):
        old = _schema({"s": {"type": "string", "minLength": 5}})
        new = _schema({"s": {"type": "string", "minLength": 1}})
        changes = semantic_diff(old, new)
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0].kind, SemanticChangeKind.CONSTRAINT_LOOSENED)
        self.assertFalse(changes[0].breaking)

    def test_maxlength_decrease_tightens(self):
        old = _schema({"s": {"type": "string", "maxLength": 100}})
        new = _schema({"s": {"type": "string", "maxLength": 10}})
        kinds = [c.kind for c in semantic_diff(old, new)]
        self.assertIn(SemanticChangeKind.CONSTRAINT_TIGHTENED, kinds)

    def test_enum_shrink_tightens(self):
        old = _schema({"c": {"type": "string", "enum": ["a", "b", "c"]}})
        new = _schema({"c": {"type": "string", "enum": ["a"]}})
        kinds = [c.kind for c in semantic_diff(old, new)]
        self.assertIn(SemanticChangeKind.CONSTRAINT_TIGHTENED, kinds)

    def test_enum_grow_loosens(self):
        old = _schema({"c": {"type": "string", "enum": ["a"]}})
        new = _schema({"c": {"type": "string", "enum": ["a", "b"]}})
        kinds = [c.kind for c in semantic_diff(old, new)]
        self.assertIn(SemanticChangeKind.CONSTRAINT_LOOSENED, kinds)

    def test_requiredness_change(self):
        old = _schema({"a": {"type": "string"}}, required=[])
        new = _schema({"a": {"type": "string"}}, required=["a"])
        kinds = [c.kind for c in semantic_diff(old, new)]
        self.assertIn(SemanticChangeKind.CONSTRAINT_TIGHTENED, kinds)

    def test_changes_carry_field_and_detail(self):
        old = _schema({"a": {"type": "string"}})
        new = _schema({})
        (ch,) = semantic_diff(old, new)
        self.assertEqual(ch.field, "a")
        self.assertTrue(ch.detail)


class AssessRiskTests(unittest.TestCase):
    def test_empty_changes_allow(self):
        r = assess_semantic_risk([])
        self.assertEqual(r.verdict, "allow")

    def test_field_removed_always_deny(self):
        ch = [SemanticChange(SemanticChangeKind.FIELD_REMOVED, "x",
                             "removed", True)]
        self.assertEqual(assess_semantic_risk(ch, is_sensitive=False).verdict, "deny")
        self.assertEqual(assess_semantic_risk(ch, is_sensitive=True).verdict, "deny")

    def test_narrowed_on_sensitive_deny(self):
        ch = [SemanticChange(SemanticChangeKind.TYPE_NARROWED, "cmd",
                             "any -> string", True)]
        self.assertEqual(assess_semantic_risk(ch, is_sensitive=True).verdict, "deny")

    def test_narrowed_on_nonsensitive_allow(self):
        ch = [SemanticChange(SemanticChangeKind.TYPE_NARROWED, "cmd",
                             "any -> string", True)]
        r = assess_semantic_risk(ch, is_sensitive=False)
        self.assertEqual(r.verdict, "allow")

    def test_tightened_on_sensitive_deny(self):
        ch = [SemanticChange(SemanticChangeKind.CONSTRAINT_TIGHTENED, "path",
                             "minLength 1 -> 5", True)]
        self.assertEqual(assess_semantic_risk(ch, is_sensitive=True).verdict, "deny")

    def test_widened_allow_even_sensitive(self):
        ch = [SemanticChange(SemanticChangeKind.TYPE_WIDENED, "q",
                             "string -> any", False)]
        r = assess_semantic_risk(ch, is_sensitive=True)
        self.assertEqual(r.verdict, "allow")

    def test_changes_carried_on_allow(self):
        ch = [SemanticChange(SemanticChangeKind.FIELD_ADDED, "opt",
                             "added (optional)", False)]
        r = assess_semantic_risk(ch)
        self.assertEqual(r.changes, tuple(ch))

    def test_reasons_nonempty_on_deny(self):
        ch = [SemanticChange(SemanticChangeKind.FIELD_REMOVED, "x",
                             "removed", True)]
        r = assess_semantic_risk(ch)
        self.assertTrue(r.reasons)

    def test_malformed_changes_rejected(self):
        with self.assertRaises(ValueError):
            assess_semantic_risk("not-a-list")  # type: ignore
        with self.assertRaises(ValueError):
            assess_semantic_risk([{"kind": "x"}])  # type: ignore

    def test_nonbool_sensitive_rejected(self):
        with self.assertRaises(ValueError):
            assess_semantic_risk([], is_sensitive="yes")  # type: ignore

    def test_assessment_frozen(self):
        r = assess_semantic_risk([])
        self.assertIsInstance(r, SemanticRiskAssessment)
        with self.assertRaises(AttributeError):
            r.verdict = "deny"  # type: ignore


class SensitiveToolTests(unittest.TestCase):
    def test_sensitive_substrings(self):
        for name in ("exec_command", "shell_run", "read_file", "network_fetch",
                     "EXEC", "FileManager"):
            self.assertTrue(is_sensitive_tool(name), name)

    def test_nonsensitive(self):
        for name in ("get_weather", "summarize", "translate"):
            self.assertFalse(is_sensitive_tool(name), name)

    def test_nonstring_not_sensitive(self):
        self.assertFalse(is_sensitive_tool(None))
        self.assertFalse(is_sensitive_tool(42))


class EndToEndTests(unittest.TestCase):
    def test_check_schema_drift_allow(self):
        old = _schema({"a": {"type": "string"}}, required=["a"])
        new = _schema({"a": {"type": "string"}, "b": {"type": "string"}},
                      required=["a"])
        r = check_schema_drift(old, new)
        self.assertEqual(r.verdict, "allow")

    def test_check_schema_drift_sensitive_deny(self):
        old = _schema({"cmd": {"type": "string"}})
        new = _schema({"cmd": {"type": "string", "minLength": 10}})
        r = check_schema_drift(old, new, is_sensitive=True)
        self.assertEqual(r.verdict, "deny")

    def test_none_schemas_no_drift(self):
        r = check_schema_drift(None, None)
        self.assertEqual(r.verdict, "allow")
        self.assertEqual(r.changes, ())


if __name__ == "__main__":
    unittest.main()
