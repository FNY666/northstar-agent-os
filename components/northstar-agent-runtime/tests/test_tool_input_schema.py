from __future__ import annotations

import unittest
from unittest.mock import patch

import tool_input_schema
from tool_input_schema import ToolInputSchemaError, validate_tool_input, validate_tool_schema


class ToolInputSchemaTests(unittest.TestCase):
    def test_provider_input_is_bounded_before_schema_validation(self):
        with self.assertRaisesRegex(ToolInputSchemaError, "tool input.*resource limit"):
            validate_tool_input({"value": "x" * 200_000}, {"type": "object"})

    def test_unicode_size_estimate_preserves_bmp_but_accounts_for_surrogate_pairs(self):
        self.assertLess(
            tool_input_schema.check_json_tree_budget("中" * 100_000),
            tool_input_schema.MAX_SCHEMA_TREE_BYTES,
        )
        with self.assertRaisesRegex(ToolInputSchemaError, "tool input.*resource limit"):
            tool_input_schema.check_json_tree_budget("😀" * 90_000)

    def test_schema_tree_node_count_is_bounded(self):
        schema = {"type": "object", "properties": {f"p{i}": {} for i in range(50_001)}}
        with patch.object(tool_input_schema, "MAX_SCHEMA_TREE_BYTES", 10_000_000):
            with self.assertRaisesRegex(ToolInputSchemaError, "tool schema.*node limit"):
                validate_tool_schema(schema)

    def test_shared_subtrees_are_counted_by_expanded_json_occurrences(self):
        value = "leaf"
        for _ in range(10):
            value = [value, value]
        with patch.object(tool_input_schema, "MAX_SCHEMA_TREE_NODES", 100):
            with self.assertRaisesRegex(ToolInputSchemaError, "tool input.*node limit"):
                tool_input_schema.check_json_tree_budget(value)

    def test_wide_container_is_rejected_before_children_are_scheduled(self):
        value = list(range(5_000))
        with patch.object(tool_input_schema, "MAX_SCHEMA_TREE_NODES", 100):
            with self.assertRaisesRegex(ToolInputSchemaError, "tool input.*node limit"):
                tool_input_schema.check_json_tree_budget(value)

    def test_json_text_node_scan_counts_values_without_counting_object_keys(self):
        text = '{"items": ["a\\\"b", 1, null]}'
        self.assertEqual(tool_input_schema.check_json_text_node_budget(text), 5)
        with patch.object(tool_input_schema, "MAX_SCHEMA_TREE_NODES", 4):
            with self.assertRaisesRegex(ToolInputSchemaError, "node limit"):
                tool_input_schema.check_json_text_node_budget(text)

    def test_json_text_node_scan_rejects_nesting_before_decoding(self):
        with patch.object(tool_input_schema, "MAX_SCHEMA_TREE_DEPTH", 2):
            with self.assertRaisesRegex(ToolInputSchemaError, "nesting limit"):
                tool_input_schema.check_json_text_node_budget("[[[0]]]")

    def test_mcp_schema_must_be_an_object_schema(self):
        validate_tool_schema({"type": "object", "properties": {}})
        with self.assertRaisesRegex(ToolInputSchemaError, "type must be 'object'"):
            validate_tool_schema({"type": "string"})

    def test_remote_refs_in_schema_positions_are_rejected_but_example_data_is_not_scanned(self):
        valid = {
            "type": "object",
            "properties": {"value": {"type": "string", "examples": [{"$ref": "https://example.invalid/data"}]}},
        }
        validate_tool_schema(valid)
        remote = {"type": "object", "properties": {"value": {"$ref": "https://example.invalid/data"}}}
        with self.assertRaisesRegex(ToolInputSchemaError, "remote JSON Schema references are disabled"):
            validate_tool_schema(remote)

    def test_object_contract_validates_required_types_bounds_and_extra_fields(self):
        schema = {
            "type": "object",
            "required": ["timeout_ms"],
            "properties": {"timeout_ms": {"type": "integer", "minimum": 1}},
            "additionalProperties": False,
        }
        validate_tool_input({"timeout_ms": 5}, schema)
        for payload in ({}, {"timeout_ms": True}, {"timeout_ms": 0}, {"timeout_ms": 1, "extra": 2}):
            with self.subTest(payload=payload), self.assertRaises(ToolInputSchemaError):
                validate_tool_input(payload, schema)

    def test_nested_array_and_enum_contracts(self):
        schema = {
            "type": "object",
            "properties": {
                "argv": {"type": "array", "minItems": 1, "items": {"type": "string"}},
                "mode": {"enum": ["read", "write"]},
            },
        }
        validate_tool_input({"argv": ["echo", "ok"], "mode": "read"}, schema)
        for payload in ({"argv": []}, {"argv": ["echo", 1]}, {"mode": "delete"}):
            with self.subTest(payload=payload), self.assertRaises(ToolInputSchemaError):
                validate_tool_input(payload, schema)

    def test_deep_input_is_refused_by_iterative_budget_check(self):
        value = "leaf"
        for _ in range(1_000):
            value = {"nested": value}
        with self.assertRaisesRegex(ToolInputSchemaError, "nesting limit"):
            validate_tool_input({"value": value}, {"type": "object"})

    def test_unsupported_assertion_keywords_fail_closed(self):
        with patch("tool_input_schema._jsonschema", None):
            with self.assertRaisesRegex(ToolInputSchemaError, "unsupported schema keyword"):
                validate_tool_input({"value": "x"}, {"type": "object", "properties": {"value": {"pattern": "x"}}})

    def test_malformed_schema_declarations_fail_closed_even_when_input_would_match(self):
        with self.assertRaisesRegex(ToolInputSchemaError, "invalid JSON Schema"):
            validate_tool_input({}, {"type": [["object"]]})

    def test_malformed_schema_dialect_fails_as_a_bounded_validation_error(self):
        for dialect in ([], {}, "https://example.invalid/schema"):
            with self.subTest(dialect=dialect), self.assertRaisesRegex(
                ToolInputSchemaError, "unsupported JSON Schema dialect"
            ):
                validate_tool_input({}, {"$schema": dialect, "type": "object"})

    def test_unique_items_uses_json_numeric_equality_but_keeps_booleans_distinct(self):
        schema = {"type": "object", "properties": {"values": {"type": "array", "uniqueItems": True}}}
        validate_tool_input({"values": [True, 1]}, schema)
        with self.assertRaisesRegex(ToolInputSchemaError, "unique"):
            validate_tool_input({"values": [1, 1.0]}, schema)

    def test_nested_enum_does_not_confuse_booleans_and_numbers(self):
        schema = {"properties": {"value": {"enum": [{"flag": True}]}}}
        validate_tool_input({"value": {"flag": True}}, schema)
        with self.assertRaises(ToolInputSchemaError):
            validate_tool_input({"value": {"flag": 1}}, schema)

    @unittest.skipIf(tool_input_schema._jsonschema is None, "install the json-schema extra")
    def test_draft_2020_local_refs_and_regex_are_supported(self):
        schema = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$defs": {"slug": {"type": "string", "pattern": "^[a-z]+$"}},
            "type": "object",
            "properties": {"name": {"$ref": "#/$defs/slug"}},
            "required": ["name"],
        }
        validate_tool_input({"name": "northstar"}, schema)
        with self.assertRaises(ToolInputSchemaError):
            validate_tool_input({"name": "not valid"}, schema)

    @unittest.skipIf(tool_input_schema._jsonschema is None, "install the json-schema extra")
    def test_remote_refs_are_never_resolved_over_network(self):
        schema = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$ref": "https://example.invalid/schema.json",
        }
        with self.assertRaisesRegex(ToolInputSchemaError, "remote JSON Schema references are disabled"):
            validate_tool_input({}, schema)

    @unittest.skipIf(tool_input_schema._jsonschema is None, "install the json-schema extra")
    def test_regex_backtracking_is_bounded(self):
        schema = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {"value": {"type": "string", "pattern": "^(a+)+$"}},
        }
        with self.assertRaises(ToolInputSchemaError):
            validate_tool_input({"value": "a" * 5000 + "!"}, schema)

    @unittest.skipIf(tool_input_schema._jsonschema is None, "install the json-schema extra")
    def test_regex_timeout_cannot_be_treated_as_a_failed_one_of_branch(self):
        schema = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {
                "value": {
                    "oneOf": [
                        {"type": "string", "pattern": "^(a+)+$"},
                        {"type": "string"},
                    ]
                }
            },
        }
        with self.assertRaisesRegex(ToolInputSchemaError, "timed out|time budget"):
            validate_tool_input({"value": "a" * 5000 + "!"}, schema)

    @unittest.skipIf(tool_input_schema._jsonschema is None, "install the json-schema extra")
    def test_pattern_properties_validate_matched_keys(self):
        schema = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "patternProperties": {"^x-": {"type": "integer"}},
        }
        validate_tool_input({"x-limit": 3, "other": "ok"}, schema)
        with self.assertRaises(ToolInputSchemaError):
            validate_tool_input({"x-limit": "3"}, schema)

    def test_composition_keywords_and_format_annotation(self):
        schema = {
            "type": "object",
            "properties": {
                "value": {
                    "format": "email",
                    "anyOf": [{"type": "string", "minLength": 3}, {"type": "integer"}],
                    "not": {"const": "bad"},
                }
            },
        }
        validate_tool_input({"value": "x@y"}, schema)
        validate_tool_input({"value": 5}, schema)
        for value in ("x", "bad", True):
            with self.subTest(value=value), self.assertRaises(ToolInputSchemaError):
                validate_tool_input({"value": value}, schema)

    def test_one_of_and_conditional_schemas(self):
        one_of = {"oneOf": [{"type": "integer"}, {"type": "number"}]}
        with self.assertRaisesRegex(ToolInputSchemaError, "oneOf"):
            validate_tool_input({"value": 4}, {"properties": {"value": one_of}})
        conditional = {
            "type": "object",
            "if": {"properties": {"mode": {"const": "strict"}}, "required": ["mode"]},
            "then": {"required": ["token"]},
            "else": {"required": ["note"]},
        }
        validate_tool_input({"mode": "strict", "token": "x"}, conditional)
        with self.assertRaisesRegex(ToolInputSchemaError, "required"):
            validate_tool_input({"mode": "strict"}, conditional)

    def test_non_json_hook_values_are_rejected_even_when_extra_fields_are_allowed(self):
        with self.assertRaisesRegex(ToolInputSchemaError, "JSON values"):
            validate_tool_input({"value": object()}, {"type": "object"})


if __name__ == "__main__":
    unittest.main()
