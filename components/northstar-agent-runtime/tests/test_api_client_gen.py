"""Tests for api_client_gen: OpenAPI-shaped client generation bookkeeping."""

from __future__ import annotations

import ast
import json
import unittest
from pathlib import Path

from api_client_gen import (
    API_CLIENT_GEN_SCHEMA,
    API_CLIENT_GEN_VERSION,
    APIClientGen,
    APIClientGenError,
    BadSpecError,
    DuplicateOperationError,
    SeqOrderError,
    UnknownLanguageError,
    UnknownSpecError,
    ValidationError,
    api_client_gen_audit_event,
    main,
)


def _demo_spec() -> str:
    return json.dumps(
        {
            "openapi": "3.0.0",
            "info": {"title": "Pet Store", "version": "2.1.0"},
            "paths": {
                "/pets/{petId}": {
                    "get": {
                        "operationId": "getPet",
                        "summary": "Fetch a pet",
                        "parameters": [
                            {
                                "name": "petId",
                                "in": "path",
                                "required": True,
                                "schema": {"type": "string"},
                            }
                        ],
                        "responses": {"200": {"description": "ok"}},
                    },
                    "delete": {
                        "operationId": "deletePet",
                        "parameters": [
                            {
                                "name": "petId",
                                "in": "path",
                                "required": True,
                                "schema": {"type": "string"},
                            }
                        ],
                        "responses": {"204": {"description": "gone"}},
                    },
                }
            },
        }
    )


class TestPins(unittest.TestCase):
    def test_version_pins(self):
        self.assertEqual(API_CLIENT_GEN_VERSION, "api-client-gen.v1")
        self.assertEqual(API_CLIENT_GEN_SCHEMA, "northstar.api-client-gen.v1")


class TestParse(unittest.TestCase):
    def test_parse_roundtrip(self):
        g = APIClientGen()
        spec = g.parse(_demo_spec(), 0)
        self.assertTrue(spec.pin.startswith("sha256:"))
        self.assertEqual(spec.title, "Pet Store")
        self.assertEqual(spec.spec_version, "2.1.0")
        self.assertEqual(len(spec.operations), 2)
        self.assertEqual(spec.operations[0].method, "delete")
        self.assertEqual(spec.operations[0].operation_id, "deletePet")
        self.assertEqual(g.spec_ids(), (spec.spec_id,))

    def test_bad_json_refused(self):
        g = APIClientGen()
        with self.assertRaises(BadSpecError):
            g.parse("{not json", 0)

    def test_missing_paths_refused(self):
        g = APIClientGen()
        doc = json.dumps({"openapi": "3.0.0", "info": {"title": "T", "version": "1"}})
        with self.assertRaises(BadSpecError):
            g.parse(doc, 0)

    def test_duplicate_operation_id_refused(self):
        g = APIClientGen()
        doc = {
            "openapi": "3.0.0",
            "info": {"title": "T", "version": "1"},
            "paths": {
                "/a": {"get": {"operationId": "same", "responses": {}}},
                "/b": {"get": {"operationId": "same", "responses": {}}},
            },
        }
        with self.assertRaises(DuplicateOperationError):
            g.parse(json.dumps(doc), 0)

    def test_unknown_method_refused(self):
        g = APIClientGen()
        doc = {
            "openapi": "3.0.0",
            "info": {"title": "T", "version": "1"},
            "paths": {"/a": {"frobnicate": {"operationId": "x", "responses": {}}}},
        }
        with self.assertRaises(BadSpecError):
            g.parse(json.dumps(doc), 0)

    def test_seq_order_enforced(self):
        g = APIClientGen()
        g.parse(_demo_spec(), 0)
        with self.assertRaises(SeqOrderError):
            g.parse(_demo_spec(), 0)
        with self.assertRaises(APIClientGenError):
            g.parse(_demo_spec(), True)

    def test_failed_parse_consumes_seq(self):
        g = APIClientGen()
        with self.assertRaises(BadSpecError):
            g.parse("{bad", 0)
        # seq 0 is now consumed: a fresh valid spec needs seq 1
        spec = g.parse(_demo_spec(), 1)
        self.assertEqual(spec.spec_id, "spec-1")


class TestGenerate(unittest.TestCase):
    def test_generate_all_languages(self):
        g = APIClientGen()
        spec = g.parse(_demo_spec(), 0)
        for i, (lang, fname) in enumerate(
            [("python", "client.py"), ("typescript", "client.ts"), ("shell", "client.sh")]
        ):
            bundle = g.generate(spec.spec_id, lang, i + 1)
            self.assertEqual(bundle.file_name, fname)
            self.assertTrue(bundle.verify())
            self.assertIn("get_pet" if lang != "typescript" else "getPet", bundle.code)

    def test_generated_code_mentions_operations(self):
        g = APIClientGen()
        spec = g.parse(_demo_spec(), 0)
        bundle = g.generate(spec.spec_id, "python", 1)
        self.assertIn("def get_pet(self, petId):", bundle.code)
        self.assertIn("def delete_pet(self, petId):", bundle.code)
        self.assertIn("requests.delete", bundle.code)

    def test_deterministic_across_instances(self):
        g1, g2 = APIClientGen(), APIClientGen()
        s1, s2 = g1.parse(_demo_spec(), 0), g2.parse(_demo_spec(), 0)
        b1 = g1.generate(s1.spec_id, "python", 1)
        b2 = g2.generate(s2.spec_id, "python", 1)
        self.assertEqual(b1.code, b2.code)

    def test_unknown_language_refused(self):
        g = APIClientGen()
        spec = g.parse(_demo_spec(), 0)
        with self.assertRaises(UnknownLanguageError):
            g.generate(spec.spec_id, "cobol", 1)

    def test_unknown_spec_refused(self):
        g = APIClientGen()
        with self.assertRaises(UnknownSpecError):
            g.generate("spec-999", "python", 0)


class TestValidate(unittest.TestCase):
    def test_validate_clean(self):
        g = APIClientGen()
        spec = g.parse(_demo_spec(), 0)
        report = g.validate(spec.spec_id, 1)
        self.assertTrue(report.valid)
        self.assertTrue(report.verify())
        self.assertEqual(report.findings, ())

    def test_validate_path_param_undeclared(self):
        g = APIClientGen()
        doc = {
            "openapi": "3.0.0",
            "info": {"title": "T", "version": "1"},
            "paths": {
                "/pets/{petId}": {
                    "get": {"operationId": "x", "responses": {}, "parameters": []}
                }
            },
        }
        spec = g.parse(json.dumps(doc), 0)
        report = g.validate(spec.spec_id, 1)
        self.assertFalse(report.valid)
        rules = {f.rule for f in report.findings}
        self.assertIn("path-param-undeclared", rules)

    def test_validate_is_read_only(self):
        g = APIClientGen()
        spec = g.parse(_demo_spec(), 0)
        g.validate(spec.spec_id, 5)
        # validate did not consume the mutation seq: 6 still < 5 is invalid, 6 works
        spec2 = g.parse(_demo_spec(), 6)
        self.assertEqual(spec2.spec_id, "spec-2")


class TestAudit(unittest.TestCase):
    def test_audit_shape_and_bad_kind(self):
        ev = api_client_gen_audit_event("spec-parsed", 3, spec_id="spec-1")
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        self.assertEqual(ev["audit_seq"], 3)
        with self.assertRaises(APIClientGenError):
            api_client_gen_audit_event("bogus-kind", 0)

    def test_audit_bans_spec_text_and_code(self):
        with self.assertRaises(APIClientGenError):
            api_client_gen_audit_event("client-generated", 1, code="print(1)")
        with self.assertRaises(APIClientGenError):
            api_client_gen_audit_event("spec-parsed", 1, spec_text="{}")


class TestStdlibOnly(unittest.TestCase):
    def test_stdlib_only(self):
        src = Path(__file__).parent.parent.joinpath("api_client_gen.py").read_text()
        tree = ast.parse(src)
        allowed = {
            "hashlib",
            "json",
            "re",
            "threading",
            "dataclasses",
            "typing",
            "__future__",
            "canonical_json",  # the standard guarded canonicalizer import
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed)


class TestMain(unittest.TestCase):
    def test_main(self):
        main()


if __name__ == "__main__":
    unittest.main()
