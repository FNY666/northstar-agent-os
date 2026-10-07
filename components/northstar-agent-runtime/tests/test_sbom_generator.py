"""Tests for sbom_generator (unittest, house style)."""

import unittest

from sbom_generator import (
    SBOM_GENERATOR_SCHEMA,
    SBOM_GENERATOR_VERSION,
    SBOMDocument,
    SBOMGenerator,
    SBOMError,
    DuplicateComponentError,
    InvalidComponentError,
    InvalidLicenseError,
    SeqOrderError,
    UnknownComponentError,
    VerificationError,
    sbom_generator_audit_event,
    main,
)


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(SBOM_GENERATOR_VERSION, "sbom-generator.v1")

    def test_schema_pin(self):
        self.assertEqual(SBOM_GENERATOR_SCHEMA, "northstar.sbom-generator.v1")


class TestAdd(unittest.TestCase):
    def test_add_roundtrip(self):
        gen = SBOMGenerator()
        rec = gen.add("requests", "2.31.0", "Apache-2.0", seq=0)
        self.assertEqual(rec.name, "requests")
        self.assertEqual(rec.version, "2.31.0")
        self.assertTrue(rec.digest.startswith("sha256:"))
        self.assertEqual(gen.component("requests", "2.31.0"), rec)

    def test_add_idempotent_identical(self):
        gen = SBOMGenerator()
        first = gen.add("requests", "2.31.0", "Apache-2.0", seq=0)
        second = gen.add("requests", "2.31.0", "Apache-2.0", seq=1)
        self.assertEqual(first, second)
        self.assertEqual(gen.component_count(), 1)

    def test_add_conflicting_content_refused(self):
        gen = SBOMGenerator()
        gen.add("requests", "2.31.0", "Apache-2.0", seq=0)
        with self.assertRaises(DuplicateComponentError):
            gen.add("requests", "2.31.0", "MIT", seq=1)

    def test_add_empty_name(self):
        gen = SBOMGenerator()
        with self.assertRaises(SBOMError):
            gen.add("", "1.0", "MIT", seq=0)

    def test_add_bad_seq(self):
        gen = SBOMGenerator()
        with self.assertRaises(SBOMError):
            gen.add("x", "1.0", "MIT", seq=True)
        with self.assertRaises(SeqOrderError):
            gen.add("x", "1.0", "MIT", seq=0)
            gen.add("y", "1.0", "MIT", seq=0)

    def test_unknown_component(self):
        gen = SBOMGenerator()
        with self.assertRaises(UnknownComponentError):
            gen.component("nope", "1.0")

    def test_bad_purl(self):
        gen = SBOMGenerator()
        with self.assertRaises(InvalidComponentError):
            gen.add("x", "1.0", "MIT", seq=0, purl="not-a-purl")

    def test_purl_and_digest_roundtrip(self):
        gen = SBOMGenerator()
        rec = gen.add("x", "1.0", "MIT", seq=0, purl="pkg:pypi/x@1.0",
                      supplier="Acme", source_digest="sha256:" + "ab" * 32)
        self.assertEqual(rec.purl, "pkg:pypi/x@1.0")
        self.assertEqual(rec.supplier, "Acme")
        self.assertEqual(rec.source_digest, "sha256:" + "ab" * 32)


class TestLicenses(unittest.TestCase):
    def setUp(self):
        self.gen = SBOMGenerator()

    def test_plain_id_ok(self):
        self.gen.add("a", "1.0", "MIT", seq=0)

    def test_expression_ok(self):
        self.gen.add("a", "1.0", "Apache-2.0 OR MIT", seq=0)
        self.gen.add("b", "1.0", "(GPL-3.0-only AND LGPL-2.1-or-later) WITH Classpath-exception-2.0", seq=1)

    def test_licenseref_ok(self):
        self.gen.add("a", "1.0", "LicenseRef-Proprietary", seq=0)

    def test_noassertion_ok(self):
        self.gen.add("a", "1.0", "NOASSERTION", seq=0)

    def test_misspelled_refused(self):
        with self.assertRaises(InvalidLicenseError):
            self.gen.add("a", "1.0", "MITT", seq=0)

    def test_unknown_operator_refused(self):
        with self.assertRaises(InvalidLicenseError):
            self.gen.add("a", "1.0", "MIT XOR Apache-2.0", seq=0)

    def test_unbalanced_parens_refused(self):
        with self.assertRaises(InvalidLicenseError):
            self.gen.add("a", "1.0", "(MIT OR Apache-2.0", seq=0)

    def test_dangling_operator_refused(self):
        with self.assertRaises(InvalidLicenseError):
            self.gen.add("a", "1.0", "MIT OR", seq=0)

    def test_missing_operator_refused(self):
        with self.assertRaises(InvalidLicenseError):
            self.gen.add("a", "1.0", "MIT Apache-2.0", seq=0)


class TestGenerate(unittest.TestCase):
    def _gen(self):
        gen = SBOMGenerator("my-doc")
        gen.add("urllib3", "2.2.3", "MIT", seq=0)
        gen.add("requests", "2.31.0", "Apache-2.0", seq=1)
        return gen

    def test_generate_spdx(self):
        doc = self._gen().generate(format="spdx-json", seq=2)
        self.assertIsInstance(doc, SBOMDocument)
        self.assertEqual(doc.component_count, 2)
        self.assertEqual(doc.body["spdxVersion"], "SPDX-2.3")
        self.assertEqual(doc.body["dataLicense"], "CC0-1.0")
        names = [p["name"] for p in doc.body["packages"]]
        self.assertEqual(names, ["requests", "urllib3"])  # sorted
        self.assertTrue(doc.digest.startswith("sha256:"))

    def test_generate_cyclonedx(self):
        doc = self._gen().generate(format="cyclonedx-json", seq=2)
        self.assertEqual(doc.body["bomFormat"], "CycloneDX")
        self.assertEqual(doc.body["specVersion"], "1.5")
        exprs = [c["licenses"][0]["expression"] for c in doc.body["components"]]
        self.assertEqual(exprs, ["Apache-2.0", "MIT"])  # sorted by (name, version)

    def test_generate_deterministic(self):
        doc1 = self._gen().generate(format="spdx-json", seq=2)
        doc2 = self._gen().generate(format="spdx-json", seq=2)
        self.assertEqual(doc1.digest, doc2.digest)

    def test_generate_empty_registry_refused(self):
        with self.assertRaises(SBOMError):
            SBOMGenerator().generate(format="spdx-json", seq=0)

    def test_generate_unknown_format_refused(self):
        with self.assertRaises(SBOMError):
            self._gen().generate(format="yaml", seq=2)


class TestVerify(unittest.TestCase):
    def test_verify_happy_path(self):
        gen = SBOMGenerator()
        gen.add("requests", "2.31.0", "Apache-2.0", seq=0)
        doc = gen.generate(format="spdx-json", seq=1)
        report = gen.verify(doc, seq=2)
        self.assertTrue(report.overall_ok)
        self.assertTrue(report.digest_matches)
        self.assertTrue(report.required_fields_ok)
        self.assertTrue(report.licenses_ok)
        self.assertTrue(report.components_match_registry)
        self.assertEqual(report.issues, ())

    def test_verify_tamper_detected(self):
        gen = SBOMGenerator()
        gen.add("requests", "2.31.0", "Apache-2.0", seq=0)
        doc = gen.generate(format="spdx-json", seq=1)
        tampered_body = dict(doc.body)
        tampered_body["name"] = "evil-doc"
        tampered = SBOMDocument(format=doc.format, document_name=doc.document_name,
                                serial=doc.serial, body=tampered_body,
                                component_count=doc.component_count,
                                digest=doc.digest, seq=doc.seq)
        report = gen.verify(tampered, seq=2)
        self.assertFalse(report.overall_ok)
        self.assertFalse(report.digest_matches)
        self.assertTrue(any("tampered" in i for i in report.issues))

    def test_verify_registry_mismatch(self):
        gen = SBOMGenerator()
        gen.add("requests", "2.31.0", "Apache-2.0", seq=0)
        doc = gen.generate(format="spdx-json", seq=1)
        gen.add("urllib3", "2.2.3", "MIT", seq=2)  # registry changed after gen
        report = gen.verify(doc, seq=3)
        self.assertFalse(report.components_match_registry)
        self.assertFalse(report.overall_ok)

    def test_verify_wrong_type(self):
        gen = SBOMGenerator()
        with self.assertRaises(VerificationError):
            gen.verify("not-a-doc", seq=0)


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        for kind in ("component-added", "component-duplicate", "sbom-generated",
                     "sbom-verified", "sbom-verification-failed"):
            ev = sbom_generator_audit_event(kind, seq=0, name="x")
            self.assertEqual(ev["schema"], "audit.ndjson/1")
            self.assertEqual(ev["kind"], kind)

    def test_audit_bad_kind(self):
        with self.assertRaises(SBOMError):
            sbom_generator_audit_event("explode", seq=0)


class TestStdlibOnly(unittest.TestCase):
    def test_stdlib_only(self):
        import ast
        from pathlib import Path
        path = Path(__file__).resolve().parent.parent / "sbom_generator.py"
        tree = ast.parse(path.read_text())
        allowed = {"__future__", "hashlib", "json", "re", "threading",
                   "dataclasses", "typing"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn(node.module.split(".")[0], allowed)


class TestMain(unittest.TestCase):
    def test_main(self):
        main()


if __name__ == "__main__":
    unittest.main()
