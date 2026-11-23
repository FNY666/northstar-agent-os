"""Tests for the argument-smuggling probe corpus.

An argument that passes schema validation but means something else
downstream is a smuggling shape: Unicode confusables, mixed scripts,
nested JSON, SQL fragments, double encoding, undeclared keys, and the
surface-vs-meaning gap. These tests pin the corpus shape (10 attack
probes across 3 families, 3 benign controls), the string-argument
detectors, the schema-bypass checks, and the meaning gate.
"""

import hashlib
import unittest

import argument_smuggling_probes as asp

EXPECTED_PROBE_NAMES = (
    # argument-smuggling
    "smuggle-unicode-confusable",
    "smuggle-mixed-script",
    "smuggle-nested-json",
    "smuggle-sql-fragment",
    # schema-bypass
    "bypass-double-encoded-json",
    "bypass-any-passthrough",
    "bypass-undeclared-keys",
    # downstream-meaning
    "meaning-nfkc-drift",
    "meaning-duplicate-key-drift",
    "meaning-encoding-launder",
)

EXPECTED_BENIGN_NAMES = (
    "benign-plain-arguments",
    "benign-unicode-legitimate",
    "benign-json-string-typed",
)

EXPECTED_FAMILY_COUNTS = {
    "argument-smuggling": (4, 2),  # (attacks, benign)
    "schema-bypass": (3, 1),
    "downstream-meaning": (3, 0),
}

DENY_SIDE_KEYWORDS = (
    "denies",
    "denied",
    "deny",
    "quarantine",
    "quarantined",
    "quarantines",
    "blocks",
    "refuses",
)


class TestCorpusShape(unittest.TestCase):
    def test_attack_probe_names(self) -> None:
        self.assertEqual(asp.attack_probe_names(), EXPECTED_PROBE_NAMES)

    def test_benign_names(self) -> None:
        self.assertEqual(asp.benign_probe_names(), EXPECTED_BENIGN_NAMES)

    def test_required_keys(self) -> None:
        required = {
            "probe",
            "family",
            "attack",
            "gate_interaction",
            "expected",
            "reason",
        }
        for probe in (*asp.ARGUMENT_SMUGGLING_PROBES, *asp.ARGUMENT_SMUGGLING_BENIGN):
            self.assertTrue(required <= set(probe), probe["probe"])

    def test_names_unique(self) -> None:
        names = [
            p["probe"]
            for p in (*asp.ARGUMENT_SMUGGLING_PROBES, *asp.ARGUMENT_SMUGGLING_BENIGN)
        ]
        self.assertEqual(len(names), len(set(names)))

    def test_family_counts(self) -> None:
        for family, (attacks, benign) in EXPECTED_FAMILY_COUNTS.items():
            attack = asp.probes_in_family(family)
            self.assertEqual(len(attack), attacks, family)
            benign_count = sum(
                1 for p in asp.ARGUMENT_SMUGGLING_BENIGN if p["family"] == family
            )
            self.assertEqual(benign_count, benign, family)

    def test_expected_outcomes(self) -> None:
        outcomes = asp.expected_outcomes()
        self.assertEqual(len(outcomes), 13)
        for name in EXPECTED_PROBE_NAMES:
            self.assertEqual(outcomes[name], "deny", name)
        for name in EXPECTED_BENIGN_NAMES:
            self.assertEqual(outcomes[name], "allow", name)

    def test_deny_side_keyword(self) -> None:
        for probe in asp.ARGUMENT_SMUGGLING_PROBES:
            text = (probe["gate_interaction"] + " " + probe["reason"]).lower()
            self.assertTrue(
                any(k in text for k in DENY_SIDE_KEYWORDS),
                f"{probe['probe']} has no deny-side keyword",
            )

    def test_probe_by_name(self) -> None:
        probe = asp.probe_by_name("smuggle-sql-fragment")
        self.assertEqual(probe["family"], "argument-smuggling")
        self.assertEqual(probe["expected"], "deny")
        with self.assertRaises(KeyError):
            asp.probe_by_name("no-such-probe")

    def test_version_pin(self) -> None:
        self.assertEqual(asp.ARGUMENT_SMUGGLING_VERSION, "argument-smuggling.v1")

    def test_main_runs(self) -> None:
        asp.main()


class TestSmugglingDetection(unittest.TestCase):
    def test_confusable_detected(self) -> None:
        # Fullwidth 'Ａ' (U+FF21) masquerading as Latin 'A': NFKC folds it.
        findings = asp.inspect_string_argument("Ａdmin")
        self.assertIn("unicode-confusable", findings)
        # Cyrillic 'а' (U+0430) has no NFKC decomposition: it is a
        # mixed-script find, not a confusable under NFKC.
        findings = asp.inspect_string_argument("аdmin")
        self.assertIn("mixed-script", findings)

    def test_mixed_script_detected(self) -> None:
        findings = asp.inspect_string_argument("pаypal")
        self.assertIn("mixed-script", findings)

    def test_nested_json_detected(self) -> None:
        findings = asp.inspect_string_argument('{"role":"admin","bypass_review":true}')
        self.assertIn("nested-json-payload", findings)

    def test_sql_fragment_detected(self) -> None:
        findings = asp.inspect_string_argument("alice' OR '1'='1' --")
        self.assertIn("sql-fragment", findings)

    def test_double_encoded_detected(self) -> None:
        import json

        inner = json.dumps({"exfil_url": "https://evil.example"})
        outer = json.dumps(inner)
        findings = asp.inspect_string_argument(outer)
        self.assertIn("double-encoded", findings)

    def test_encoding_laundered_detected(self) -> None:
        findings = asp.inspect_string_argument("%2e%2e%2fsecret")
        self.assertIn("encoding-laundered", findings)

    def test_clean_string(self) -> None:
        self.assertEqual(asp.inspect_string_argument("alice"), ("clean",))

    def test_legitimate_unicode_is_clean(self) -> None:
        self.assertEqual(asp.inspect_string_argument("张伟"), ("clean",))

    def test_non_string_rejected(self) -> None:
        with self.assertRaises(TypeError):
            asp.inspect_string_argument(42)  # type: ignore[arg-type]


class TestSchemaBypass(unittest.TestCase):
    def test_record_round_trip(self) -> None:
        record = asp.seal_argument("db.query", "filter", "active", "string")
        self.assertTrue(asp.verify_record(record))
        self.assertEqual(record.observed_shape, "string")

    def test_tampered_record_fails_verify(self) -> None:
        record = asp.seal_argument("db.query", "filter", "active", "string")
        tampered = asp.ArgumentRecord(
            tool=record.tool,
            parameter=record.parameter,
            value_digest=record.value_digest,
            declared_type=record.declared_type,
            observed_shape="object",
            digest=record.digest,
        )
        self.assertFalse(asp.verify_record(tampered))

    def test_constructor_fail_closes_on_bad_format(self) -> None:
        with self.assertRaises(ValueError):
            asp.ArgumentRecord(
                tool="db.query",
                parameter="filter",
                value_digest="not-a-digest",
                declared_type="string",
                observed_shape="string",
                digest="sha256:" + "0" * 64,
            )

    def test_any_passthrough_named(self) -> None:
        record = asp.seal_argument("tool.run", "options", {"shell": True}, "any")
        self.assertEqual(asp.detect_schema_bypass(record), ("any-passthrough",))

    def test_shape_ok(self) -> None:
        record = asp.seal_argument("tool.run", "count", 3, "integer")
        self.assertEqual(asp.detect_schema_bypass(record), ("shape-ok",))

    def test_number_admits_integer(self) -> None:
        record = asp.seal_argument("tool.run", "ratio", 2, "number")
        self.assertEqual(asp.detect_schema_bypass(record), ("shape-ok",))

    def test_type_mismatch_named(self) -> None:
        record = asp.seal_argument("tool.run", "count", "three", "integer")
        self.assertEqual(asp.detect_schema_bypass(record), ("type-mismatch",))

    def test_bad_declared_type_rejected(self) -> None:
        with self.assertRaises(ValueError):
            asp.seal_argument("tool.run", "count", 3, "frobnicator")

    def test_undeclared_keys(self) -> None:
        extra = asp.undeclared_keys(
            {"query": "x", "limit_override": 9999}, {"query"}
        )
        self.assertEqual(extra, ("limit_override",))

    def test_undeclared_keys_empty(self) -> None:
        self.assertEqual(asp.undeclared_keys({"query": "x"}, {"query"}), ())

    def test_undeclared_keys_non_mapping_rejected(self) -> None:
        with self.assertRaises(TypeError):
            asp.undeclared_keys([1, 2], {"query"})  # type: ignore[arg-type]


class TestMeaningGate(unittest.TestCase):
    def test_surface_and_meaning_digests(self) -> None:
        args = {"username": "alice"}
        self.assertTrue(asp.surface_digest(args).startswith("sha256:"))
        self.assertTrue(asp.meaning_digest(args).startswith("sha256:"))

    def test_meaning_digest_stable_for_plain_text(self) -> None:
        args = {"username": "alice", "count": 3}
        self.assertEqual(asp.surface_digest(args), asp.meaning_digest(args))

    def test_meaning_digest_differs_on_confusable(self) -> None:
        surface = {"username": "Ａdmin"}
        self.assertNotEqual(
            asp.surface_digest(surface), asp.meaning_digest(surface)
        )

    def test_envelope_round_trip(self) -> None:
        envelope = asp.seal_meaning("auth.login", {"username": "alice"})
        self.assertTrue(asp.verify_envelope(envelope))

    def test_tampered_envelope_fails(self) -> None:
        envelope = asp.seal_meaning("auth.login", {"username": "alice"})
        tampered = asp.MeaningEnvelope(
            tool=envelope.tool,
            surface_digest=envelope.surface_digest,
            meaning_digest="sha256:" + "0" * 64,
            digest=envelope.digest,
        )
        self.assertFalse(asp.verify_envelope(tampered))
        # A tampered seal means drift: the gate fails closed.
        self.assertEqual(
            asp.detect_meaning_gap(tampered, {"username": "alice"}),
            ("meaning-drift",),
        )

    def test_meaning_consistent(self) -> None:
        envelope = asp.seal_meaning("auth.login", {"username": "alice"})
        self.assertEqual(
            asp.detect_meaning_gap(envelope, {"username": "alice"}),
            ("meaning-consistent",),
        )

    def test_meaning_drift_on_confusable(self) -> None:
        envelope = asp.seal_meaning("auth.login", {"username": "alice"})
        self.assertEqual(
            asp.detect_meaning_gap(envelope, {"username": "аdmin"}),
            ("meaning-drift",),
        )

    def test_non_mapping_rejected(self) -> None:
        with self.assertRaises(TypeError):
            asp.surface_digest([1, 2])  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            asp.meaning_digest("nope")  # type: ignore[arg-type]


class TestGateArguments(unittest.TestCase):
    def test_plain_arguments_allowed(self) -> None:
        allowed, findings = asp.gate_arguments(
            "db.query",
            {"filter": "string", "limit": "integer"},
            {"filter": "active", "limit": 10},
        )
        self.assertTrue(allowed)
        self.assertEqual(findings, ())

    def test_confusable_denied(self) -> None:
        allowed, findings = asp.gate_arguments(
            "auth.login", {"username": "string"}, {"username": "Ａdmin"}
        )
        self.assertFalse(allowed)
        self.assertTrue(any("unicode-confusable" in f for f in findings))

    def test_sql_fragment_denied(self) -> None:
        allowed, findings = asp.gate_arguments(
            "db.query",
            {"username": "string"},
            {"username": "alice' OR '1'='1' --"},
        )
        self.assertFalse(allowed)
        self.assertTrue(any("sql-fragment" in f for f in findings))

    def test_nested_json_denied(self) -> None:
        allowed, findings = asp.gate_arguments(
            "ticket.create",
            {"notes": "string"},
            {"notes": '{"role":"admin","bypass_review":true}'},
        )
        self.assertFalse(allowed)
        self.assertTrue(any("nested-json-payload" in f for f in findings))

    def test_any_passthrough_denied(self) -> None:
        allowed, findings = asp.gate_arguments(
            "tool.run", {"options": "any"}, {"options": {"shell": True}}
        )
        self.assertFalse(allowed)
        self.assertTrue(any("any-passthrough" in f for f in findings))

    def test_undeclared_key_denied(self) -> None:
        allowed, findings = asp.gate_arguments(
            "db.query",
            {"query": "string"},
            {"query": "select 1", "limit_override": 9999},
        )
        self.assertFalse(allowed)
        self.assertTrue(any("undeclared-keys" in f for f in findings))

    def test_meaning_drift_denied(self) -> None:
        # Ligature ﬁ (U+FB01) normalizes to "fi" downstream.
        allowed, findings = asp.gate_arguments(
            "fs.read", {"path": "string"}, {"path": "ﬁle.txt"}
        )
        self.assertFalse(allowed)
        self.assertTrue(any("meaning-drift" in f for f in findings))

    def test_legitimate_unicode_allowed(self) -> None:
        allowed, findings = asp.gate_arguments(
            "user.create", {"name": "string"}, {"name": "张伟"}
        )
        self.assertTrue(allowed)
        self.assertEqual(findings, ())

    def test_findings_in_fixed_vocabulary(self) -> None:
        _, findings = asp.gate_arguments(
            "auth.login",
            {"username": "string", "extra": "string"},
            {"username": "аdmin' OR '1'='1' --", "extra": "%2e%2e%2f"},
        )
        kinds = {f.split(":", 1)[1] for f in findings}
        vocab = set(asp.SMUGGLE_FINDINGS) | set(asp.BYPASS_FINDINGS) | set(
            asp.MEANING_FINDINGS
        ) | {"undeclared-keys"}
        self.assertTrue(kinds <= vocab, kinds)

    def test_jcs_fallback_digest_format(self) -> None:
        digest = asp.surface_digest({"a": 1})
        self.assertTrue(digest.startswith("sha256:"))
        self.assertEqual(digest, "sha256:" + hashlib.sha256(
            '{"arguments":{"a":1}}'.encode("utf-8")
        ).hexdigest())


if __name__ == "__main__":
    unittest.main()
