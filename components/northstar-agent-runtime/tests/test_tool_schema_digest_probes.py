"""Tests for the tool-schema-digest probes.

The tool a gate approved is not always the tool that runs: schemas drift
mid-conversation, names collide across namespaces, and session-level
digests go stale. These tests pin the corpus shape (10 attack probes
across 3 families, 3 benign controls) and the per-invocation binding /
drift detection / identity binding semantics.
"""

import unittest

import tool_schema_digest_probes as tsd
from canonical_json import jcs_sha256_hex

EXPECTED_PROBE_NAMES = (
    # invocation-digest
    "digest-session-reuse",
    "digest-args-laundering",
    "digest-swap-mid-session",
    "digest-replay-binding",
    # schema-drift
    "drift-param-added",
    "drift-param-removed",
    "drift-description-reword",
    "drift-type-change",
    # identity-binding
    "identity-name-collision",
    "identity-unpinned-invocation",
)

EXPECTED_BENIGN_NAMES = (
    "benign-pinned-match",
    "benign-versioned-repin",
    "benign-identical-reobserve",
)

REQUIRED_KEYS = ("probe", "family", "attack", "gate_interaction", "expected", "reason")

# Every attack probe's gate interaction must name an active deny-side
# check -- framing the attack must never read as a defense.
DENY_SIDE_KEYWORDS = (
    "denies",
    "denied",
    "deny",
    "quarantine",
    "quarantined",
    "quarantines",
    "blocks",
    "refuses",
    "never",
    "fail closed",
)


def _args(tag: str) -> str:
    return "sha256:" + jcs_sha256_hex({"args": tag})


def _schema(**overrides):
    base = {
        "name": "db.query",
        "description": "Run a read-only query.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "sql": {"type": "string"},
                "limit": {"type": "integer"},
            },
            "required": ["sql"],
        },
    }
    base.update(overrides)
    return base


class CorpusShapeTests(unittest.TestCase):
    def test_attack_probe_names(self):
        self.assertEqual(tsd.attack_probe_names(), EXPECTED_PROBE_NAMES)

    def test_benign_probe_names(self):
        self.assertEqual(tsd.benign_probe_names(), EXPECTED_BENIGN_NAMES)

    def test_required_keys(self):
        for probe in (*tsd.TOOL_SCHEMA_DIGEST_PROBES, *tsd.TOOL_SCHEMA_DIGEST_BENIGN):
            for key in REQUIRED_KEYS:
                self.assertIn(key, probe, probe["probe"])
                self.assertTrue(probe[key], probe["probe"])

    def test_unique_names(self):
        names = [p["probe"] for p in (*tsd.TOOL_SCHEMA_DIGEST_PROBES, *tsd.TOOL_SCHEMA_DIGEST_BENIGN)]
        self.assertEqual(len(names), len(set(names)))

    def test_attack_gate_interactions_carry_deny_side_keyword(self):
        for probe in tsd.TOOL_SCHEMA_DIGEST_PROBES:
            text = probe["gate_interaction"].lower()
            self.assertTrue(
                any(k in text for k in DENY_SIDE_KEYWORDS),
                probe["probe"],
            )

    def test_families_cover_all_attack_probes(self):
        covered = [p for fam in tsd.FAMILIES.values() for p in fam]
        self.assertEqual(sorted(covered), sorted(EXPECTED_PROBE_NAMES))

    def test_expected_outcomes(self):
        outcomes = tsd.expected_outcomes()
        for name in EXPECTED_PROBE_NAMES:
            self.assertEqual(outcomes[name], "deny", name)
        for name in EXPECTED_BENIGN_NAMES:
            self.assertEqual(outcomes[name], "allow", name)

    def test_probe_by_name(self):
        probe = tsd.probe_by_name("drift-type-change")
        self.assertEqual(probe["family"], "schema-drift")
        with self.assertRaises(KeyError):
            tsd.probe_by_name("no-such-probe")


class SchemaDigestTests(unittest.TestCase):
    def test_digest_covers_description(self):
        a = _schema()
        b = _schema(description="Run any query.")
        self.assertNotEqual(tsd.schema_digest(a), tsd.schema_digest(b))

    def test_digest_stable(self):
        self.assertEqual(tsd.schema_digest(_schema()), tsd.schema_digest(_schema()))

    def test_digest_rejects_non_mapping(self):
        with self.assertRaises(TypeError):
            tsd.schema_digest(["not", "a", "mapping"])

    def test_digest_rejects_empty(self):
        with self.assertRaises(ValueError):
            tsd.schema_digest({})


class SnapshotTests(unittest.TestCase):
    def test_pin_and_verify_round_trip(self):
        snap = tsd.pin_schema("db.query", _schema(), "v1")
        self.assertTrue(tsd.verify_snapshot(snap))

    def test_tampered_seal_fails(self):
        snap = tsd.pin_schema("db.query", _schema(), "v1")
        tampered = tsd.ToolSchemaSnapshot(
            tool=snap.tool,
            schema_digest=snap.schema_digest,
            version=snap.version,
            digest="sha256:" + "0" * 64,
        )
        self.assertFalse(tsd.verify_snapshot(tampered))

    def test_empty_tool_rejected(self):
        with self.assertRaises(ValueError):
            tsd.pin_schema("", _schema(), "v1")

    def test_empty_version_rejected(self):
        with self.assertRaises(ValueError):
            tsd.pin_schema("db.query", _schema(), "")


class BindingTests(unittest.TestCase):
    def test_bind_and_verify_round_trip(self):
        snap = tsd.pin_schema("db.query", _schema(), "v1")
        binding = tsd.bind_invocation(snap, "inv-1", _args("a"))
        self.assertTrue(tsd.verify_binding(binding, "inv-1"))

    def test_binding_replay_across_invocations_rejected(self):
        snap = tsd.pin_schema("db.query", _schema(), "v1")
        binding = tsd.bind_invocation(snap, "inv-1", _args("a"))
        self.assertFalse(tsd.verify_binding(binding, "inv-2"))

    def test_tampered_binding_fails(self):
        snap = tsd.pin_schema("db.query", _schema(), "v1")
        binding = tsd.bind_invocation(snap, "inv-1", _args("a"))
        tampered = tsd.InvocationBinding(
            tool=binding.tool,
            schema_digest=binding.schema_digest,
            invocation_id=binding.invocation_id,
            arguments_digest=binding.arguments_digest,
            digest="sha256:" + "0" * 64,
        )
        self.assertFalse(tsd.verify_binding(tampered, "inv-1"))

    def test_bind_against_tampered_snapshot_raises(self):
        snap = tsd.pin_schema("db.query", _schema(), "v1")
        tampered = tsd.ToolSchemaSnapshot(
            tool=snap.tool,
            schema_digest=snap.schema_digest,
            version=snap.version,
            digest="sha256:" + "0" * 64,
        )
        with self.assertRaises(ValueError):
            tsd.bind_invocation(tampered, "inv-1", _args("a"))


class DriftDetailTests(unittest.TestCase):
    def test_identical_schemas_no_details(self):
        self.assertEqual(tsd.drift_details(_schema(), _schema()), ())

    def test_parameter_added(self):
        observed = _schema()
        observed["inputSchema"]["properties"]["raw_sql"] = {"type": "string"}
        self.assertIn("parameter_added", tsd.drift_details(_schema(), observed))

    def test_parameter_removed(self):
        observed = _schema()
        del observed["inputSchema"]["properties"]["limit"]
        self.assertIn("parameter_removed", tsd.drift_details(_schema(), observed))

    def test_type_changed(self):
        observed = _schema()
        observed["inputSchema"]["properties"]["limit"] = {"type": "string"}
        self.assertIn("type_changed", tsd.drift_details(_schema(), observed))

    def test_required_changed(self):
        observed = _schema()
        observed["inputSchema"]["required"] = ["sql", "limit"]
        self.assertIn("required_changed", tsd.drift_details(_schema(), observed))

    def test_description_changed(self):
        observed = _schema(description="Run any query whatsoever.")
        self.assertIn("description_changed", tsd.drift_details(_schema(), observed))

    def test_drift_details_rejects_non_mapping(self):
        with self.assertRaises(TypeError):
            tsd.drift_details(_schema(), ["nope"])


class RegistryTests(unittest.TestCase):
    def test_no_drift_on_match(self):
        registry = tsd.SchemaRegistry()
        registry.register(tsd.pin_schema("db.query", _schema(), "v1"))
        finding = registry.check("db.query", _schema(), _schema())
        self.assertEqual(finding.kind, "no_drift")
        self.assertEqual(finding.details, ())
        self.assertTrue(tsd.verify_finding(finding))

    def test_unknown_tool_fail_closed(self):
        registry = tsd.SchemaRegistry()
        finding = registry.check("db.query", _schema())
        self.assertEqual(finding.kind, "unknown_tool")

    def test_drift_detected_with_details(self):
        registry = tsd.SchemaRegistry()
        pinned = _schema()
        registry.register(tsd.pin_schema("db.query", pinned, "v1"))
        observed = _schema(description="Run any query whatsoever.")
        finding = registry.check("db.query", observed, pinned)
        self.assertEqual(finding.kind, "schema_drift")
        self.assertIn("description_changed", finding.details)

    def test_register_rejects_bad_seal(self):
        registry = tsd.SchemaRegistry()
        bad = tsd.ToolSchemaSnapshot(
            tool="db.query",
            schema_digest="sha256:" + "a" * 64,
            version="v1",
            digest="sha256:" + "0" * 64,
        )
        with self.assertRaises(ValueError):
            registry.register(bad)

    def test_re_admission_replaces_pin(self):
        registry = tsd.SchemaRegistry()
        registry.register(tsd.pin_schema("db.query", _schema(), "v1"))
        v2 = _schema(description="Run a read-only query (v2).")
        registry.register(tsd.pin_schema("db.query", v2, "v2"))
        finding = registry.check("db.query", v2, v2)
        self.assertEqual(finding.kind, "no_drift")


class ToolCallTests(unittest.TestCase):
    def test_clean_call_binds(self):
        registry = tsd.SchemaRegistry()
        schema = _schema()
        registry.register(tsd.pin_schema("db.query", schema, "v1"))
        binding, finding = tsd.bind_tool_call(
            registry, "db.query", schema, "inv-1", _args("a"), schema
        )
        self.assertIsNotNone(binding)
        self.assertEqual(finding.kind, "no_drift")
        assert binding is not None
        self.assertTrue(tsd.verify_binding(binding, "inv-1"))

    def test_drifted_call_fails_closed_no_binding(self):
        registry = tsd.SchemaRegistry()
        pinned = _schema()
        registry.register(tsd.pin_schema("db.query", pinned, "v1"))
        drifted = _schema()
        drifted["inputSchema"]["properties"]["raw_sql"] = {"type": "string"}
        binding, finding = tsd.bind_tool_call(
            registry, "db.query", drifted, "inv-1", _args("a"), pinned
        )
        self.assertIsNone(binding)
        self.assertEqual(finding.kind, "schema_drift")

    def test_unpinned_tool_fails_closed(self):
        registry = tsd.SchemaRegistry()
        binding, finding = tsd.bind_tool_call(
            registry, "db.query", _schema(), "inv-1", _args("a")
        )
        self.assertIsNone(binding)
        self.assertEqual(finding.kind, "unknown_tool")


class MainTests(unittest.TestCase):
    def test_main_runs(self):
        tsd.main()


if __name__ == "__main__":
    unittest.main()
