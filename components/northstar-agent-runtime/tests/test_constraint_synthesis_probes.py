"""Tests for the constraint-synthesis probes.

AgentRx's bet: derive executable invariants mechanically from the tool
schema and run every candidate call against them as a bench-harness
layer. These tests pin the corpus shape (10 attack probes across 3
families, 3 benign controls), the declaration-bounded synthesis rules,
and the digest-pinned validation semantics.
"""

import unittest

import constraint_synthesis_probes as csp
from canonical_json import jcs_sha256_hex

EXPECTED_PROBE_NAMES = (
    # schema-synthesis
    "synthesis-anyof-coverage",
    "synthesis-prose-only-constraint",
    "synthesis-undeclared-dependency",
    "synthesis-vacuous-pattern",
    # harness-validation
    "harness-stale-constraint-set",
    "harness-args-evasion",
    "harness-layer-skipped",
    # constraint-integrity
    "integrity-tampered-constraint",
    "integrity-selective-drop",
    "integrity-digest-mismatch",
)

EXPECTED_BENIGN_NAMES = (
    "benign-all-constraints-pass",
    "benign-resynthesized-after-repin",
    "benign-vacuous-schema-honest",
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


def _schema(**overrides):
    base = {
        "name": "db.query",
        "inputSchema": {
            "type": "object",
            "properties": {
                "table": {"type": "string", "enum": ["users", "orders"]},
                "limit": {"type": "integer", "minimum": 1, "maximum": 100},
                "query_id": {"type": "string", "pattern": "^[a-z0-9-]{8}$"},
            },
            "required": ["table"],
            "additionalProperties": False,
        },
    }
    base["inputSchema"].update(overrides.pop("inputSchema", {}))
    base.update(overrides)
    return base


class CorpusShapeTests(unittest.TestCase):
    def test_attack_probe_names(self):
        self.assertEqual(csp.attack_probe_names(), EXPECTED_PROBE_NAMES)

    def test_benign_probe_names(self):
        self.assertEqual(csp.benign_probe_names(), EXPECTED_BENIGN_NAMES)

    def test_probe_names_unique(self):
        names = [*csp.attack_probe_names(), *csp.benign_probe_names()]
        self.assertEqual(len(names), len(set(names)))

    def test_required_keys(self):
        for name in (*EXPECTED_PROBE_NAMES, *EXPECTED_BENIGN_NAMES):
            probe = csp.probe_by_name(name)
            for key in REQUIRED_KEYS:
                self.assertIn(key, probe, f"{name} missing {key}")
                self.assertTrue(probe[key], f"{name}.{key} empty")

    def test_attack_gate_interactions_carry_deny_side_keyword(self):
        for name in EXPECTED_PROBE_NAMES:
            text = csp.probe_by_name(name)["gate_interaction"].lower()
            self.assertTrue(
                any(k in text for k in DENY_SIDE_KEYWORDS),
                f"{name} gate_interaction lacks deny-side keyword",
            )

    def test_expected_outcomes(self):
        outcomes = csp.expected_outcomes()
        for name in EXPECTED_PROBE_NAMES:
            self.assertEqual(outcomes[name], "deny")
        for name in EXPECTED_BENIGN_NAMES:
            self.assertEqual(outcomes[name], "allow")

    def test_families(self):
        self.assertEqual(
            set(csp.FAMILIES),
            {"schema-synthesis", "harness-validation", "constraint-integrity"},
        )
        total = sum(len(csp.probes_in_family(f)) for f in csp.FAMILIES)
        self.assertEqual(total, len(EXPECTED_PROBE_NAMES))

    def test_probe_by_name_unknown(self):
        with self.assertRaises(KeyError):
            csp.probe_by_name("no-such-probe")

    def test_main(self):
        csp.main()


class SynthesisTests(unittest.TestCase):
    def test_synthesizes_declared_constraints(self):
        cset = csp.synthesize_constraints(_schema())
        kinds = {c.kind for c in cset.constraints}
        self.assertIn("required", kinds)
        self.assertIn("type", kinds)
        self.assertIn("enum", kinds)
        self.assertIn("range", kinds)
        self.assertIn("pattern", kinds)
        self.assertIn("closed", kinds)

    def test_never_invents_prose_constraints(self):
        # "must be a valid email" in the description with no format field
        # must not become a constraint.
        schema = _schema()
        schema["inputSchema"]["properties"]["email"] = {
            "type": "string",
            "description": "must be a valid email address",
        }
        cset = csp.synthesize_constraints(schema)
        email_constraints = [
            c for c in cset.constraints if c.spec.get("param") == "email"
        ]
        kinds = {c.kind for c in email_constraints}
        # Only the declared type constraint; no invented pattern/format.
        self.assertEqual(kinds, {"type"})

    def test_never_invents_undeclared_dependencies(self):
        schema = _schema()
        schema["inputSchema"]["properties"]["region"] = {"type": "string"}
        cset = csp.synthesize_constraints(schema)
        specs = [dict(c.spec) for c in cset.constraints]
        self.assertFalse(
            any("requires" in str(s) or "depends" in str(s) for s in specs),
            "synthesizer invented an undeclared dependency",
        )

    def test_degenerate_pattern_fails_closed(self):
        schema = _schema()
        schema["inputSchema"]["properties"]["token"] = {
            "type": "string",
            "pattern": ".*",
        }
        with self.assertRaises(ValueError):
            csp.synthesize_constraints(schema)

    def test_anyof_branches_all_covered(self):
        schema = {
            "name": "search",
            "parameters": {
                "type": "object",
                "properties": {"q": {"type": "string"}},
                "anyOf": [
                    {"properties": {"user_id": {"type": "integer"}}},
                    {"properties": {"org_id": {"type": "string"}}},
                ],
            },
        }
        cset = csp.synthesize_constraints(schema)
        params = {c.spec.get("param") for c in cset.constraints}
        self.assertIn("branch0.user_id", params)
        self.assertIn("branch1.org_id", params)

    def test_empty_schema_rejected(self):
        with self.assertRaises(ValueError):
            csp.synthesize_constraints({})

    def test_non_mapping_rejected(self):
        with self.assertRaises(TypeError):
            csp.synthesize_constraints(["not", "a", "mapping"])

    def test_constraint_digest_verifies(self):
        c = csp.build_constraint("required", {"param": "x"})
        self.assertTrue(c.digest.startswith("sha256:"))
        with self.assertRaises(ValueError):
            csp.Constraint(
                kind="required",
                spec={"param": "x"},
                digest="sha256:" + "0" * 64,
            )

    def test_unknown_kind_rejected(self):
        with self.assertRaises(ValueError):
            csp.build_constraint("mind-reading", {"param": "x"})

    def test_set_digest_stable(self):
        a = csp.synthesize_constraints(_schema())
        b = csp.synthesize_constraints(_schema())
        self.assertEqual(a.digest, b.digest)
        self.assertEqual(a.schema_digest, b.schema_digest)

    def test_set_bound_to_schema_digest(self):
        schema = _schema()
        cset = csp.synthesize_constraints(schema)
        self.assertEqual(cset.schema_digest, "sha256:" + jcs_sha256_hex(schema))


class IntegrityTests(unittest.TestCase):
    def test_verify_ok(self):
        cset = csp.synthesize_constraints(_schema())
        self.assertTrue(csp.verify_constraint_set(cset))

    def test_tampered_constraint_fails(self):
        cset = csp.synthesize_constraints(_schema())
        # Build a constraint whose digest does not match its content,
        # bypassing __post_init__ the way a tampered record would arrive.
        tampered = object.__new__(csp.Constraint)
        object.__setattr__(tampered, "kind", cset.constraints[0].kind)
        object.__setattr__(tampered, "spec", dict(cset.constraints[0].spec))
        object.__setattr__(tampered, "digest", "sha256:" + "f" * 64)
        evil = object.__new__(csp.ConstraintSet)
        object.__setattr__(evil, "schema_digest", cset.schema_digest)
        object.__setattr__(
            evil, "constraints", (tampered, *cset.constraints[1:])
        )
        object.__setattr__(evil, "digest", cset.digest)  # stale digest
        self.assertFalse(csp.verify_constraint_set(evil))

    def test_completeness_ok(self):
        schema = _schema()
        cset = csp.synthesize_constraints(schema)
        ok, missing = csp.check_completeness(schema, cset)
        self.assertTrue(ok)
        self.assertEqual(missing, ())

    def test_selective_drop_detected(self):
        schema = _schema()
        full = csp.synthesize_constraints(schema)
        thinned = tuple(
            c for c in full.constraints if not (c.kind == "enum" and c.spec.get("param") == "table")
        )
        self.assertLess(len(thinned), len(full.constraints))
        thinned_set = csp.ConstraintSet(
            schema_digest=full.schema_digest,
            constraints=thinned,
            digest="sha256:"
            + jcs_sha256_hex(
                {
                    "schema_digest": full.schema_digest,
                    "constraints": [
                        {"kind": c.kind, "spec": dict(c.spec), "digest": c.digest}
                        for c in thinned
                    ],
                }
            ),
        )
        ok, missing = csp.check_completeness(schema, thinned_set)
        self.assertFalse(ok)
        self.assertIn("enum:table", missing)

    def test_completeness_schema_mismatch(self):
        schema = _schema()
        cset = csp.synthesize_constraints(schema)
        other = _schema()
        other["inputSchema"]["properties"]["limit"]["maximum"] = 50
        ok, missing = csp.check_completeness(other, cset)
        self.assertFalse(ok)
        self.assertIn("schema-digest-mismatch", missing)


class ValidationTests(unittest.TestCase):
    def test_valid_call_passes(self):
        schema = _schema()
        cset = csp.synthesize_constraints(schema)
        ok, findings = csp.validate_arguments(
            cset, {"table": "users", "limit": 10, "query_id": "abcd1234"}, schema
        )
        self.assertTrue(ok)
        self.assertEqual(findings, ())

    def test_missing_required_denied(self):
        schema = _schema()
        cset = csp.synthesize_constraints(schema)
        ok, findings = csp.validate_arguments(cset, {"limit": 10}, schema)
        self.assertFalse(ok)
        self.assertTrue(any(f.code == "required-missing" for f in findings))

    def test_type_mismatch_denied(self):
        schema = _schema()
        cset = csp.synthesize_constraints(schema)
        ok, findings = csp.validate_arguments(
            cset, {"table": "users", "limit": "ten"}, schema
        )
        self.assertFalse(ok)
        self.assertTrue(any(f.code == "type-mismatch" for f in findings))

    def test_enum_violation_denied(self):
        schema = _schema()
        cset = csp.synthesize_constraints(schema)
        ok, findings = csp.validate_arguments(cset, {"table": "admins"}, schema)
        self.assertFalse(ok)
        self.assertTrue(any(f.code == "enum-violation" for f in findings))

    def test_range_violation_denied(self):
        schema = _schema()
        cset = csp.synthesize_constraints(schema)
        ok, findings = csp.validate_arguments(cset, {"table": "users", "limit": 500}, schema)
        self.assertFalse(ok)
        self.assertTrue(any(f.code == "range-violation" for f in findings))

    def test_pattern_violation_denied(self):
        schema = _schema()
        cset = csp.synthesize_constraints(schema)
        ok, findings = csp.validate_arguments(
            cset, {"table": "users", "query_id": "NOT-A-VALID-ID!!!"}, schema
        )
        self.assertFalse(ok)
        self.assertTrue(any(f.code == "pattern-violation" for f in findings))

    def test_closure_violation_denied(self):
        schema = _schema()
        cset = csp.synthesize_constraints(schema)
        ok, findings = csp.validate_arguments(
            cset, {"table": "users", "__debug_exec": True}, schema
        )
        self.assertFalse(ok)
        self.assertTrue(any(f.code == "closure-violation" for f in findings))

    def test_stale_set_denied(self):
        schema = _schema()
        cset = csp.synthesize_constraints(schema)
        drifted = _schema()
        drifted["inputSchema"]["properties"]["limit"]["maximum"] = 50
        ok, findings = csp.validate_arguments(
            cset, {"table": "users", "limit": 10}, drifted
        )
        self.assertFalse(ok)
        self.assertTrue(any(f.code == "stale-set" for f in findings))

    def test_bad_arguments_denied(self):
        schema = _schema()
        cset = csp.synthesize_constraints(schema)
        ok, findings = csp.validate_arguments(cset, ["not", "a", "mapping"], schema)
        self.assertFalse(ok)
        self.assertTrue(any(f.code == "bad-arguments" for f in findings))

    def test_receipt_binds_call_and_set(self):
        schema = _schema()
        cset = csp.synthesize_constraints(schema)
        receipt = csp.validation_receipt(cset, {"table": "users"}, schema)
        self.assertTrue(receipt["ok"])
        self.assertEqual(receipt["set_digest"], cset.digest)
        self.assertEqual(receipt["schema_digest"], cset.schema_digest)
        self.assertTrue(receipt["receipt_digest"].startswith("sha256:"))

    def test_receipt_records_findings(self):
        schema = _schema()
        cset = csp.synthesize_constraints(schema)
        receipt = csp.validation_receipt(cset, {"table": "admins"}, schema)
        self.assertFalse(receipt["ok"])
        self.assertTrue(any(f["code"] == "enum-violation" for f in receipt["findings"]))


if __name__ == "__main__":
    unittest.main()
