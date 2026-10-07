"""Tests for destructive_prefix_probes."""

import unittest

from destructive_prefix_probes import (
    DESTRUCTIVE_PREFIX_BENIGN,
    DESTRUCTIVE_PREFIX_PROBES,
    FAMILIES,
    PREFIX_RISK_CLASSES,
    AliasMapping,
    NameGateDecision,
    NameRecord,
    attack_probe_names,
    benign_probe_names,
    classify_name,
    detect_alias_hides_risk,
    detect_description_contradiction,
    detect_prefix_risk,
    detect_undeclared_risk,
    expected_outcomes,
    gate_name,
    pin_alias,
    probe_by_name,
    probes_in_family,
    resolve_alias,
    seal_name,
    verify_alias,
    verify_decision,
    verify_record,
)

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

REQUIRED_PROBE_KEYS = (
    "probe",
    "family",
    "attack",
    "gate_interaction",
    "expected",
    "reason",
)


def _good_record(**overrides):
    kwargs = {
        "registered_name": "drop_table",
        "display_name": None,
        "description": "Drop a table from the staging schema.",
        "declared_risk": ("destructive",),
    }
    kwargs.update(overrides)
    return seal_name(**kwargs)


class CorpusShapeTest(unittest.TestCase):
    def test_probe_counts(self) -> None:
        self.assertEqual(len(DESTRUCTIVE_PREFIX_PROBES), 10)
        self.assertEqual(len(DESTRUCTIVE_PREFIX_BENIGN), 3)

    def test_family_counts(self) -> None:
        self.assertEqual(len(probes_in_family("destructive-prefix")), 4)
        self.assertEqual(len(probes_in_family("name-coercion")), 3)
        self.assertEqual(len(probes_in_family("prefix-gates")), 3)

    def test_required_keys(self) -> None:
        for probe in (*DESTRUCTIVE_PREFIX_PROBES, *DESTRUCTIVE_PREFIX_BENIGN):
            for key in REQUIRED_PROBE_KEYS:
                self.assertIn(key, probe, probe["probe"])

    def test_unique_names(self) -> None:
        names = [p["probe"] for p in (*DESTRUCTIVE_PREFIX_PROBES, *DESTRUCTIVE_PREFIX_BENIGN)]
        self.assertEqual(len(names), len(set(names)))

    def test_attack_gate_interactions_carry_deny_side_keyword(self) -> None:
        for probe in DESTRUCTIVE_PREFIX_PROBES:
            text = probe["gate_interaction"].lower()
            self.assertTrue(
                any(k in text for k in DENY_SIDE_KEYWORDS),
                f"{probe['probe']} has no deny-side keyword",
            )

    def test_expected_values(self) -> None:
        for probe in DESTRUCTIVE_PREFIX_PROBES:
            self.assertEqual(probe["expected"], "deny")
        for probe in DESTRUCTIVE_PREFIX_BENIGN:
            self.assertEqual(probe["expected"], "allow")

    def test_accessors(self) -> None:
        self.assertEqual(len(attack_probe_names()), 10)
        self.assertEqual(len(benign_probe_names()), 3)
        outcomes = expected_outcomes()
        self.assertEqual(outcomes["prefix-selection-coercion"], "deny")
        self.assertEqual(outcomes["benign-declared-destructive"], "allow")

    def test_probe_by_name(self) -> None:
        self.assertEqual(
            probe_by_name("coercion-alias-laundering")["family"], "name-coercion"
        )
        with self.assertRaises(KeyError):
            probe_by_name("no-such-probe")

    def test_families_cover_all_attacks(self) -> None:
        covered = {p for names in FAMILIES.values() for p in names}
        self.assertEqual(covered, set(attack_probe_names()))


class PrefixClassificationTest(unittest.TestCase):
    def test_destructive_prefixes(self) -> None:
        self.assertIn("destructive", classify_name("drop_table"))
        self.assertIn("destructive", classify_name("wipe_disk"))
        self.assertIn("destructive", classify_name("delete_records"))

    def test_execution_prefixes(self) -> None:
        self.assertIn("execution", classify_name("exec_remote"))
        self.assertIn("execution", classify_name("eval_expression"))

    def test_force_prefixes(self) -> None:
        self.assertIn("force", classify_name("force_delete"))
        self.assertIn("force", classify_name("unsafe_wipe"))

    def test_multiple_classes(self) -> None:
        self.assertEqual(
            classify_name("force_delete_records"), frozenset({"destructive", "force"})
        )

    def test_prefix_anchored(self) -> None:
        # 'drop_' must not match 'backdrop'; prefix-anchored only.
        self.assertEqual(classify_name("backdrop"), frozenset())

    def test_unclassified_is_empty(self) -> None:
        self.assertEqual(classify_name("get_weather"), frozenset())
        self.assertEqual(detect_prefix_risk("get_weather"), ())

    def test_case_insensitive(self) -> None:
        self.assertIn("destructive", classify_name("DROP_TABLE"))

    def test_bad_name_rejected(self) -> None:
        with self.assertRaises(ValueError):
            classify_name("")

    def test_prefix_registry_nonempty(self) -> None:
        self.assertTrue(all(PREFIX_RISK_CLASSES.values()))


class RecordSemanticsTest(unittest.TestCase):
    def test_round_trip(self) -> None:
        record = _good_record()
        self.assertTrue(verify_record(record))
        self.assertTrue(record.digest.startswith("sha256:"))

    def test_tamper_breaks_seal(self) -> None:
        record = _good_record()
        bad = object.__new__(NameRecord)
        object.__setattr__(bad, "registered_name", record.registered_name)
        object.__setattr__(bad, "display_name", record.display_name)
        object.__setattr__(bad, "description", "totally different description")
        object.__setattr__(bad, "declared_risk", record.declared_risk)
        object.__setattr__(bad, "digest", record.digest)
        self.assertFalse(verify_record(bad))

    def test_empty_name_rejected(self) -> None:
        with self.assertRaises(ValueError):
            seal_name("", None, "desc", ())

    def test_declared_risk_must_be_tuple(self) -> None:
        with self.assertRaises(ValueError):
            NameRecord(
                registered_name="drop_table",
                display_name=None,
                description="desc",
                declared_risk=["destructive"],  # type: ignore[arg-type]
                digest="sha256:" + "0" * 64,
            )


class DetectorTest(unittest.TestCase):
    def test_undeclared_risk_named(self) -> None:
        record = seal_name(
            "force_delete_records", None, "desc", ("destructive",)
        )
        self.assertEqual(detect_undeclared_risk(record), ("force",))

    def test_fully_declared_is_clean(self) -> None:
        self.assertEqual(detect_undeclared_risk(_good_record()), ())

    def test_alias_hides_risk_positive(self) -> None:
        record = seal_name(
            "drop_database", "Cleanup", "desc", ("destructive",)
        )
        self.assertTrue(detect_alias_hides_risk(record))

    def test_alias_hides_risk_negative_with_signal(self) -> None:
        record = seal_name(
            "drop_database", "Drop old snapshots", "desc", ("destructive",)
        )
        self.assertFalse(detect_alias_hides_risk(record))

    def test_alias_hides_risk_no_label(self) -> None:
        self.assertFalse(detect_alias_hides_risk(_good_record()))

    def test_description_contradiction_positive(self) -> None:
        record = seal_name(
            "exec_shell", None, "read-only system inspection", ("execution",)
        )
        self.assertTrue(detect_description_contradiction(record))

    def test_description_contradiction_negative(self) -> None:
        record = seal_name(
            "exec_shell", None, "run remote diagnostics", ("execution",)
        )
        self.assertFalse(detect_description_contradiction(record))

    def test_description_contradiction_unclassified_name(self) -> None:
        record = seal_name("get_weather", None, "read-only forecast", ())
        self.assertFalse(detect_description_contradiction(record))


class AliasMappingTest(unittest.TestCase):
    def test_round_trip(self) -> None:
        mapping = pin_alias("cleanup", "delete_temp_files", ("destructive",))
        self.assertTrue(verify_alias(mapping))

    def test_tamper_breaks_seal(self) -> None:
        mapping = pin_alias("cleanup", "delete_temp_files", ("destructive",))
        bad = object.__new__(AliasMapping)
        object.__setattr__(bad, "alias", mapping.alias)
        object.__setattr__(bad, "registered_name", "drop_database")
        object.__setattr__(bad, "declared_risk", mapping.declared_risk)
        object.__setattr__(bad, "digest", mapping.digest)
        self.assertFalse(verify_alias(bad))

    def test_resolve_alias_pinned(self) -> None:
        mapping = pin_alias("cleanup", "delete_temp_files", ("destructive",))
        resolved = resolve_alias("cleanup", (mapping,))
        self.assertIsNotNone(resolved)
        assert resolved is not None
        self.assertEqual(resolved.registered_name, "delete_temp_files")

    def test_resolve_alias_unmapped(self) -> None:
        self.assertIsNone(resolve_alias("purge", ()))

    def test_resolve_alias_tampered_not_resolved(self) -> None:
        mapping = pin_alias("cleanup", "delete_temp_files", ("destructive",))
        bad = object.__new__(AliasMapping)
        object.__setattr__(bad, "alias", mapping.alias)
        object.__setattr__(bad, "registered_name", "drop_database")
        object.__setattr__(bad, "declared_risk", mapping.declared_risk)
        object.__setattr__(bad, "digest", mapping.digest)
        self.assertIsNone(resolve_alias("cleanup", (bad,)))


class GateTest(unittest.TestCase):
    def test_declared_destructive_allowed(self) -> None:
        decision = gate_name(_good_record())
        self.assertEqual(decision.disposition, "allow")
        self.assertEqual(decision.findings, ())
        self.assertTrue(verify_decision(decision))

    def test_unclassified_allowed_with_finding(self) -> None:
        record = seal_name("get_weather", None, "forecast", ())
        decision = gate_name(record)
        self.assertEqual(decision.disposition, "allow")
        self.assertEqual(decision.findings, ("unclassified-name",))
        self.assertTrue(verify_decision(decision))

    def test_undeclared_risk_denied(self) -> None:
        record = seal_name("force_delete_records", None, "desc", ("destructive",))
        decision = gate_name(record)
        self.assertEqual(decision.disposition, "deny")
        self.assertEqual(decision.findings, ("undeclared-risk-class",))
        self.assertTrue(verify_decision(decision))

    def test_alias_hides_risk_denied(self) -> None:
        record = seal_name("drop_database", "Cleanup", "desc", ("destructive",))
        decision = gate_name(record)
        self.assertEqual(decision.disposition, "deny")
        self.assertEqual(decision.findings, ("alias-hides-risk",))
        self.assertTrue(verify_decision(decision))

    def test_description_contradiction_denied(self) -> None:
        record = seal_name(
            "exec_shell", None, "read-only inspection", ("execution",)
        )
        decision = gate_name(record)
        self.assertEqual(decision.disposition, "deny")
        self.assertEqual(decision.findings, ("description-contradicts-name",))
        self.assertTrue(verify_decision(decision))

    def test_unverifiable_record_denied(self) -> None:
        record = _good_record()
        bad = object.__new__(NameRecord)
        object.__setattr__(bad, "registered_name", record.registered_name)
        object.__setattr__(bad, "display_name", record.display_name)
        object.__setattr__(bad, "description", "changed")
        object.__setattr__(bad, "declared_risk", record.declared_risk)
        object.__setattr__(bad, "digest", record.digest)
        decision = gate_name(bad)
        self.assertEqual(decision.disposition, "deny")
        self.assertEqual(decision.findings, ("record-unverifiable",))

    def test_tampered_decision_fails_verify(self) -> None:
        decision = gate_name(_good_record())
        bad = object.__new__(NameGateDecision)
        object.__setattr__(bad, "registered_name", decision.registered_name)
        object.__setattr__(bad, "disposition", "allow")
        object.__setattr__(bad, "findings", ("undeclared-risk-class",))
        object.__setattr__(bad, "digest", decision.digest)
        self.assertFalse(verify_decision(bad))

    def test_first_failure_wins(self) -> None:
        # Undeclared risk AND alias hiding risk: seal order puts
        # undeclared-risk first.
        record = seal_name("force_delete_records", "Tidy", "desc", ())
        decision = gate_name(record)
        self.assertEqual(decision.findings, ("undeclared-risk-class",))


class MainTest(unittest.TestCase):
    def test_main_runs(self) -> None:
        import destructive_prefix_probes

        destructive_prefix_probes.main()


if __name__ == "__main__":
    unittest.main()
