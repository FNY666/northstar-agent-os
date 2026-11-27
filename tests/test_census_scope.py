"""The census scope must be the UNION of every suite that references a module.

``scripts/b173-census-all.sh`` pairs each module with a test scope before
asking the probe whether a planted fault is noticed.  If that scope is too
narrow, a mutant that a sibling suite DOES catch is reported as SURVIVED --
a false accusation of a weak test suite, the mirror image of the
stale-bytecode false kill.

Measured 2026-11-25 on ``job_queue.py``:

    its own suite alone   killed 43/85   (42 survivors)
    the four-suite union  killed 76/85   (9 survivors)

Twenty-nine of the narrow scope's "survivors" were caught by the sibling
suites.  The union scope is the one that is true.

This test pins the resolver's DEFINITION, which is the part that can go
wrong quietly:

* "references" means a real IMPORT, read from the AST -- not a grep.  Two
  suites mention ``job_queue.py`` in prose and import it in neither; a
  grep-based scope counts them and measures suites that do not exercise
  the module at all.
* the module's own suite comes FIRST, so a census log is comparable
  between runs.
* a module with no referencing suite resolves to the empty scope, and the
  census script SKIPs it rather than falling back to an arbitrary suite.
"""
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "census-scope.py"
RUNTIME = ROOT / "components" / "northstar-agent-runtime"

SPEC = importlib.util.spec_from_file_location("census_scope", SCRIPT)
if SPEC is None or SPEC.loader is None:  # pragma: no cover - repository corruption
    raise RuntimeError(f"cannot load {SCRIPT}")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class CensusScopeTests(unittest.TestCase):
    """The scope the real component resolves to."""

    def test_job_queue_resolves_to_the_four_suite_union(self) -> None:
        # These four are the suites docs/design/refusal-hold-wiring.md
        # §22.1 names as the scope for `job_queue.py`, and the scope the
        # 76/85 measurement was taken at.
        self.assertEqual(
            MODULE.referencing_suites(RUNTIME, "job_queue"),
            [
                "test_job_queue",
                "test_leased_task_claim",
                "test_refusal_hold",
                "test_refusal_hold_queue_wiring",
            ],
        )

    def test_a_prose_mention_is_not_a_reference(self) -> None:
        # `test_graph_database.py` and `test_status_page.py` both MENTION
        # `job_queue.py` -- they quote its rules in a comment.  Neither
        # imports it, and neither exercises it.  A grep-based scope counts
        # them and measures suites that never touch the module.
        suites = MODULE.referencing_suites(RUNTIME, "job_queue")
        self.assertNotIn("test_graph_database", suites)
        self.assertNotIn("test_status_page", suites)

    def test_the_own_suite_comes_first(self) -> None:
        for base in ("job_queue", "status_page", "graph_database", "zero_knowledge"):
            suites = MODULE.referencing_suites(RUNTIME, base)
            self.assertTrue(suites, f"{base} resolved to no suite at all")
            self.assertEqual(
                suites[0],
                f"test_{base}",
                f"{base}'s own suite must come first",
            )

    def test_the_scope_is_deterministic(self) -> None:
        # A census log is only comparable between runs if the scope is
        # stable.  The sibling suites are sorted, not filesystem-ordered.
        first = MODULE.referencing_suites(RUNTIME, "job_queue")
        for _ in range(3):
            self.assertEqual(MODULE.referencing_suites(RUNTIME, "job_queue"), first)
        self.assertEqual(first[1:], sorted(first[1:]))


class CensusScopeShapeTests(unittest.TestCase):
    """The resolver must recognise every import shape the runtime uses."""

    def _resolve(self, sources: dict[str, str], base: str):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "tests").mkdir()
            for name, body in sources.items():
                (root / "tests" / name).write_text(body, encoding="utf-8")
            return MODULE.referencing_suites(root, base)

    def test_a_plain_import_is_a_reference(self) -> None:
        suites = self._resolve(
            {"test_thing.py": "import thing\n"}, "thing"
        )
        self.assertEqual(suites, ["test_thing"])

    def test_a_from_import_is_a_reference(self) -> None:
        suites = self._resolve(
            {"test_thing.py": "from thing import Thing\n"}, "thing"
        )
        self.assertEqual(suites, ["test_thing"])

    def test_a_parenthesised_from_import_is_a_reference(self) -> None:
        suites = self._resolve(
            {"test_thing.py": "from thing import (\n    Thing,\n    Other,\n)\n"},
            "thing",
        )
        self.assertEqual(suites, ["test_thing"])

    def test_a_mention_in_a_comment_is_not_a_reference(self) -> None:
        suites = self._resolve(
            {"test_thing.py": "# see thing.py's `_check_seq`\nimport os\n"},
            "thing",
        )
        self.assertEqual(suites, [])

    def test_a_mention_in_a_docstring_is_not_a_reference(self) -> None:
        suites = self._resolve(
            {"test_thing.py": '"""thing.py does the thing."""\nimport os\n'},
            "thing",
        )
        self.assertEqual(suites, [])

    def test_a_prefix_is_not_a_reference(self) -> None:
        # `thing_registry` is a different module.  A substring match would
        # count it, and the scope would then measure a suite that never
        # touches `thing`.
        suites = self._resolve(
            {"test_thing.py": "import thing_registry\n"}, "thing"
        )
        self.assertEqual(suites, [])

    def test_a_module_with_no_referencing_suite_resolves_to_empty(self) -> None:
        # The census script must SKIP such a module rather than fall back
        # to an arbitrary suite -- a fallback measures the wrong thing.
        suites = self._resolve({"test_other.py": "import other\n"}, "thing")
        self.assertEqual(suites, [])

    def test_the_resolver_is_not_vacuous(self) -> None:
        # A resolver that found nothing would satisfy the empty cases.
        suites = self._resolve(
            {"test_thing.py": "import thing\n", "test_other.py": "import os\n"},
            "thing",
        )
        self.assertEqual(suites, ["test_thing"])


if __name__ == "__main__":
    unittest.main()


#: The `ai_*` audit-event seq-guard family, pinned BY NAME.
#:
#: MEASURED 2026-11-26: the 162 `ai_*` modules whose audit-event
#: function guards a `seq` parameter with a bool/int discriminator.
#: `tests/test_ai_audit_seq_guard_family.py` loads all of them.
SEQ_GUARD_FAMILY = (
    "ai_accident",
    "ai_accountability",
    "ai_accountability_incident",
    "ai_accountability_mitigation",
    "ai_accountability_monitoring",
    "ai_accountability_remediation",
    "ai_accountability_risk",
    "ai_accountability_testing",
    "ai_accountability_threat",
    "ai_accountability_validation",
    "ai_accountability_verification",
    "ai_accountability_vulnerability",
    "ai_act",
    "ai_adversarial",
    "ai_alignment",
    "ai_attack",
    "ai_audit",
    "ai_benchmarking",
    "ai_bias",
    "ai_calibration",
    "ai_charter",
    "ai_compliance",
    "ai_compliance_incident",
    "ai_compliance_mitigation",
    "ai_compliance_monitoring",
    "ai_compliance_remediation",
    "ai_compliance_risk",
    "ai_compliance_testing",
    "ai_compliance_threat",
    "ai_compliance_validation",
    "ai_compliance_verification",
    "ai_compliance_vulnerability",
    "ai_concept",
    "ai_containment",
    "ai_contestability_incident",
    "ai_contestability_mitigation",
    "ai_contestability_monitoring",
    "ai_contestability_remediation",
    "ai_contestability_risk",
    "ai_contestability_testing",
    "ai_contestability_threat",
    "ai_contestability_validation",
    "ai_contestability_verification",
    "ai_contestability_vulnerability",
    "ai_counterfactual",
    "ai_defense",
    "ai_detection",
    "ai_distillation",
    "ai_distribution_shift",
    "ai_ensemble",
    "ai_ethics_incident",
    "ai_ethics_mitigation",
    "ai_ethics_monitoring",
    "ai_ethics_remediation",
    "ai_ethics_risk",
    "ai_ethics_testing",
    "ai_ethics_threat",
    "ai_ethics_validation",
    "ai_ethics_verification",
    "ai_ethics_vulnerability",
    "ai_evaluation",
    "ai_explainability",
    "ai_exploit",
    "ai_failure",
    "ai_fairness_incident",
    "ai_fairness_mitigation",
    "ai_fairness_monitoring",
    "ai_fairness_remediation",
    "ai_fairness_risk",
    "ai_fairness_testing",
    "ai_fairness_threat",
    "ai_fairness_validation",
    "ai_fairness_verification",
    "ai_fairness_vulnerability",
    "ai_feature",
    "ai_fuzzing",
    "ai_gating",
    "ai_harm",
    "ai_incident",
    "ai_isolation",
    "ai_mechanistic",
    "ai_mitigation",
    "ai_monitoring",
    "ai_ood_detection",
    "ai_oversight_incident",
    "ai_oversight_mitigation",
    "ai_oversight_monitoring",
    "ai_oversight_remediation",
    "ai_oversight_risk",
    "ai_oversight_testing",
    "ai_oversight_threat",
    "ai_oversight_validation",
    "ai_oversight_verification",
    "ai_oversight_vulnerability",
    "ai_pentesting",
    "ai_prevention",
    "ai_privacy",
    "ai_probing",
    "ai_pruning",
    "ai_quarantine",
    "ai_recovery",
    "ai_redress",
    "ai_redteaming",
    "ai_remediation",
    "ai_resilience",
    "ai_risk",
    "ai_robustness",
    "ai_robustness_incident",
    "ai_robustness_mitigation",
    "ai_robustness_monitoring",
    "ai_robustness_remediation",
    "ai_robustness_risk",
    "ai_robustness_testing",
    "ai_robustness_threat",
    "ai_robustness_validation",
    "ai_robustness_verification",
    "ai_robustness_vulnerability",
    "ai_safety",
    "ai_safety_incident",
    "ai_safety_mitigation",
    "ai_safety_monitoring",
    "ai_safety_remediation",
    "ai_safety_risk",
    "ai_safety_testing",
    "ai_safety_threat",
    "ai_safety_validation",
    "ai_safety_verification",
    "ai_safety_vulnerability",
    "ai_saliency",
    "ai_sandbox",
    "ai_security",
    "ai_stress_testing",
    "ai_surveillance",
    "ai_testing",
    "ai_threat",
    "ai_throttling",
    "ai_traceability_incident",
    "ai_traceability_mitigation",
    "ai_traceability_monitoring",
    "ai_traceability_remediation",
    "ai_traceability_risk",
    "ai_traceability_testing",
    "ai_traceability_threat",
    "ai_traceability_validation",
    "ai_traceability_verification",
    "ai_traceability_vulnerability",
    "ai_transparency",
    "ai_transparency_incident",
    "ai_transparency_mitigation",
    "ai_transparency_monitoring",
    "ai_transparency_remediation",
    "ai_transparency_risk",
    "ai_transparency_testing",
    "ai_transparency_threat",
    "ai_transparency_validation",
    "ai_transparency_verification",
    "ai_transparency_vulnerability",
    "ai_uncertainty",
    "ai_validation",
    "ai_verification",
    "ai_visualization",
    "ai_vulnerability",
)

class CensusScopeScaleTests(unittest.TestCase):
    """How many modules does the single-suite pairing get WRONG?

    A scope defect that touches one module is a bug.  A scope defect
    that touches a seventh of the runtime is a DESIGN defect, and the
    number is what says so.  So the number is measured and pinned.

    Measured 2026-11-25 over the runtime's 1620 top-level modules:
    **123** are referenced by more than one test suite, so the old
    single-suite pairing understated the scope for 7.6% of the runtime.

    **AMENDED 2026-11-25 (the dynamic-load fix).**  The first count was
    123, and it was computed by a resolver that read only STATIC
    imports.  519 of the runtime's suites load their module by FILE
    PATH, so the count understated the scope for a second reason -- and
    for **121 of the 270 rows** in the census artifact it understated it
    all the way to EMPTY, which made the census SKIP the row.

    With the dynamic loads read as well, the count is **133**.  The
    number is a measurement, so it moved; what did not move is the
    guard, which is what says so.

    **AMENDED 2026-11-26 (the `audit_cli` CLI-surface slice).**  The
    new `components/northstar-agent-runtime/tests/test_audit_cli_surface.py`
    drives `audit_cli.py`'s `verify-archive` command, so `audit_archive`
    now has TWO referencing suites and is itself multi-suite.  The
    count is **134**.

    The count moved for a REAL reason and not because the guard is
    loose: a module becomes multi-suite when a SECOND suite loads it,
    and this is a second suite loading it.  A count that moves is a
    count that was measured.

    **AMENDED 2026-11-26 (the `alignment_check` and `backpressure`
    slices).**  Two more suites, each loading its own module:
    `tests/test_alignment_check_surface.py` loads `alignment_check`,
    and `tests/test_backpressure_surface.py` loads `backpressure`.
    Both modules now have TWO referencing suites, so the count is
    **156**.

    **AMENDED 2026-11-26 (the `attack_extra_*` family slice).**  The
    new `components/northstar-agent-runtime/tests/test_attack_extra_family.py`
    loads ALL TWENTY `attack_extra_NN` modules, so every one of them now
    has TWO referencing suites -- its own, plus the family suite.  The
    count is **154**, exactly twenty more than 134, and the twenty new
    rows are exactly the twenty family modules.

    That the delta is EXACTLY twenty is the check that matters.  A
    family suite that loaded the twenty modules in a LOOP would have
    added ZERO to this count, because the scope resolver only sees a
    load whose module name is a LITERAL -- the same fact that made the
    family suite invisible to the census in the first place.  A guard
    that counts "modules with more than one suite" cannot tell the
    difference between "a second suite loads this" and "a second suite
    loads this", but a reader of this docstring can: the twenty rows
    listed below are the twenty that moved.

    **AMENDED 2026-11-26 (the `ai_*` import-guard family slice).**
    The new `components/northstar-agent-runtime/tests/
    test_ai_import_guard_family.py` loads ONE HUNDRED AND SEVENTY
    `ai_*` modules, so every one of them now has TWO referencing
    suites -- its own, plus the family suite.  The count is **326**.

    That the delta is EXACTLY 162 and not 170 is the check that
    matters, and it has the same cause as the twenty above: EIGHT of
    the family's modules -- the `ai_*_auditing` ones -- already had a
    second suite, from the previous slice, so they were already
    counted.  170 - 8 = 162.

    The family modules are pinned BY NAME below, for the same reason
    the twenty are: a count that moves is a count that was measured,
    but only if the reader can see WHICH rows moved.  And the family
    suite's own premise test asserts that every one of the 170 still
    carries the template, so a module that leaves the family is caught
    rather than silently carried by the cases.

    **AMENDED 2026-11-26 (the `ai_*` audit-event seq-guard family and
    the six bool-seq defect sites).**  Two more suites landed:

    * `components/northstar-agent-runtime/tests/
      test_ai_audit_seq_guard_family.py` loads ONE HUNDRED AND
      SIXTY-TWO `ai_*` modules -- the ones whose audit-event function
      guards a `seq` parameter with a bool/int discriminator.  The
      count moved 326 -> 335, and the delta is EXACTLY NINE, not 162:
      153 of the 162 are ALSO members of the import-guard family, so
      they were already counted.
    * `components/northstar-agent-runtime/tests/
      test_seq_bool_rejection.py` loads the SIX modules whose seq
      guard accepted a bool (`monitor_channel_probes`,
      `privilege_at_recall_probes`, `evidence_compaction_probes`,
      `fraud_detector`, `tax_calculator`, `mfa_manager`).  The count
      moved 335 -> 341.

    **AMENDED 2026-11-26 (the int-guard bool family, OUTSIDE the
    `ai_*` seq-guard family).**  One more suite landed:

    * `components/northstar-agent-runtime/tests/
      test_int_guard_bool_family.py` loads TWENTY-TWO modules whose int
      guards had no bool half.  The count moved 341 -> 361, and the
      delta is EXACTLY TWENTY, not twenty-two: `agent_identity` and
      `passport` were ALREADY multi-suite (their scopes were
      `test_agent_identity,test_identity_e1,test_passport` and
      `test_passport` respectively), so they were already counted.

    The delta is twenty because the family suite loads the modules by
    FILE PATH with an EXPLICIT LITERAL call -- the house loader shape
    the resolver recognises.  A module loaded from a dict literal is
    INVISIBLE to the resolver, and the family would then measure
    nothing.

    **AMENDED 2026-11-26 (the int-guard bool family, PART TWO).**  A
    second suite landed:

    * `components/northstar-agent-runtime/tests/
      test_int_guard_bool_family_part2.py` loads the EIGHTEEN modules
      whose int guards had no bool half and that the first family suite
      did not prove with a crafted input.  The count moved 361 -> 371,
      and the delta is EXACTLY EIGHTEEN: every one of the eighteen was
      single-suite before, so every one of them moved.

    The two suites do not overlap in what they LOAD: the first loads
    twenty-two modules, the second eighteen, and `vr_interface` is the
    only module in both -- it was already multi-suite when the first
    suite landed, so the first suite's delta did not include it, and
    the second suite's eighteen are all single-suite.

    **AMENDED 2026-11-26 (the int-guard bool family, PART THREE).**  A
    third suite landed:

    * `components/northstar-agent-runtime/tests/
      test_int_guard_bool_family_part3.py` loads the FOURTEEN modules
      that hold the LAST of the int-guard sites no crafted input had
      proved.  The count did NOT move: it is STILL 371, and the delta
      is EXACTLY ZERO.

    The zero is a fact about the family, not an accident.  Twelve of
    the fourteen were already multi-suite -- PART ONE moved twenty
    rows, PART TWO moved eighteen, and between them they cover every
    part-three module except `agent_identity` and `passport`, which
    were multi-suite before either suite landed.  So the count is
    BLIND to PART THREE: a suite that silently stopped loading one of
    its fourteen modules would leave the count at 371 and the scope
    pairing would fall back to the module's own suite, and NO count
    would say so.

    That is why the fourteen rows are pinned BY NAME, with the family
    suite's presence asserted directly.  A zero delta is exactly the
    case where the count cannot carry the claim and the names must.

    **AMENDED 2026-11-26 (the NUMERIC-guard bool family).**  A fourth
    suite landed:

    * `components/northstar-agent-runtime/tests/
      test_numeric_guard_bool_family.py` loads the EIGHT modules whose
      `isinstance(X, (int, float))` guards had no bool half.  The count
      moved 371 -> 378, and the delta is EXACTLY SEVEN.

    The seven are the eight minus `ask_or_solve_probes`, which was
    already multi-suite -- PART TWO loads it -- so the numeric suite's
    presence does not change its scope.  Every one of the other SEVEN
    was single-suite before, so every one of them moved.
    """

    def test_the_multi_suite_modules_are_counted(self) -> None:
        runtime = RUNTIME
        modules = sorted(p.stem for p in runtime.glob("*.py"))
        self.assertEqual(len(modules), 1621)
        multi = [
            stem for stem in modules
            if len(MODULE.referencing_suites(runtime, stem)) > 1
        ]
        self.assertEqual(
            len(multi), 378,
            "the number of modules whose scope the single-suite pairing "
            "understated",
        )

    def test_the_twenty_family_modules_are_multi_suite(self) -> None:
        # The delta above was EXACTLY twenty.  Pin the twenty by name,
        # so a family suite that silently stops loading some of them
        # cannot be absorbed into the count.  A count that moves is a
        # count that was measured -- but only if the reader can see
        # WHICH rows moved.
        for n in range(1, 21):
            stem = f"attack_extra_{n:02d}"
            suites = MODULE.referencing_suites(RUNTIME, stem)
            with self.subTest(module=stem):
                self.assertEqual(
                    suites, ["test_attack_extra_01".replace("01", f"{n:02d}"),
                             "test_attack_extra_family"],
                    f"{stem} is not multi-suite",
                )

    def test_the_int_guard_bool_family_modules_are_multi_suite(self) -> None:
        """The twenty newly-multi-suite rows, pinned by NAME.

        MEASURED 2026-11-26: `tests/test_int_guard_bool_family.py`
        loads TWENTY-TWO modules -- the ones whose int guards had no
        bool half.  Twenty of them became multi-suite (the count moved
        341 -> 361); `agent_identity` and `passport` were already
        multi-suite and were already counted.

        Pinned by name because the count alone cannot say WHICH rows
        moved, and a family suite that silently stops loading one of
        them would be absorbed into the count.  The expected scope is
        the module's own suite PLUS the family suite, read from the
        resolver, so a module that grows a third suite is still
        reported (and the assertion is on the family suite's PRESENCE,
        not on the exact list).

        The two that were ALREADY multi-suite are pinned separately:
        their count did not move, so a silent drop would show up as a
        count that does not move when it should.
        """
        newly = [
            "command_registry", "confidence_gate", "crypto_defense_14",
            "deployment_registry", "eldercare_agents", "evaluator_access",
            "game_agents", "herd_gate", "incident_receipts",
            "input_defense_13", "input_defense_26", "model_attack_18",
            "monitor_deafness_probes", "multi_attack_02", "multi_attack_04",
            "offline_bundle", "retail_agents", "synthetic_cap",
            "vendor_chain", "vr_interface",
        ]
        self.assertEqual(len(newly), 20, "the delta was exactly twenty")
        for stem in newly:
            suites = MODULE.referencing_suites(RUNTIME, stem)
            with self.subTest(module=stem):
                self.assertIn("test_int_guard_bool_family", suites)
                # The module's OWN suite, by NAME -- except where the
                # runtime's own suite is not named after the module:
                # `crypto_defense_14` is exercised by
                # `test_crypto_defenses` (plural), which is a fact
                # about the repo, not a guess.
                own = (
                    "test_crypto_defenses"
                    if stem == "crypto_defense_14"
                    else f"test_{stem}"
                )
                self.assertIn(own, suites)
                self.assertGreaterEqual(len(suites), 2)

    def test_the_two_already_multi_suite_family_modules_are_still_multi_suite(self) -> None:
        """The two the count did NOT move for.

        `agent_identity` and `passport` already had a second suite, so
        the family suite did not change their count.  If the family
        suite silently stopped loading them, the count would stay at
        361 and nothing would catch it -- so they are pinned by name.
        """
        for stem in ("agent_identity", "passport"):
            suites = MODULE.referencing_suites(RUNTIME, stem)
            with self.subTest(module=stem):
                self.assertIn("test_int_guard_bool_family", suites)
                self.assertIn(f"test_{stem}", suites)
                self.assertGreaterEqual(len(suites), 2)

    def test_the_int_guard_bool_family_part_two_modules_are_multi_suite(self) -> None:
        """The eighteen newly-multi-suite rows from PART TWO, by NAME.

        MEASURED 2026-11-26: `tests/test_int_guard_bool_family_part2.py`
        loads EIGHTEEN modules -- the ones whose int guards had no bool
        half and that the first family suite did not prove with a
        crafted input.  All eighteen were single-suite before, so the
        count moved 361 -> 371 and the delta is EXACTLY EIGHTEEN.

        Pinned by name for the same reason as the twenty above: the
        count alone cannot say WHICH rows moved, and a family suite that
        silently stops loading one of them would be absorbed into the
        count.

        The assertion is on the family suite's PRESENCE, not on the
        exact list, so a module that grows a third suite is still
        reported.  The module's OWN suite is checked by NAME, except
        where the runtime's own suite is not named after the module.
        """
        newly = [
            "ask_or_solve_probes", "audit_merkle", "compaction",
            "deployment_registry", "evaluator_access", "herd_gate",
            "hybrid_crypto", "mfa_manager", "model_lineage", "permissions",
            "permit_agents", "remote_attestation", "runtime_defense_05",
            "split_learning", "stream_guard", "tax_agents", "vr_interface",
            "watermark_tracker",
        ]
        self.assertEqual(len(newly), 18, "the delta was exactly eighteen")
        for stem in newly:
            suites = MODULE.referencing_suites(RUNTIME, stem)
            with self.subTest(module=stem):
                self.assertIn("test_int_guard_bool_family_part2", suites)
                own = (
                    "test_crypto_defenses"
                    if stem == "crypto_defense_14"
                    else f"test_{stem}"
                )
                self.assertIn(own, suites)
                self.assertGreaterEqual(len(suites), 2)

    def test_the_int_guard_bool_family_part_three_modules_are_multi_suite(self) -> None:
        """The PART THREE modules, pinned by NAME -- and the delta is ZERO.

        MEASURED 2026-11-26: `tests/test_int_guard_bool_family_part3.py`
        loads FOURTEEN modules -- the last of the int-guard sites that
        no crafted input had proved.  The count did NOT move: it is
        still 371.  The delta is EXACTLY ZERO, because all fourteen
        were ALREADY multi-suite -- twelve of them through PART ONE and
        PART TWO, and `agent_identity` and `passport` were multi-suite
        before either.

        That is exactly why the rows are pinned by NAME.  With a zero
        delta the count is BLIND to this suite: if it silently stopped
        loading a module, the count would stay 371 and the scope
        pairing would quietly fall back to the module's own suite --
        the family would measure nothing and no count would say so.

        So this test asserts the family suite's PRESENCE in each
        module's scope, not the count.
        """
        modules = [
            "agent_identity", "crypto_defense_14", "deployment_registry",
            "eldercare_agents", "evaluator_access", "incident_receipts",
            "input_defense_26", "monitor_deafness_probes", "offline_bundle",
            "passport", "retail_agents", "synthetic_cap", "vendor_chain",
            "vr_interface",
        ]
        self.assertEqual(len(modules), 14, "the family loads fourteen modules")
        for stem in modules:
            suites = MODULE.referencing_suites(RUNTIME, stem)
            with self.subTest(module=stem):
                self.assertIn("test_int_guard_bool_family_part3", suites)
                own = (
                    "test_crypto_defenses"
                    if stem == "crypto_defense_14"
                    else f"test_{stem}"
                )
                self.assertIn(own, suites)
                self.assertGreaterEqual(len(suites), 2)

    def test_the_numeric_guard_family_modules_are_multi_suite(self) -> None:
        """The NUMERIC family's seven new rows, pinned by NAME.

        MEASURED 2026-11-26: `tests/test_numeric_guard_bool_family.py`
        loads EIGHT modules -- the ones whose `isinstance(X, (int, float))`
        guards had no bool half.  The count moved 371 -> 378, and the
        delta is EXACTLY SEVEN: `ask_or_solve_probes` was already
        multi-suite through PART TWO, so the numeric suite's presence
        does not change its scope.

        The seven rows are pinned by NAME for the same reason the
        others are: a count that moves can carry the claim, but only
        if the reader can see WHICH rows moved.
        """
        moved = [
            "benchmark_retirement_probes", "constraint_synthesis_probes",
            "decision_model", "harness_binding", "model_attack_09",
            "moderation_agents", "orbital_agents",
        ]
        self.assertEqual(len(moved), 7, "the delta is exactly seven")
        for stem in moved:
            suites = MODULE.referencing_suites(RUNTIME, stem)
            with self.subTest(module=stem):
                self.assertIn("test_numeric_guard_bool_family", suites)
                self.assertIn(f"test_{stem}", suites)
                self.assertGreaterEqual(len(suites), 2)

    def test_the_numeric_family_loads_the_eighth_module_too(self) -> None:
        """The EIGHTH module the family loads is already multi-suite.

        `ask_or_solve_probes` is loaded by PART TWO as well, so its
        scope does not change -- but the family suite's presence in it
        is still asserted, because a suite that silently stopped
        loading a module would leave the count unmoved and the scope
        pairing quietly degraded.
        """
        suites = MODULE.referencing_suites(RUNTIME, "ask_or_solve_probes")
        with self.subTest(module="ask_or_solve_probes"):
            self.assertIn("test_numeric_guard_bool_family", suites)
            self.assertIn("test_int_guard_bool_family_part2", suites)

    def test_the_two_single_module_slices_are_multi_suite(self) -> None:
        # The same discipline as the twenty family modules: pin the
        # new multi-suite rows by NAME, so a suite that silently stops
        # loading its module cannot be absorbed into the count.
        for stem in ("alignment_check", "backpressure"):
            with self.subTest(module=stem):
                suites = MODULE.referencing_suites(RUNTIME, stem)
                self.assertEqual(len(suites), 2, f"{stem} is not multi-suite")
                self.assertIn(f"test_{stem}", suites)
                self.assertIn(f"test_{stem}_surface", suites)

    def test_the_ai_transparency_auditing_slice_is_multi_suite(self) -> None:
        # Measured 2026-11-26: the `ai_transparency_auditing` slice
        # added `tests/test_ai_transparency_auditing_surface.py`, which
        # loads the module -- so the module's scope is now TWO suites and
        # the count moved 156 -> 157.
        #
        # Pinned BY NAME, for the reason the twenty family modules are
        # pinned by name: a count that moves is a count that was
        # measured, but only if the reader can see WHICH rows moved.
        suites = MODULE.referencing_suites(RUNTIME, "ai_transparency_auditing")
        self.assertEqual(
            suites,
            ["test_ai_transparency_auditing",
             "test_ai_auditing_family_surface",
             "test_ai_import_guard_family",
             "test_ai_transparency_auditing_surface"],
            "ai_transparency_auditing is not multi-suite",
        )

    def test_the_ai_auditing_family_modules_are_multi_suite(self) -> None:
        """The eight sibling modules, pinned by NAME.

        MEASURED 2026-11-26: `tests/test_ai_auditing_family_surface.py`
        loads all eight `ai_*_auditing` modules, so seven of them (the
        eighth, `ai_transparency_auditing`, was already counted) became
        multi-suite -- the count moved 157 -> 164.

        Pinned by name because the count alone cannot say WHICH rows
        moved, and a family suite that silently stops loading one of
        them would be absorbed into the count.
        """
        family = (
            "ai_accountability_auditing",
            "ai_compliance_auditing",
            "ai_contestability_auditing",
            "ai_ethics_auditing",
            "ai_fairness_auditing",
            "ai_safety_auditing",
            "ai_traceability_auditing",
            "ai_transparency_auditing",
        )
        for stem in family:
            with self.subTest(module=stem):
                suites = MODULE.referencing_suites(RUNTIME, stem)
                self.assertIn(f"test_{stem}", suites)
                self.assertIn("test_ai_auditing_family_surface", suites)
                # `ai_transparency_auditing` carries a FOURTH suite:
                # the single-module surface suite of the slice that
                # found the family in the first place.
                #
                # And every one of the eight now carries a THIRD: the
                # `ai_*` import-guard family suite, because all eight
                # are members of that family too (measured 2026-11-26).
                expected = {
                    "ai_transparency_auditing": 4,
                }.get(stem, 3)
                self.assertEqual(
                    len(suites), expected, f"{stem} is not multi-suite"
                )

    def test_the_ai_import_guard_family_modules_are_multi_suite(self):
        """The 170 `ai_*` import-guard modules, pinned BY NAME.

        MEASURED 2026-11-26: `tests/test_ai_import_guard_family.py`
        loads all 170 of them, so 162 of them became multi-suite --
        the count moved 164 -> 326.  The eight `ai_*_auditing` modules
        already had a second suite, so they were already counted.

        Pinned by name because the count alone cannot say WHICH rows
        moved, and a family suite that silently stops loading one of
        them would be absorbed into the count.

        The list is the family's OWN membership: the modules whose
        `stdlib_only()` structurally matches the template -- it reads
        `__file__`, it has an `ast.Import` branch and an
        `ast.ImportFrom` branch, and each branch has its own
        `return False`.  A module that joins the family is expected to
        be picked up; one that leaves it is expected to fail the
        family's own premise test rather than this one.
        """
        family = (
            "ai_accident",
            "ai_accountability",
            "ai_accountability_auditing",
            "ai_accountability_incident",
            "ai_accountability_mitigation",
            "ai_accountability_monitoring",
            "ai_accountability_remediation",
            "ai_accountability_risk",
            "ai_accountability_testing",
            "ai_accountability_threat",
            "ai_accountability_validation",
            "ai_accountability_verification",
            "ai_accountability_vulnerability",
            "ai_adversarial",
            "ai_assurance",
            "ai_attack",
            "ai_audit",
            "ai_bias",
            "ai_calibration",
            "ai_charter",
            "ai_compliance",
            "ai_compliance_auditing",
            "ai_compliance_incident",
            "ai_compliance_mitigation",
            "ai_compliance_monitoring",
            "ai_compliance_remediation",
            "ai_compliance_risk",
            "ai_compliance_testing",
            "ai_compliance_threat",
            "ai_compliance_validation",
            "ai_compliance_verification",
            "ai_compliance_vulnerability",
            "ai_concept",
            "ai_containment",
            "ai_contestability_auditing",
            "ai_contestability_incident",
            "ai_contestability_mitigation",
            "ai_contestability_monitoring",
            "ai_contestability_remediation",
            "ai_contestability_risk",
            "ai_contestability_testing",
            "ai_contestability_threat",
            "ai_contestability_validation",
            "ai_contestability_verification",
            "ai_contestability_vulnerability",
            "ai_defense",
            "ai_distillation",
            "ai_distribution_shift",
            "ai_ensemble",
            "ai_ethics_auditing",
            "ai_ethics_incident",
            "ai_ethics_mitigation",
            "ai_ethics_monitoring",
            "ai_ethics_remediation",
            "ai_ethics_risk",
            "ai_ethics_testing",
            "ai_ethics_threat",
            "ai_ethics_validation",
            "ai_ethics_verification",
            "ai_ethics_vulnerability",
            "ai_exploit",
            "ai_failure",
            "ai_fairness_auditing",
            "ai_fairness_incident",
            "ai_fairness_mitigation",
            "ai_fairness_monitoring",
            "ai_fairness_remediation",
            "ai_fairness_risk",
            "ai_fairness_testing",
            "ai_fairness_threat",
            "ai_fairness_validation",
            "ai_fairness_verification",
            "ai_fairness_vulnerability",
            "ai_feature",
            "ai_fuzzing",
            "ai_governance",
            "ai_harm",
            "ai_incident",
            "ai_isolation",
            "ai_liability",
            "ai_mitigation",
            "ai_monitoring",
            "ai_ood_detection",
            "ai_oversight",
            "ai_oversight_auditing",
            "ai_oversight_incident",
            "ai_oversight_mitigation",
            "ai_oversight_monitoring",
            "ai_oversight_remediation",
            "ai_oversight_risk",
            "ai_oversight_testing",
            "ai_oversight_threat",
            "ai_oversight_validation",
            "ai_oversight_verification",
            "ai_oversight_vulnerability",
            "ai_pentesting",
            "ai_policy",
            "ai_prevention",
            "ai_privacy",
            "ai_probing",
            "ai_pruning",
            "ai_quarantine",
            "ai_recourse",
            "ai_recovery",
            "ai_redress",
            "ai_redteaming",
            "ai_regulation",
            "ai_remediation",
            "ai_resilience",
            "ai_risk",
            "ai_robustness",
            "ai_robustness_auditing",
            "ai_robustness_incident",
            "ai_robustness_mitigation",
            "ai_robustness_monitoring",
            "ai_robustness_remediation",
            "ai_robustness_risk",
            "ai_robustness_testing",
            "ai_robustness_threat",
            "ai_robustness_validation",
            "ai_robustness_verification",
            "ai_robustness_vulnerability",
            "ai_safety",
            "ai_safety_auditing",
            "ai_safety_incident",
            "ai_safety_mitigation",
            "ai_safety_monitoring",
            "ai_safety_remediation",
            "ai_safety_risk",
            "ai_safety_testing",
            "ai_safety_threat",
            "ai_safety_validation",
            "ai_safety_verification",
            "ai_safety_vulnerability",
            "ai_saliency",
            "ai_sandbox",
            "ai_security",
            "ai_stress_testing",
            "ai_surveillance",
            "ai_testing",
            "ai_threat",
            "ai_throttling",
            "ai_traceability_auditing",
            "ai_traceability_incident",
            "ai_traceability_mitigation",
            "ai_traceability_monitoring",
            "ai_traceability_remediation",
            "ai_traceability_risk",
            "ai_traceability_testing",
            "ai_traceability_threat",
            "ai_traceability_validation",
            "ai_traceability_verification",
            "ai_traceability_vulnerability",
            "ai_transparency",
            "ai_transparency_auditing",
            "ai_transparency_incident",
            "ai_transparency_mitigation",
            "ai_transparency_monitoring",
            "ai_transparency_remediation",
            "ai_transparency_risk",
            "ai_transparency_testing",
            "ai_transparency_threat",
            "ai_transparency_validation",
            "ai_transparency_verification",
            "ai_transparency_vulnerability",
            "ai_uncertainty",
            "ai_validation",
            "ai_verification",
            "ai_visualization",
            "ai_vulnerability",
        )
        self.assertEqual(len(family), 170)
        for stem in family:
            with self.subTest(module=stem):
                suites = MODULE.referencing_suites(RUNTIME, stem)
                self.assertIn(f"test_{stem}", suites)
                self.assertIn("test_ai_import_guard_family", suites)
                # A module that ALSO belongs to another family suite
                # carries more than two.  The `ai_*_auditing` eight
                # carry the auditing family suite as well, and
                # `ai_transparency_auditing` carries a fourth.
                # The eight that the AUDITING family suite loads carry
                # a third suite -- but only the ones that suite really
                # loads.  `ai_oversight_auditing` and
                # `ai_robustness_auditing` are members of THIS family
                # only, so they carry two.
                auditing = (
                    "ai_accountability_auditing",
                    "ai_compliance_auditing",
                    "ai_contestability_auditing",
                    "ai_ethics_auditing",
                    "ai_fairness_auditing",
                    "ai_safety_auditing",
                    "ai_traceability_auditing",
                    "ai_transparency_auditing",
                )
                expected = 3 if stem in auditing else 2
                if stem == "ai_transparency_auditing":
                    expected = 4
                # A module that is ALSO in the audit-event seq-guard
                # family carries the seq-guard family suite as well.
                # MEASURED 2026-11-26: 153 of the 170 are, and the
                # seventeen that are not are the `ai_*_auditing` eight
                # (already at 3 or 4) plus the nine that the seq-guard
                # family does not carry.
                if stem in SEQ_GUARD_FAMILY:
                    expected += 1
                self.assertEqual(
                    len(suites), expected,
                    f"{stem} is not multi-suite",
                )

    def test_the_ai_audit_seq_guard_family_modules_are_multi_suite(self):
        """The 162 `ai_*` audit-event seq-guard modules, pinned BY NAME.

        MEASURED 2026-11-26: `tests/test_ai_audit_seq_guard_family.py`
        loads all 162 of them, so NINE of them became multi-suite --
        the count moved 326 -> 335.  The delta is NINE and not 162
        because 153 of the 162 are ALSO members of the import-guard
        family, so they already carried a second suite.

        Pinned by name because the count alone cannot say WHICH rows
        moved, and a family suite that silently stops loading one of
        them would be absorbed into the count.

        The list is the family's OWN membership: the modules whose
        audit-event function's second parameter is named `seq` and
        whose body carries a bool/int discriminating guard on it.  A
        module that joins the family is expected to be picked up; one
        that leaves it is expected to fail the family's own premise
        test rather than this one.
        """
        family = SEQ_GUARD_FAMILY
        self.assertEqual(len(family), 162)
        for stem in family:
            with self.subTest(module=stem):
                suites = MODULE.referencing_suites(RUNTIME, stem)
                self.assertIn(f"test_{stem}", suites)
                self.assertIn("test_ai_audit_seq_guard_family", suites)

    def test_the_six_bool_seq_defect_modules_are_multi_suite(self):
        """The six modules whose seq guard accepted a bool.

        MEASURED 2026-11-26: `tests/test_seq_bool_rejection.py` loads
        all six, so each became multi-suite -- the count moved
        335 -> 341.

        The six are the exception to the repo's own convention: 1266
        of the runtime's seq-ish int guards spell the bool half out
        (`isinstance(seq, bool) or not isinstance(seq, int)`), and
        these six did not, so each of them accepted ``True`` where the
        other 1266 refused it.
        """
        six = (
            "evidence_compaction_probes",
            "fraud_detector",
            "mfa_manager",
            "monitor_channel_probes",
            "privilege_at_recall_probes",
            "tax_calculator",
        )
        for stem in six:
            with self.subTest(module=stem):
                suites = MODULE.referencing_suites(RUNTIME, stem)
                self.assertIn(f"test_{stem}", suites)
                self.assertIn("test_seq_bool_rejection", suites)

    def test_agents_is_exercised_by_eleven_suites(self) -> None:
        # The clearest case: `agents.py` has ONE own suite and TEN
        # siblings that exercise it.  A census that paired it with
        # `test_agents` alone would report survivors that ten other
        # suites catch.
        suites = MODULE.referencing_suites(RUNTIME, "agents")
        self.assertEqual(len(suites), 11)
        self.assertEqual(suites[0], "test_agents")


class TheScopeMustSeeDynamicLoadsTests(unittest.TestCase):
    """A STATIC import index is not the scope.

    THE DEFECT (measured 2026-11-25)
    --------------------------------
    ``scripts/census-scope.py`` decided "this suite exercises this
    module" by reading the suite's IMPORT statements from the AST.  That
    is right as far as it goes, and it is wrong about a third of the
    runtime.

    **519** of the runtime's suites do not import their module at all.
    They load it BY FILE PATH, because the module is not importable in
    isolation (it reaches for siblings that are not on the path) and the
    suite needs it standalone.  The house loader is::

        def _load(name):
            spec = importlib.util.spec_from_file_location(name, RUNTIME / f"{name}.py")
            module = importlib.util.module_from_spec(spec)
            sys.modules[name] = module
            spec.loader.exec_module(module)
            return module

        ap = _load("annotation_pin")

    For those suites the import index had no entry, so the scope
    resolver returned the EMPTY scope, and the census script printed::

        MUTANT SKIP: no test file exercises annotation_pin

    **121 of the 270 rows** in ``docs/baseline/mutant-census/census-v3.txt``
    name such a module.  So 121 of 270 measurements were SKIPped -- and
    a SKIP reads as a deliberate scope decision, so nothing looked
    wrong.

    The harm is not the SKIP itself.  It is that a SKIP is INVISIBLE: the
    artifact still holds a number for the row, the number was measured
    at the SINGLE-suite scope, and the row looked like a measurement.

    THE FIX
    -------
    The scope resolver now reads the dynamic loads too, so the union
    scope is the union of the suites that reach the module BY ANY MEANS.

    THE NON-VACUITY CONTROL
    -----------------------
    A resolver that read nothing at all would satisfy "the scope is not
    empty".  So every shape below is tested in BOTH directions: the
    shape must be FOUND, and a suite that does NOT contain it must not
    be counted.
    """

    def _resolve(self, sources: dict[str, str], base: str):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "tests").mkdir()
            for name, body in sources.items():
                (root / "tests" / name).write_text(body, encoding="utf-8")
            return MODULE.referencing_suites(root, base)

    def test_the_house_loader_is_seen(self) -> None:
        """The runtime's own loader shape, with double quotes."""
        suites = self._resolve(
            {
                "test_thing.py": (
                    "import importlib.util\n"
                    "import sys\n"
                    "from pathlib import Path\n"
                    "RUNTIME = Path(__file__).resolve().parent.parent\n"
                    "def _load(name):\n"
                    "    spec = importlib.util.spec_from_file_location("
                    "name, RUNTIME / f\"{name}.py\")\n"
                    "    module = importlib.util.module_from_spec(spec)\n"
                    "    sys.modules[name] = module\n"
                    "    spec.loader.exec_module(module)\n"
                    "    return module\n"
                    "t = _load(\"thing\")\n"
                )
            },
            "thing",
        )
        self.assertEqual(
            suites,
            ["test_thing"],
            "the house loader is how the runtime's suites reach their "
            "module; a resolver that cannot see it reports an EMPTY scope "
            "and the census SKIPs the row",
        )

    def test_the_house_loader_with_single_quotes_is_seen(self) -> None:
        """The same loader, single-quoted.

        Measured: half the runtime's suites write `f'{name}.py'` and half
        write `f"{name}.py"`.  A resolver that reads only one of them
        misses half the runtime -- and the miss is silent, because the
        other half still resolves.
        """
        suites = self._resolve(
            {
                "test_thing.py": (
                    "import importlib.util\n"
                    "import sys\n"
                    "from pathlib import Path\n"
                    "RUNTIME = Path(__file__).resolve().parent.parent\n"
                    "def _load(name):\n"
                    "    spec = importlib.util.spec_from_file_location("
                    "name, RUNTIME / f'{name}.py')\n"
                    "    module = importlib.util.module_from_spec(spec)\n"
                    "    sys.modules[name] = module\n"
                    "    spec.loader.exec_module(module)\n"
                    "    return module\n"
                    "t = _load(\"thing\")\n"
                )
            },
            "thing",
        )
        self.assertEqual(suites, ["test_thing"])

    def test_a_literal_spec_from_file_location_is_seen(self) -> None:
        suites = self._resolve(
            {
                "test_thing.py": (
                    "import importlib.util\n"
                    "import sys\n"
                    "from pathlib import Path\n"
                    "_MOD_PATH = Path(__file__).resolve().parent.parent / \"thing.py\"\n"
                    "_spec = importlib.util.spec_from_file_location(\"thing\", _MOD_PATH)\n"
                    "m = importlib.util.module_from_spec(_spec)\n"
                    "sys.modules[\"thing\"] = m\n"
                    "_spec.loader.exec_module(m)\n"
                )
            },
            "thing",
        )
        self.assertEqual(suites, ["test_thing"])

    def test_the_module_type_and_exec_pattern_is_seen(self) -> None:
        """The other house shape: `types.ModuleType` plus `exec`."""
        suites = self._resolve(
            {
                "test_thing.py": (
                    "import sys\n"
                    "import types\n"
                    "from pathlib import Path\n"
                    "_MODULE_PATH = Path(__file__).parent.parent / \"thing.py\"\n"
                    "def _load_module():\n"
                    "    src = _MODULE_PATH.read_text()\n"
                    "    mod = types.ModuleType(\"thing\")\n"
                    "    mod.__file__ = str(_MODULE_PATH)\n"
                    "    sys.modules[\"thing\"] = mod\n"
                    "    exec(compile(src, str(_MODULE_PATH), \"exec\"), mod.__dict__)\n"
                    "    return mod\n"
                    "t = _load_module()\n"
                )
            },
            "thing",
        )
        self.assertEqual(suites, ["test_thing"])

    def test_a_docstring_naming_the_module_is_not_a_reference(self) -> None:
        """A docstring is documentation, not a load.

        Without this, a suite whose DOCSTRING names a module would be
        counted as exercising it -- and the census would measure a suite
        that never touches the module.
        """
        suites = self._resolve(
            {
                "test_thing.py": (
                    '"""thing.py does the thing."""\n'
                    "import os\n"
                )
            },
            "thing",
        )
        self.assertEqual(suites, [])

    def test_a_prose_mention_is_still_not_a_reference(self) -> None:
        """The original rule still holds for prose."""
        suites = self._resolve(
            {
                "test_thing.py": (
                    "# see thing.py's `_check`\n"
                    "import os\n"
                )
            },
            "thing",
        )
        self.assertEqual(suites, [])

    def test_the_resolver_is_not_vacuous(self) -> None:
        """THE NON-VACUITY CONTROL.

        A resolver that found nothing would satisfy every "is not a
        reference" case above.  So the same tree must ALSO produce a
        real reference -- and the two must not be confused.
        """
        suites = self._resolve(
            {
                "test_thing.py": (
                    "import importlib.util\n"
                    "import sys\n"
                    "from pathlib import Path\n"
                    "RUNTIME = Path(__file__).resolve().parent.parent\n"
                    "def _load(name):\n"
                    "    spec = importlib.util.spec_from_file_location("
                    "name, RUNTIME / f\"{name}.py\")\n"
                    "    module = importlib.util.module_from_spec(spec)\n"
                    "    sys.modules[name] = module\n"
                    "    spec.loader.exec_module(module)\n"
                    "    return module\n"
                    "t = _load(\"thing\")\n"
                ),
                "test_other.py": (
                    '"""thing.py is mentioned here."""\n'
                    "import os\n"
                ),
            },
            "thing",
        )
        self.assertEqual(suites, ["test_thing"])


class TheCensusArtifactIsMeasuredTests(unittest.TestCase):
    """The census artifact's rows must resolve to a scope.

    THE DEFECT (measured 2026-11-25)
    --------------------------------
    121 of the 270 rows in ``docs/baseline/mutant-census/census-v3.txt``
    name a module that no suite imports STATICALLY, so the scope
    resolver returned the EMPTY scope and the census SKIPped the row.

    The SKIP was invisible: the artifact still carries a number for
    every row, measured at the SINGLE-suite scope, and a row that was
    never measured at the union scope looks exactly like a row that was
    measured and found wanting.

    So the guard is on the ARTIFACT: how many of its rows resolve to a
    scope today.  The number is a measurement and it is pinned, so a
    future resolver that loses the dynamic loads again fails HERE rather
    than silently in a census that nobody reads.
    """

    #: The rows that resolve to the EMPTY scope, and why that is right.
    #:
    #: ``ba_01``..``ba_04`` have no suite of their own
    #: and are mentioned only in PROSE elsewhere:
    #:
    #:   tests/test_py_modules_list.py:21   "ba_01", "ba_02", ...
    #:
    #: So the census SKIPs them, and that is the correct answer: no
    #: suite exercises them.  Every OTHER row must resolve.
    #:
    #: MEASURED 2026-11-26: ``allowlist`` LEFT this set.  It was here
    #: because the module had NO suite of its own -- only a prose
    #: mention in ``tests/test_action_card.py:52``.  The slice that
    #: gave ``allowlist`` a suite (``tests/test_allowlist_surface.py``)
    #: changed that, and a row that now RESOLVES must not stay in the
    #: exception set: an exception that no longer holds is a guard that
    #: has stopped guarding.
    EXPECTED_EMPTY = {"ba_01", "ba_02", "ba_03", "ba_04"}

    def _rows(self):
        import re

        artifact = (
            ROOT / "docs" / "baseline" / "mutant-census" / "census-v3.txt"
        )
        if not artifact.exists():
            self.skipTest(f"the census artifact is absent: {artifact}")
        text = artifact.read_text(encoding="utf-8")
        rows = []
        for line in text.splitlines():
            match = re.match(
                r"^(\S+) .*MUTANT RESULT: killed (\d+)/(\d+);", line)
            if match:
                rows.append(match.group(1))
        return rows

    def test_the_artifact_has_the_rows_it_is_expected_to_have(self) -> None:
        rows = self._rows()
        self.assertEqual(
            len(rows), 270,
            "the census artifact's row count changed; the guards below "
            "are stated against it",
        )

    def test_every_row_but_the_exceptions_resolves_to_a_scope(self) -> None:
        empty = []
        for module in self._rows():
            base = module[:-3] if module.endswith(".py") else module
            if not (RUNTIME / f"{base}.py").exists():
                continue
            if not MODULE.referencing_suites(RUNTIME, base):
                empty.append(module)
        self.assertEqual(
            sorted(empty),
            sorted(self.EXPECTED_EMPTY),
            "a census row that resolves to NO scope is a row the census "
            "SKIPS, and a SKIP is invisible: the artifact still carries a "
            "number for it.  Either the resolver cannot see the suite "
            "that exercises the module (the dynamic-load shapes), or the "
            "row genuinely has no suite",
        )

    def test_the_unresolved_rows_have_no_suite_of_their_own(self) -> None:
        """The exceptions must stay exceptions, for the stated reason."""
        for module in sorted(self.EXPECTED_EMPTY):
            own = RUNTIME / "tests" / f"test_{module}.py"
            self.assertFalse(
                own.exists(),
                f"{module} now has a suite of its own, so it must no "
                "longer be in the exception set",
            )
