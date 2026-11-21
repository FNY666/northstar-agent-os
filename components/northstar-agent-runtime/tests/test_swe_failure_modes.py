"""Tests for swe_failure_modes: classify failed patches, route each mode.

The four real paths are driven end to end here -- a failed patch is built,
classified, and routed to the check that can catch it -- plus the
classification-result shape, the UNKNOWN bucket, and the cost accounting.
"""

import unittest

from swe_failure_modes import (
    CLASSIFIABLE_MODES,
    ROUTE_ASSUMPTION_VERIFICATION,
    ROUTE_LAYER_CROSSING,
    ROUTE_REGRESSION_SUITE,
    ROUTE_REQUIREMENT_READBACK,
    RULE_ASSUMPTION_UNVERIFIED,
    RULE_INTEGRATION_OFF_TARGET,
    RULE_NONE,
    RULE_REQUIREMENT_UNMET,
    RULE_SYMPTOM_ONLY,
    SCHEMA_PIN,
    SWE_FAILURE_MODES_VERSION,
    FailureMode,
    CheckInput,
    CheckItem,
    CheckList,
    Classification,
    DeliveryCost,
    Evidence,
    FailureRecord,
    ModeCost,
    PatchChange,
    TestOutcome,
    apportion_cost_by_mode,
    classify,
    cost_per_delivery,
    cost_report,
    route,
)


def _record(**kw):
    """Build a FailureRecord with sensible defaults."""
    base = dict(
        instruction="do the thing",
        instruction_requirements=(),
        requirement_files={},
        changes=(),
        failed_tests=(),
        all_tests=(),
        repo_symbols=frozenset(),
        unknown_references=(),
        symptom_layer="",
        root_cause_layer="",
    )
    base.update(kw)
    return FailureRecord(**base)


class TestRequirementMissPath(unittest.TestCase):
    """Path (a): the instruction demanded a behaviour; the patch never
    touched the code that implements it."""

    def _record(self):
        return _record(
            instruction=(
                "The auth API must reject an expired token with a 401 "
                "instead of falling through to the session lookup."
            ),
            instruction_requirements=("reject an expired token",),
            requirement_files={"reject an expired token": "api/auth.py"},
            changes=(
                PatchChange(file="api/logging.py", symbols=("log_auth",)),
            ),
            failed_tests=(
                TestOutcome(
                    name="test_rejects_expired_token",
                    passed=False,
                    file="tests/test_auth.py",
                    line=42,
                ),
            ),
        )

    def test_classified_as_requirement_miss(self):
        result = classify(self._record())
        self.assertIs(result.mode, FailureMode.REQUIREMENT_MISS)
        self.assertEqual(result.rule, RULE_REQUIREMENT_UNMET)
        self.assertFalse(result.is_unknown)

    def test_evidence_names_the_test_file_and_line(self):
        result = classify(self._record())
        failing = [e for e in result.evidence if e.kind == "failing-test"]
        self.assertEqual(len(failing), 1)
        self.assertEqual(failing[0].detail, "test_rejects_expired_token")
        self.assertEqual(failing[0].file, "tests/test_auth.py")
        self.assertEqual(failing[0].line, 42)
        # the requirement gap is named too, not just the label
        gaps = [e for e in result.evidence if e.kind == "requirement-not-implemented"]
        self.assertEqual(len(gaps), 1)
        self.assertIn("reject an expired token", gaps[0].detail)
        self.assertEqual(gaps[0].file, "api/auth.py")

    def test_routes_to_instruction_diff_readback(self):
        record = self._record()
        checklist = route(classify(record), record)
        self.assertEqual(checklist.mode, FailureMode.REQUIREMENT_MISS)
        self.assertEqual(checklist.route, ROUTE_REQUIREMENT_READBACK)

    def test_checklist_lists_the_requirement_and_the_coverage_gap(self):
        record = self._record()
        checklist = route(classify(record), record)
        self.assertEqual(len(checklist.checks), 1)
        check = checklist.checks[0]
        self.assertEqual(check.name, "requirement-diff-readback")
        inputs = {i.name: i.value for i in check.inputs}
        self.assertEqual(inputs["required-behaviour"], "reject an expired token")
        self.assertEqual(inputs["implementation-file"], "api/auth.py")
        self.assertEqual(inputs["patch-coverage"], "NOT covered by patch")
        self.assertIn("api/logging.py", inputs["patch-changed-files"])
        self.assertTrue(check.criterion.strip())

    def test_a_patch_that_did_touch_the_requirement_is_not_a_requirement_miss(self):
        record = _record(
            instruction="The auth API must reject an expired token.",
            instruction_requirements=("reject an expired token",),
            requirement_files={"reject an expired token": "api/auth.py"},
            changes=(PatchChange(file="api/auth.py"),),
            failed_tests=(
                TestOutcome(name="test_rejects_expired_token", passed=False),
            ),
        )
        result = classify(record)
        self.assertNotEqual(result.mode, FailureMode.REQUIREMENT_MISS)


class TestIntegrationBreakPath(unittest.TestCase):
    """Path (b): the patch changed file X; a test in file Y, green
    before the patch, is red after it."""

    def _record(self):
        return _record(
            instruction="Make the invoice parser stricter about dates.",
            changes=(
                PatchChange(file="billing/parser.py", symbols=("parse_date",)),
            ),
            failed_tests=(
                TestOutcome(
                    name="test_legacy_invoice_still_parses",
                    passed=False,
                    file="tests/test_legacy_invoice.py",
                    line=88,
                    passed_before_patch=True,
                ),
            ),
        )

    def test_classified_as_integration_break(self):
        result = classify(self._record())
        self.assertIs(result.mode, FailureMode.INTEGRATION_BREAK)
        self.assertEqual(result.rule, RULE_INTEGRATION_OFF_TARGET)

    def test_evidence_names_the_broken_test_and_the_changed_file(self):
        result = classify(self._record())
        broken = [e for e in result.evidence if e.kind == "broken-by-patch"]
        self.assertEqual(len(broken), 1)
        self.assertIn("test_legacy_invoice_still_parses", broken[0].detail)
        self.assertEqual(broken[0].file, "tests/test_legacy_invoice.py")
        self.assertEqual(broken[0].line, 88)
        changed = [e for e in result.evidence if e.kind == "patch-changed-file"]
        self.assertEqual([e.detail for e in changed], ["billing/parser.py"])

    def test_routes_to_the_regression_suite(self):
        record = self._record()
        checklist = route(classify(record), record)
        self.assertEqual(checklist.mode, FailureMode.INTEGRATION_BREAK)
        self.assertEqual(checklist.route, ROUTE_REGRESSION_SUITE)

    def test_checklist_lists_the_broken_test_and_the_changed_file(self):
        record = self._record()
        checklist = route(classify(record), record)
        self.assertEqual(len(checklist.checks), 1)
        check = checklist.checks[0]
        self.assertEqual(check.name, "regression-suite")
        inputs = {i.name: i.value for i in check.inputs}
        self.assertEqual(inputs["broken-test"], "test_legacy_invoice_still_parses")
        self.assertIn("billing/parser.py", inputs["patch-changed-files"])
        self.assertTrue(check.criterion.strip())

    def test_a_test_that_was_already_red_is_not_an_integration_break(self):
        record = _record(
            instruction="Make the invoice parser stricter.",
            changes=(PatchChange(file="billing/parser.py"),),
            failed_tests=(
                TestOutcome(name="test_legacy_invoice_still_parses", passed=False,
                           file="tests/test_legacy_invoice.py",
                           passed_before_patch=False),
            ),
        )
        result = classify(record)
        self.assertNotEqual(result.mode, FailureMode.INTEGRATION_BREAK)

    def test_a_failing_test_inside_the_changed_file_is_not_an_integration_break(self):
        record = _record(
            instruction="Make the invoice parser stricter.",
            changes=(PatchChange(file="billing/parser.py"),),
            failed_tests=(
                TestOutcome(name="test_parse_date", passed=False,
                           file="tests/test_parser.py",
                           passed_before_patch=True),
            ),
        )
        result = classify(record)
        self.assertNotEqual(result.mode, FailureMode.INTEGRATION_BREAK)


class TestUnverifiedAssumptionPath(unittest.TestCase):
    """Path (c): the patch calls a name the codebase does not define."""

    def _record(self):
        return _record(
            instruction="Retry the upload when the network drops.",
            changes=(
                PatchChange(
                    file="net/upload.py",
                    symbols=("retry_with_backoff",),
                    added_lines=("    return retry_with_backoff(request, tries=3)",),
                ),
            ),
            repo_symbols=frozenset({"upload_once", "Request"}),
            failed_tests=(
                TestOutcome(name="test_upload_retries", passed=False,
                           file="tests/test_upload.py", line=15),
            ),
        )

    def test_classified_as_unverified_assumption(self):
        result = classify(self._record())
        self.assertIs(result.mode, FailureMode.UNVERIFIED_ASSUMPTION)
        self.assertEqual(result.rule, RULE_ASSUMPTION_UNVERIFIED)

    def test_evidence_names_the_absent_name(self):
        result = classify(self._record())
        absent = [e for e in result.evidence if e.kind == "unknown-reference"]
        self.assertEqual(len(absent), 1)
        self.assertIn("retry_with_backoff", absent[0].detail)
        self.assertIn("not defined", absent[0].detail)

    def test_routes_to_assumption_verification(self):
        record = self._record()
        checklist = route(classify(record), record)
        self.assertEqual(checklist.mode, FailureMode.UNVERIFIED_ASSUMPTION)
        self.assertEqual(checklist.route, ROUTE_ASSUMPTION_VERIFICATION)

    def test_checklist_lists_the_name_and_the_absence_evidence(self):
        record = self._record()
        checklist = route(classify(record), record)
        self.assertEqual(len(checklist.checks), 1)
        check = checklist.checks[0]
        self.assertEqual(check.name, "assumption-verification")
        inputs = {i.name: i.value for i in check.inputs}
        self.assertEqual(inputs["referenced-name"], "retry_with_backoff")
        self.assertIn("not defined", inputs["existence-evidence"])
        self.assertTrue(check.criterion.strip())

    def test_a_name_that_does_exist_is_not_an_unverified_assumption(self):
        record = _record(
            instruction="Retry the upload when the network drops.",
            changes=(
                PatchChange(file="net/upload.py", symbols=("upload_once",)),
            ),
            repo_symbols=frozenset({"upload_once", "Request"}),
            failed_tests=(
                TestOutcome(name="test_upload_retries", passed=False),
            ),
        )
        result = classify(record)
        self.assertNotEqual(result.mode, FailureMode.UNVERIFIED_ASSUMPTION)


class TestWrongLayerPath(unittest.TestCase):
    """Path (d): the symptom layer's test passes, a neighbouring layer's
    test fails."""

    def _record(self):
        return _record(
            instruction="Fix the crash the dashboard shows on startup.",
            changes=(PatchChange(file="ui/handler.py"),),
            all_tests=(
                TestOutcome(name="test_handler_startup", passed=True,
                           file="tests/test_handler.py", line=12),
                TestOutcome(name="test_store_load", passed=False,
                           file="tests/test_store.py", line=31),
            ),
            symptom_layer="ui/handler.py",
            root_cause_layer="store/store.py",
        )

    def test_classified_as_wrong_layer(self):
        result = classify(self._record())
        self.assertIs(result.mode, FailureMode.WRONG_LAYER)
        self.assertEqual(result.rule, RULE_SYMPTOM_ONLY)

    def test_evidence_names_both_layers(self):
        result = classify(self._record())
        green = [e for e in result.evidence if e.kind == "symptom-test-passed"]
        red = [e for e in result.evidence if e.kind == "root-cause-test-failed"]
        self.assertEqual([e.detail for e in green], ["test_handler_startup"])
        self.assertEqual([e.detail for e in red], ["test_store_load"])
        self.assertEqual(red[0].file, "tests/test_store.py")
        self.assertEqual(red[0].line, 31)
        split = [e for e in result.evidence if e.kind == "layer-split"]
        self.assertEqual(len(split), 1)
        self.assertIn("ui/handler.py", split[0].detail)
        self.assertIn("store/store.py", split[0].detail)

    def test_routes_to_the_layer_crossing_check(self):
        record = self._record()
        checklist = route(classify(record), record)
        self.assertEqual(checklist.mode, FailureMode.WRONG_LAYER)
        self.assertEqual(checklist.route, ROUTE_LAYER_CROSSING)

    def test_checklist_lists_the_symptom_layer_and_the_root_cause_layer(self):
        record = self._record()
        checklist = route(classify(record), record)
        self.assertEqual(len(checklist.checks), 1)
        check = checklist.checks[0]
        self.assertEqual(check.name, "layer-crossing-check")
        inputs = {i.name: i.value for i in check.inputs}
        self.assertEqual(inputs["symptom-layer"], "ui/handler.py")
        self.assertEqual(inputs["root-cause-layer"], "store/store.py")
        self.assertTrue(check.criterion.strip())

    def test_a_failure_with_no_layer_split_is_not_wrong_layer(self):
        record = _record(
            instruction="Fix the crash.",
            changes=(PatchChange(file="ui/handler.py"),),
            failed_tests=(
                TestOutcome(name="test_store_load", passed=False,
                           file="tests/test_store.py"),
            ),
        )
        result = classify(record)
        self.assertNotEqual(result.mode, FailureMode.WRONG_LAYER)


class TestUnknownBucket(unittest.TestCase):
    """A failure that fits none of the four modes is reported as
    UNKNOWN -- never forced into the nearest category."""

    def test_a_failure_with_no_signal_is_unknown(self):
        result = classify(_record(instruction="do something"))
        self.assertIs(result.mode, FailureMode.UNKNOWN)
        self.assertTrue(result.is_unknown)
        self.assertEqual(result.rule, RULE_NONE)

    def test_unknown_is_not_one_of_the_four_modes(self):
        result = classify(_record(instruction="do something"))
        self.assertNotIn(result.mode, CLASSIFIABLE_MODES)

    def test_unknown_routes_to_triage_with_its_own_evidence(self):
        record = _record(
            instruction="do something",
            failed_tests=(TestOutcome(name="test_mystery", passed=False,
                                      file="tests/test_mystery.py", line=3),),
        )
        result = classify(record)
        checklist = route(result, record)
        self.assertEqual(checklist.mode, FailureMode.UNKNOWN)
        self.assertEqual(checklist.route, "unknown-triage")
        inputs = {i.name: i.value for i in checklist.checks[0].inputs}
        self.assertIn("test_mystery", inputs["failed-tests"])

    def test_the_reason_says_why_it_did_not_fit(self):
        result = classify(_record(instruction="do something"))
        self.assertIn("no rule matched", result.reason)


class TestClassificationShape(unittest.TestCase):
    """The result carries the rule and the evidence -- never a bare
    label."""

    def test_the_result_never_carries_a_bare_label(self):
        record = _record(
            instruction="reject an expired token",
            instruction_requirements=("reject an expired token",),
            requirement_files={"reject an expired token": "api/auth.py"},
            failed_tests=(TestOutcome(name="test_rejects_expired_token",
                                      passed=False, file="tests/test_auth.py",
                                      line=42),),
        )
        result = classify(record)
        self.assertTrue(result.rule.strip())
        self.assertTrue(result.reason.strip())
        self.assertTrue(result.evidence)
        self.assertIn("test_rejects_expired_token", result.failed_tests)

    def test_the_result_serializes_with_schema_and_evidence(self):
        result = classify(_record(
            instruction="reject an expired token",
            instruction_requirements=("reject an expired token",),
            requirement_files={"reject an expired token": "api/auth.py"},
            failed_tests=(TestOutcome(name="test_rejects_expired_token",
                                      passed=False, file="tests/test_auth.py",
                                      line=42),),
        ))
        payload = result.as_dict()
        self.assertEqual(payload["mode"], "requirement-miss")
        self.assertEqual(payload["rule"], RULE_REQUIREMENT_UNMET)
        self.assertEqual(payload["schema"], SCHEMA_PIN)
        self.assertTrue(payload["evidence"])
        kinds = {e["kind"] for e in payload["evidence"]}
        self.assertIn("failing-test", kinds)
        self.assertIn("requirement-not-implemented", kinds)

    def test_classify_rejects_a_non_record(self):
        with self.assertRaises(ValueError):
            classify({"instruction": "not a record"})

    def test_the_module_pins_its_version(self):
        self.assertTrue(SWE_FAILURE_MODES_VERSION.startswith("swe-failure-modes."))


class TestCheckListStructure(unittest.TestCase):
    """Every route's checklist has the same fixed shape: check name +
    inputs + criterion."""

    def _one_of_each(self):
        return {
            FailureMode.REQUIREMENT_MISS: _record(
                instruction="reject an expired token",
                instruction_requirements=("reject an expired token",),
                requirement_files={"reject an expired token": "api/auth.py"},
                changes=(PatchChange(file="api/other.py"),),
                failed_tests=(TestOutcome(name="test_rejects_expired_token",
                                          passed=False),),
            ),
            FailureMode.INTEGRATION_BREAK: _record(
                instruction="parse dates",
                changes=(PatchChange(file="billing/parser.py"),),
                failed_tests=(TestOutcome(name="test_legacy", passed=False,
                                          file="tests/test_legacy.py",
                                          passed_before_patch=True),),
            ),
            FailureMode.UNVERIFIED_ASSUMPTION: _record(
                instruction="retry the upload",
                changes=(PatchChange(file="net/upload.py",
                                     symbols=("retry_with_backoff",)),),
                repo_symbols=frozenset({"upload_once"}),
                failed_tests=(TestOutcome(name="test_upload", passed=False),),
            ),
            FailureMode.WRONG_LAYER: _record(
                instruction="fix the crash",
                all_tests=(
                    TestOutcome(name="test_handler", passed=True,
                               file="tests/test_handler.py"),
                    TestOutcome(name="test_store", passed=False,
                               file="tests/test_store.py"),
                ),
                symptom_layer="ui/handler.py",
                root_cause_layer="store/store.py",
            ),
        }

    def test_every_mode_produces_a_checklist_of_the_same_shape(self):
        for mode, record in self._one_of_each().items():
            result = classify(record)
            self.assertEqual(result.mode, mode)
            checklist = route(result, record)
            self.assertTrue(checklist.route.strip())
            self.assertTrue(checklist.checks)
            for check in checklist.checks:
                self.assertTrue(check.name.strip())
                self.assertTrue(check.criterion.strip())
                self.assertTrue(check.inputs)
                for item in check.inputs:
                    self.assertTrue(item.name.strip())
                    self.assertIsInstance(item.value, str)

    def test_the_checklist_serializes_to_the_fixed_fields(self):
        record = self._one_of_each()[FailureMode.INTEGRATION_BREAK]
        checklist = route(classify(record), record)
        payload = checklist.as_dict()
        self.assertEqual(payload["mode"], "integration-break")
        self.assertEqual(payload["route"], ROUTE_REGRESSION_SUITE)
        for check in payload["checks"]:
            self.assertEqual(sorted(check), ["criterion", "inputs", "kind", "name"])

    def test_the_routes_are_the_pinned_four(self):
        records = self._one_of_each()
        routes = {
            mode: route(classify(record), record).route
            for mode, record in records.items()
        }
        self.assertEqual(routes[FailureMode.REQUIREMENT_MISS], ROUTE_REQUIREMENT_READBACK)
        self.assertEqual(routes[FailureMode.INTEGRATION_BREAK], ROUTE_REGRESSION_SUITE)
        self.assertEqual(routes[FailureMode.UNVERIFIED_ASSUMPTION],
                         ROUTE_ASSUMPTION_VERIFICATION)
        self.assertEqual(routes[FailureMode.WRONG_LAYER], ROUTE_LAYER_CROSSING)

    def test_route_rejects_a_non_classification(self):
        with self.assertRaises(ValueError):
            route({"mode": "requirement-miss"})


class TestFailClosedRecords(unittest.TestCase):
    """The record shapes refuse values outside their closed set, rather
    than accepting them and mis-classifying later."""

    def test_a_test_outcome_needs_a_name(self):
        with self.assertRaises(ValueError):
            TestOutcome(name="", passed=False)

    def test_a_test_outcome_needs_a_bool_passed(self):
        with self.assertRaises(ValueError):
            TestOutcome(name="t", passed="yes")

    def test_a_test_outcome_line_is_a_non_negative_int(self):
        with self.assertRaises(ValueError):
            TestOutcome(name="t", passed=False, line=-1)
        with self.assertRaises(ValueError):
            TestOutcome(name="t", passed=False, line="12")

    def test_a_test_outcome_before_patch_flag_is_a_bool_or_none(self):
        with self.assertRaises(ValueError):
            TestOutcome(name="t", passed=False, passed_before_patch="yes")

    def test_a_patch_change_needs_a_file(self):
        with self.assertRaises(ValueError):
            PatchChange(file="")

    def test_a_failure_record_needs_a_mapping_for_requirement_files(self):
        with self.assertRaises(ValueError):
            FailureRecord(instruction="x", requirement_files=[("a", "b")])

    def test_a_classification_needs_a_rule(self):
        with self.assertRaises(ValueError):
            Classification(mode=FailureMode.UNKNOWN, rule="", reason="x")

    def test_a_check_item_needs_a_criterion(self):
        with self.assertRaises(ValueError):
            CheckItem(name="c", inputs=(), criterion="")

    def test_a_delivery_cost_rejects_a_negative_delivery_count(self):
        with self.assertRaises(ValueError):
            cost_per_delivery(total_cost=10.0, verified_deliveries=-1)

    def test_a_check_input_needs_a_name(self):
        with self.assertRaises(ValueError):
            CheckInput(name="", value="v")


class TestCostPerDelivery(unittest.TestCase):

    def test_cost_per_delivery_divides_by_verified_deliveries(self):
        cost = cost_per_delivery(total_cost=69.60, verified_deliveries=4,
                                  total_runs=10, cost_per_run=6.96)
        self.assertAlmostEqual(cost.cost_per_delivery, 17.40)
        self.assertEqual(cost.verified_deliveries, 4)
        self.assertEqual(cost.total_runs, 10)

    def test_the_divisor_is_the_deliveries_not_the_runs(self):
        cost = cost_per_delivery(total_cost=100.0, verified_deliveries=5,
                                  total_runs=20)
        self.assertAlmostEqual(cost.cost_per_delivery, 20.0)
        # not 100/20 = 5.0
        self.assertNotAlmostEqual(cost.cost_per_delivery, 5.0)

    def test_no_deliveries_reports_no_evidence_not_zero(self):
        cost = cost_per_delivery(total_cost=100.0, verified_deliveries=0)
        self.assertIsNone(cost.cost_per_delivery)

    def test_the_report_serializes_the_delivery_number(self):
        cost = cost_per_delivery(total_cost=69.60, verified_deliveries=4,
                                 total_runs=10, cost_per_run=6.96)
        payload = cost.as_dict()
        self.assertAlmostEqual(payload["cost_per_delivery"], 17.40)
        self.assertEqual(payload["verified_deliveries"], 4)
        self.assertEqual(payload["total_runs"], 10)


class TestCostApportionedByMode(unittest.TestCase):
    """After classification, cost is apportioned across failure modes."""

    def test_each_mode_carries_its_own_cost_and_resolution_count(self):
        by_mode = apportion_cost_by_mode(
            mode_costs={
                FailureMode.REQUIREMENT_MISS: 40.0,
                FailureMode.INTEGRATION_BREAK: 20.0,
                FailureMode.UNVERIFIED_ASSUMPTION: 10.0,
                FailureMode.WRONG_LAYER: 5.0,
            },
            mode_resolved={
                FailureMode.REQUIREMENT_MISS: 2,
                FailureMode.INTEGRATION_BREAK: 1,
                FailureMode.UNVERIFIED_ASSUMPTION: 0,
                FailureMode.WRONG_LAYER: 1,
            },
        )
        by_name = {m.mode: m for m in by_mode}
        self.assertEqual(by_name[FailureMode.REQUIREMENT_MISS].cost, 40.0)
        self.assertEqual(by_name[FailureMode.REQUIREMENT_MISS].resolved, 2)
        self.assertAlmostEqual(
            by_name[FailureMode.REQUIREMENT_MISS].cost_per_delivery, 20.0)
        self.assertAlmostEqual(
            by_name[FailureMode.INTEGRATION_BREAK].cost_per_delivery, 20.0)
        self.assertIsNone(
            by_name[FailureMode.UNVERIFIED_ASSUMPTION].cost_per_delivery)

    def test_every_mode_appears_even_when_it_never_fired(self):
        by_mode = apportion_cost_by_mode(
            mode_costs={FailureMode.REQUIREMENT_MISS: 10.0},
            mode_resolved={FailureMode.REQUIREMENT_MISS: 1},
        )
        self.assertEqual(len(by_mode), 5)
        self.assertEqual(
            [m.mode for m in by_mode],
            [
                FailureMode.REQUIREMENT_MISS,
                FailureMode.INTEGRATION_BREAK,
                FailureMode.UNVERIFIED_ASSUMPTION,
                FailureMode.WRONG_LAYER,
                FailureMode.UNKNOWN,
            ],
        )
        never = [m for m in by_mode if m.mode is FailureMode.WRONG_LAYER][0]
        self.assertEqual(never.cost, 0.0)
        self.assertEqual(never.resolved, 0)
        self.assertIsNone(never.cost_per_delivery)

    def test_the_full_report_carries_both_halves(self):
        report = cost_report(
            total_cost=75.0,
            verified_deliveries=3,
            mode_costs={
                FailureMode.REQUIREMENT_MISS: 50.0,
                FailureMode.INTEGRATION_BREAK: 25.0,
            },
            mode_resolved={
                FailureMode.REQUIREMENT_MISS: 2,
                FailureMode.INTEGRATION_BREAK: 1,
            },
            total_runs=9,
            cost_per_run=8.33,
        )
        self.assertAlmostEqual(report.delivery.cost_per_delivery, 25.0)
        payload = report.as_dict()
        self.assertEqual(len(payload["by_mode"]), 5)
        self.assertAlmostEqual(payload["by_mode"][0]["cost"], 50.0)
        self.assertEqual(payload["by_mode"][0]["resolved"], 2)

    def test_the_module_does_no_estimation(self):
        # every number in the report comes from the caller
        report = cost_report(
            total_cost=13.0,
            verified_deliveries=2,
            mode_costs={FailureMode.UNKNOWN: 13.0},
            mode_resolved={FailureMode.UNKNOWN: 2},
        )
        self.assertAlmostEqual(report.delivery.cost_per_delivery, 6.5)
        self.assertAlmostEqual(report.by_mode[-1].cost_per_delivery, 6.5)


class TestSweFailureModesGuardArms(unittest.TestCase):
    """The MISSING arm of every two-armed type guard in this module.

    Each of the guards below is written ``if not isinstance(x, T) or
    <second half>``.  The existing suite drove the FIRST half (a
    wrong-typed value) and left the second half untested, so the
    ``or`` -> ``and`` mutant at that line survived: under the mutant the
    second half is never consulted, and the value the second half exists
    to reject is accepted.

    Two families live here:

    * the ``bool`` half -- ``bool`` IS an ``int`` in Python, so
      ``isinstance(True, int)`` is True and only the explicit ``bool``
      half refuses a boolean;
    * the "not an int" half -- a non-integer value of any other type.

    The two halves are killed independently: each mutant at a given line
    needs an input that the OTHER half already rejects.
    """

    # --- or@279: the "non-empty string" half of the evidence-kind guard --
    def test_a_blank_evidence_kind_is_refused(self):
        """`or@279`: the guard's second half -- a blank kind.

        The guard is ``not isinstance(self.kind, str) or not
        self.kind.strip()``.  The "not a string" half never refuses a
        blank string -- only the ``.strip()`` half does.  Under the
        mutant (``or`` -> ``and``) a whitespace-only kind is accepted.
        """
        with self.assertRaises(ValueError):
            Evidence(kind="   ", detail="a detail")

    def test_a_non_string_evidence_kind_is_refused(self):
        """`or@279`: the other half, as the control."""
        with self.assertRaises(ValueError):
            Evidence(kind=42, detail="a detail")

    # --- or@283: the "not an int" half of the evidence-line guard ------
    def test_a_boolean_evidence_line_is_refused(self):
        """`or@283`: **a bool IS an int in Python**.

        The guard is ``not isinstance(self.line, int) or isinstance(self
        .line, bool)``.  The "not an int" half never refuses a bool --
        only the explicit ``bool`` half does.  Under the mutant a
        boolean line is accepted and used as the integer 0 or 1.
        """
        with self.assertRaises(ValueError):
            Evidence(kind="kind", detail="a detail", line=True)

    def test_a_false_boolean_evidence_line_is_refused_too(self):
        """`or@283`: the other boolean."""
        with self.assertRaises(ValueError):
            Evidence(kind="kind", detail="a detail", line=False)

    def test_a_float_evidence_line_is_refused(self):
        """`or@283`: the other half, as the control."""
        with self.assertRaises(ValueError):
            Evidence(kind="kind", detail="a detail", line=1.5)

    # --- or@847: the "non-empty string" half of the check-name guard --
    def test_a_blank_check_name_is_refused(self):
        """`or@847`: the guard's second half -- a blank name.

        ``not isinstance(self.name, str) or not self.name.strip()``.
        Under the mutant a whitespace-only check name is accepted, and
        the check becomes unnameable.
        """
        with self.assertRaises(ValueError):
            CheckItem(name="   ", criterion="a criterion")

    def test_a_non_string_check_name_is_refused(self):
        """`or@847`: the other half, as the control."""
        with self.assertRaises(ValueError):
            CheckItem(name=7, criterion="a criterion")

    # --- or@881: the "non-empty string" half of the route guard --------
    def test_a_blank_route_is_refused(self):
        """`or@881`: the guard's second half -- a blank route.

        ``not isinstance(self.route, str) or not self.route.strip()``.
        Under the mutant a whitespace-only route is accepted, and the
        checklist claims to route somewhere that does not exist.
        """
        with self.assertRaises(ValueError):
            CheckList(mode=FailureMode.UNKNOWN, route="   ")

    def test_a_non_string_route_is_refused(self):
        """`or@881`: the other half, as the control."""
        with self.assertRaises(ValueError):
            CheckList(mode=FailureMode.UNKNOWN, route=7)

    # --- or@1264: the "not a bool" half of the total-cost guard -------
    def test_a_boolean_total_cost_is_refused(self):
        """`or@1264`: **a bool IS a number in Python**.

        The guard is ``not isinstance(self.total_cost, (int, float)) or
        isinstance(self.total_cost, bool)``.  The "not a number" half
        never refuses a bool -- only the explicit ``bool`` half does.
        Under the mutant a boolean total cost is accepted and booked as
        the integer 1.
        """
        with self.assertRaises(ValueError):
            DeliveryCost(total_cost=True, verified_deliveries=1)

    def test_a_string_total_cost_is_refused(self):
        """`or@1264`: the other half, as the control."""
        with self.assertRaises(ValueError):
            DeliveryCost(total_cost="1.0", verified_deliveries=1)

    # --- or@1268: the "not an int" half of the delivery-count guard ---
    def test_a_boolean_verified_delivery_count_is_refused(self):
        """`or@1268`: **a bool IS an int in Python**.

        The guard is ``not isinstance(self.verified_deliveries, int) or
        isinstance(self.verified_deliveries, bool)``.  Under the mutant
        ``verified_deliveries=True`` is accepted and used as 1.
        """
        with self.assertRaises(ValueError):
            DeliveryCost(total_cost=1.0, verified_deliveries=True)

    def test_a_float_verified_delivery_count_is_refused(self):
        """`or@1268`: the other half, as the control."""
        with self.assertRaises(ValueError):
            DeliveryCost(total_cost=1.0, verified_deliveries=2.0)

    # --- or@1274: the "not an int" half of the total-runs guard -------
    def test_a_boolean_total_runs_count_is_refused(self):
        """`or@1274`: **a bool IS an int in Python**.

        The guard is ``not isinstance(self.total_runs, int) or isinstance
        (self.total_runs, bool)``.  Under the mutant a boolean run
        count is accepted and reported as 1.
        """
        with self.assertRaises(ValueError):
            DeliveryCost(total_cost=1.0, verified_deliveries=1, total_runs=True)

    def test_a_float_total_runs_count_is_refused(self):
        """`or@1274`: the other half, as the control."""
        with self.assertRaises(ValueError):
            DeliveryCost(total_cost=1.0, verified_deliveries=1, total_runs=3.0)

    # --- or@1314: the "not a bool" half of the mode-cost guard --------
    def test_a_boolean_mode_cost_is_refused(self):
        """`or@1314`: **a bool IS a number in Python**.

        The guard is ``not isinstance(self.cost, (int, float)) or
        isinstance(self.cost, bool)``.  Under the mutant a boolean cost
        is accepted and apportioned as the integer 1.
        """
        with self.assertRaises(ValueError):
            ModeCost(mode=FailureMode.UNKNOWN, cost=True, resolved=0)

    def test_a_string_mode_cost_is_refused(self):
        """`or@1314`: the other half, as the control."""
        with self.assertRaises(ValueError):
            ModeCost(mode=FailureMode.UNKNOWN, cost="1.0", resolved=0)

    # --- or@1316: the "not an int" half of the resolved-count guard ---
    def test_a_boolean_resolved_count_is_refused(self):
        """`or@1316`: **a bool IS an int in Python**.

        The guard is ``not isinstance(self.resolved, int) or isinstance
        (self.resolved, bool)``.  Under the mutant a boolean resolution
        count is accepted and used as 1.
        """
        with self.assertRaises(ValueError):
            ModeCost(mode=FailureMode.UNKNOWN, cost=1.0, resolved=True)

    def test_a_float_resolved_count_is_refused(self):
        """`or@1316`: the other half, as the control."""
        with self.assertRaises(ValueError):
            ModeCost(mode=FailureMode.UNKNOWN, cost=1.0, resolved=2.0)
