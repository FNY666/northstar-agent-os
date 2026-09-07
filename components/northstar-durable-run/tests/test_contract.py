import importlib
import json
import sys
import unittest
from pathlib import Path

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(COMPONENT_ROOT))


RUN = {
    "schema_version": "northstar.durable-run.v1",
    "task_id": "task-001",
    "thread_id": "thread-001",
    "run_id": "run-001",
    "parent_run_id": None,
    "status": "planned",
    "deadline_at": 2_000,
    "scope_snapshot": ["workspace:read", "workspace:write"],
    "trace_id": "trace-001",
}

STEP = {
    "schema_version": "northstar.durable-step.v1",
    "task_id": "task-001",
    "thread_id": "thread-001",
    "run_id": "run-001",
    "step_id": "planner",
    "step_version": 1,
    "status": "planned",
    "attempt": 1,
    "input_digest": "sha256:" + "1" * 64,
    "scope_snapshot": ["workspace:read"],
    "idempotency_key": "run-001-planner-1",
    "expected_postconditions": ["plan_schema_valid"],
    "trace_id": "trace-001",
    "deadline_at": 1_900,
}

EVENT = {
    "schema_version": "northstar.durable-event.v1",
    "event_id": "event-001",
    "task_id": "task-001",
    "thread_id": "thread-001",
    "run_id": "run-001",
    "step_id": "planner",
    "sequence": 1,
    "event_type": "step.planned",
    "status": "planned",
    "occurred_at": 1_000,
    "idempotency_key": "run-001-planner-planned-1",
    "trace_id": "trace-001",
    "payload_digest": "sha256:" + "2" * 64,
}


class DurableContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            cls.module = importlib.import_module("durable_contract")
        except ModuleNotFoundError:
            cls.module = None

    def setUp(self):
        self.assertIsNotNone(
            self.module,
            "durable_contract module is missing; implement the contract first",
        )

    def test_run_contract_round_trips_and_canonicalizes_json(self):
        run = self.module.RunContract.from_dict(RUN)
        self.assertEqual(run.to_dict(), RUN)
        first = run.canonical_json()
        shuffled = {key: RUN[key] for key in reversed(list(RUN))}
        self.assertEqual(
            first,
            self.module.RunContract.from_dict(shuffled).canonical_json(),
        )
        self.assertEqual(json.loads(first), RUN)

    def test_run_contract_rejects_unknown_fields_and_invalid_identity(self):
        unknown = dict(RUN)
        unknown["model_grant"] = "self-authorized"
        with self.assertRaises(ValueError):
            self.module.RunContract.from_dict(unknown)

        for field, value in (
            ("task_id", "task/001"),
            ("thread_id", "thread 001"),
            ("run_id", ""),
            ("trace_id", "trace\\001"),
        ):
            invalid = dict(RUN)
            invalid[field] = value
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    self.module.RunContract.from_dict(invalid)

    def test_run_contract_rejects_invalid_status_deadline_parent_and_scopes(self):
        for field, value in (
            ("status", "succeeded"),
            ("deadline_at", True),
            ("deadline_at", 0),
            ("parent_run_id", "parent/run"),
            ("scope_snapshot", ["workspace:read", "workspace:read"]),
            ("scope_snapshot", "workspace:read"),
        ):
            invalid = dict(RUN)
            invalid[field] = value
            with self.subTest(field=field, value=value):
                with self.assertRaises(ValueError):
                    self.module.RunContract.from_dict(invalid)

        run = self.module.RunContract.from_dict(RUN)
        self.assertTrue(self.module.validate_deadline(run, now=1_999))
        with self.assertRaises(ValueError):
            self.module.validate_deadline(run, now=2_000)
        with self.assertRaises(ValueError):
            self.module.validate_deadline(run, now=True)

    def test_step_contract_requires_bounded_digest_and_postconditions(self):
        step = self.module.StepContract.from_dict(STEP)
        self.assertEqual(step.to_dict(), STEP)
        invalid_cases = []

        unknown = dict(STEP)
        unknown["prompt"] = "secret must not enter the step contract"
        invalid_cases.append(unknown)

        for digest in (
            "sha256:" + "A" * 64,
            "sha256:" + "1" * 63,
            "not-a-digest",
        ):
            invalid = dict(STEP)
            invalid["input_digest"] = digest
            invalid_cases.append(invalid)

        for attempt in (0, True, "1"):
            invalid = dict(STEP)
            invalid["attempt"] = attempt
            invalid_cases.append(invalid)

        duplicate_scope = dict(STEP)
        duplicate_scope["scope_snapshot"] = ["workspace:read", "workspace:read"]
        invalid_cases.append(duplicate_scope)

        duplicate_postcondition = dict(STEP)
        duplicate_postcondition["expected_postconditions"] = [
            "tests_pass",
            "tests_pass",
        ]
        invalid_cases.append(duplicate_postcondition)

        for invalid in invalid_cases:
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    self.module.StepContract.from_dict(invalid)

    def test_step_contract_rejects_structural_invalid_values(self):
        for field, value in (
            ("step_id", "step/escape"),
            ("step_version", 0),
            ("status", "succeeded"),
            ("deadline_at", 0),
        ):
            invalid = dict(STEP)
            invalid[field] = value
            with self.subTest(field=field, value=value):
                with self.assertRaises(ValueError):
                    self.module.StepContract.from_dict(invalid)

    def test_step_contract_rejects_identity_crossing_against_run(self):
        run = self.module.RunContract.from_dict(RUN)
        step = self.module.StepContract.from_dict(STEP)
        for field, value in (
            ("task_id", "task-002"),
            ("thread_id", "thread-002"),
            ("run_id", "run-002"),
            ("trace_id", "trace-002"),
            ("deadline_at", 2_001),
        ):
            invalid = dict(STEP)
            invalid[field] = value
            candidate = self.module.StepContract.from_dict(invalid)
            with self.subTest(field=field, value=value):
                with self.assertRaises(ValueError):
                    self.module.assert_step_identity(run, candidate)
        self.module.assert_step_identity(run, step)

    def test_event_contract_round_trips_and_requires_ordered_identity(self):
        event = self.module.EventContract.from_dict(EVENT)
        self.assertEqual(event.to_dict(), EVENT)
        self.assertEqual(
            event.canonical_json(),
            self.module.EventContract.from_dict(
                {key: EVENT[key] for key in reversed(list(EVENT))}
            ).canonical_json(),
        )
        for field, value in (
            ("event_id", "event/001"),
            ("sequence", 0),
            ("sequence", True),
            ("occurred_at", "1000"),
            ("payload_digest", "sha256:" + "3" * 63),
        ):
            invalid = dict(EVENT)
            invalid[field] = value
            with self.subTest(field=field, value=value):
                with self.assertRaises(ValueError):
                    self.module.EventContract.from_dict(invalid)

    def test_event_contract_rejects_unknown_fields_and_status_mismatch(self):
        unknown = dict(EVENT)
        unknown["raw_prompt"] = "must not be persisted"
        with self.assertRaises(ValueError):
            self.module.EventContract.from_dict(unknown)

        for field, value in (
            ("event_type", "step.finished"),
            ("status", "finished"),
        ):
            invalid = dict(EVENT)
            invalid[field] = value
            with self.subTest(field=field, value=value):
                with self.assertRaises(ValueError):
                    self.module.EventContract.from_dict(invalid)

    def test_event_contract_rejects_identity_crossing_against_run_and_step(self):
        run = self.module.RunContract.from_dict(RUN)
        step = self.module.StepContract.from_dict(STEP)
        event = self.module.EventContract.from_dict(EVENT)
        self.module.assert_event_identity(run, step, event)
        for field, value in (
            ("task_id", "task-002"),
            ("thread_id", "thread-002"),
            ("run_id", "run-002"),
            ("step_id", "repair"),
            ("trace_id", "trace-002"),
        ):
            invalid = dict(EVENT)
            invalid[field] = value
            candidate = self.module.EventContract.from_dict(invalid)
            with self.subTest(field=field, value=value):
                with self.assertRaises(ValueError):
                    self.module.assert_event_identity(run, step, candidate)

    def test_event_contract_maps_lifecycle_event_types_to_statuses(self):
        for event_type, status in (
            ("run.created", "planned"),
            ("run.started", "running"),
            ("run.waiting", "waiting"),
            ("run.finished", "finished"),
            ("run.failed", "failed"),
            ("run.cancelled", "cancelled"),
            ("run.retry", "planned"),
            ("step.retry", "planned"),
            ("step.started", "running"),
            ("step.waiting", "waiting"),
            ("step.finished", "finished"),
            ("step.failed", "failed"),
            ("step.cancelled", "cancelled"),
            ("checkpoint.created", "running"),
        ):
            candidate = dict(EVENT)
            candidate["event_type"] = event_type
            candidate["status"] = status
            with self.subTest(event_type=event_type):
                self.assertEqual(
                    self.module.EventContract.from_dict(candidate).status,
                    status,
                )

    def test_status_transitions_are_explicit_and_only_failed_is_retryable(self):
        allowed = {
            ("planned", "running"),
            ("planned", "cancelled"),
            ("running", "waiting"),
            ("running", "finished"),
            ("running", "failed"),
            ("running", "cancelled"),
            ("waiting", "running"),
            ("waiting", "failed"),
            ("waiting", "cancelled"),
            ("failed", "planned"),
        }
        statuses = ("planned", "running", "waiting", "finished", "failed", "cancelled")
        for current in statuses:
            for target in statuses:
                with self.subTest(current=current, target=target):
                    expected = (current, target) in allowed
                    self.assertEqual(
                        self.module.can_transition(current, target), expected
                    )
                    if not expected:
                        with self.assertRaises(ValueError):
                            self.module.assert_transition(current, target)

    def test_contract_rejects_non_mapping_and_missing_required_fields(self):
        for contract_type, value in (
            (self.module.RunContract, []),
            (self.module.StepContract, "step"),
            (self.module.EventContract, None),
        ):
            with self.subTest(contract_type=contract_type):
                with self.assertRaises(ValueError):
                    contract_type.from_dict(value)
        missing = dict(RUN)
        del missing["run_id"]
        with self.assertRaises(ValueError):
            self.module.RunContract.from_dict(missing)


if __name__ == "__main__":
    unittest.main()
