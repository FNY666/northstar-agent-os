"""Tests for saga_pattern.py — 27 tests."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from saga_pattern import (  # noqa: E402
    SAGA_PATTERN_VERSION,
    SCHEMA_PIN,
    Saga,
    SagaError,
    SagaEvent,
    SagaResult,
    SagaStep,
    saga_audit_event,
)


def _ok(log, name):
    def _run():
        log.append(name)

    return _run


def _boom(log, name):
    def _run():
        log.append(name)
        raise RuntimeError(f"{name} exploded")

    return _run


def _steps(log, spec):
    """spec: list of (step_id, action_kind, comp_kind); kind in {"ok","boom"}."""
    out = []
    for step_id, ak, ck in spec:
        out.append(
            SagaStep(
                step_id,
                f"desc-{step_id}",
                _boom(log, f"a-{step_id}") if ak == "boom" else _ok(log, f"a-{step_id}"),
                _boom(log, f"c-{step_id}") if ck == "boom" else _ok(log, f"c-{step_id}"),
            )
        )
    return tuple(out)


class TestVersionPin(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(SAGA_PATTERN_VERSION, "saga-pattern.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.saga-pattern.v1")


class TestSagaStepValidation(unittest.TestCase):
    def test_frozen(self):
        step = SagaStep("s1", "d", lambda: None, lambda: None)
        with self.assertRaises(Exception):
            step.step_id = "x"  # type: ignore[misc]

    def test_empty_step_id_rejected(self):
        with self.assertRaises(SagaError):
            SagaStep("", "d", lambda: None, lambda: None)

    def test_non_callable_action_rejected(self):
        with self.assertRaises(SagaError):
            SagaStep("s1", "d", "not-callable", lambda: None)  # type: ignore[arg-type]

    def test_non_callable_compensation_rejected(self):
        with self.assertRaises(SagaError):
            SagaStep("s1", "d", lambda: None, 42)  # type: ignore[arg-type]


class TestSagaConstruction(unittest.TestCase):
    def test_empty_steps_rejected(self):
        with self.assertRaises(SagaError):
            Saga("s", ())

    def test_duplicate_step_id_rejected(self):
        log = []
        with self.assertRaises(SagaError):
            Saga("s", _steps(log, [("s1", "ok", "ok"), ("s1", "ok", "ok")]))

    def test_non_step_rejected(self):
        with self.assertRaises(SagaError):
            Saga("s", ("nope",))  # type: ignore[list-item]

    def test_empty_saga_id_rejected(self):
        log = []
        with self.assertRaises(SagaError):
            Saga("", _steps(log, [("s1", "ok", "ok")]))

    def test_steps_property(self):
        log = []
        saga = Saga("s", _steps(log, [("s1", "ok", "ok"), ("s2", "ok", "ok")]))
        self.assertEqual([s.step_id for s in saga.steps], ["s1", "s2"])
        self.assertEqual(saga.saga_id, "s")


class TestHappyPath(unittest.TestCase):
    def test_completed(self):
        log = []
        saga = Saga("s", _steps(log, [("s1", "ok", "ok"), ("s2", "ok", "ok")]))
        result = saga.execute(0)
        self.assertEqual(result.status, "completed")
        self.assertEqual(result.completed_step_ids, ("s1", "s2"))
        self.assertEqual(result.compensated_step_ids, ())
        self.assertEqual(result.failed_step_id, "")
        self.assertEqual(result.error, "")
        self.assertEqual(log, ["a-s1", "a-s2"])

    def test_result_frozen_and_dict(self):
        log = []
        saga = Saga("s", _steps(log, [("s1", "ok", "ok")]))
        result = saga.execute(0)
        self.assertIsInstance(result, SagaResult)
        with self.assertRaises(Exception):
            result.status = "x"  # type: ignore[misc]
        d = result.as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(d["status"], "completed")


class TestCompensation(unittest.TestCase):
    def test_compensated_reverse_order(self):
        log = []
        saga = Saga(
            "s", _steps(log, [("s1", "ok", "ok"), ("s2", "ok", "ok"), ("s3", "boom", "ok")])
        )
        result = saga.execute(10)
        self.assertEqual(result.status, "compensated")
        self.assertEqual(result.failed_step_id, "s3")
        self.assertEqual(result.completed_step_ids, ("s1", "s2"))
        # Reverse order: s2 compensated before s1.
        self.assertEqual(result.compensated_step_ids, ("s2", "s1"))
        self.assertEqual(log, ["a-s1", "a-s2", "a-s3", "c-s2", "c-s1"])

    def test_later_steps_never_run(self):
        log = []
        saga = Saga(
            "s", _steps(log, [("s1", "boom", "ok"), ("s2", "ok", "ok")])
        )
        result = saga.execute(0)
        self.assertEqual(result.status, "compensated")
        self.assertEqual(result.completed_step_ids, ())
        self.assertEqual(result.compensated_step_ids, ())
        self.assertEqual(log, ["a-s1"])

    def test_error_recorded(self):
        log = []
        saga = Saga("s", _steps(log, [("s1", "boom", "ok")]))
        result = saga.execute(0)
        self.assertIn("exploded", result.error)

    def test_compensation_failure_marks_failed(self):
        log = []
        saga = Saga(
            "s", _steps(log, [("s1", "ok", "boom"), ("s2", "boom", "ok")])
        )
        result = saga.execute(0)
        self.assertEqual(result.status, "failed")
        self.assertEqual(result.failed_compensation_ids, ("s1",))
        # The other compensation still ran (best-effort continues).
        self.assertEqual(log, ["a-s1", "a-s2", "c-s1"])

    def test_compensation_failure_continues_remaining(self):
        log = []
        saga = Saga(
            "s",
            _steps(
                log,
                [("s1", "ok", "ok"), ("s2", "ok", "boom"), ("s3", "boom", "ok")],
            ),
        )
        result = saga.execute(0)
        self.assertEqual(result.status, "failed")
        self.assertEqual(result.failed_compensation_ids, ("s2",))
        # s1's compensation still ran after s2's failed.
        self.assertEqual(result.compensated_step_ids, ("s1",))
        self.assertEqual(log, ["a-s1", "a-s2", "a-s3", "c-s2", "c-s1"])


class TestEvents(unittest.TestCase):
    def test_event_order_happy(self):
        log = []
        saga = Saga("s", _steps(log, [("s1", "ok", "ok")]))
        saga.execute(5)
        kinds = [(e.kind, e.step_id, e.seq) for e in saga.events()]
        self.assertEqual(
            kinds,
            [
                ("saga-started", "", 5),
                ("step-started", "s1", 6),
                ("step-completed", "s1", 7),
                ("saga-completed", "", 8),
            ],
        )

    def test_event_order_compensated(self):
        log = []
        saga = Saga("s", _steps(log, [("s1", "ok", "ok"), ("s2", "boom", "ok")]))
        saga.execute(0)
        kinds = [e.kind for e in saga.events()]
        self.assertEqual(
            kinds,
            [
                "saga-started",
                "step-started",
                "step-completed",
                "step-started",
                "step-failed",
                "compensation-started",
                "compensation-completed",
                "saga-compensated",
            ],
        )

    def test_event_as_dict_schema(self):
        log = []
        saga = Saga("s", _steps(log, [("s1", "ok", "ok")]))
        saga.execute(0)
        d = saga.events()[0].as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)

    def test_bad_seq_rejected(self):
        log = []
        saga = Saga("s", _steps(log, [("s1", "ok", "ok")]))
        with self.assertRaises(SagaError):
            saga.execute(-1)
        with self.assertRaises(SagaError):
            saga.execute(True)  # type: ignore[arg-type]


class TestAuditEvent(unittest.TestCase):
    def test_audit_event_shape(self):
        log = []
        saga = Saga("s", _steps(log, [("s1", "ok", "ok")]))
        result = saga.execute(0)
        record = saga_audit_event(result, 9)
        self.assertEqual(record["audit_seq"], 9)
        self.assertEqual(record["schema"], SCHEMA_PIN)
        self.assertEqual(record["status"], "completed")

    def test_audit_event_bad_seq(self):
        log = []
        saga = Saga("s", _steps(log, [("s1", "ok", "ok")]))
        result = saga.execute(0)
        with self.assertRaises(SagaError):
            saga_audit_event(result, -1)

    def test_audit_event_bad_result(self):
        with self.assertRaises(SagaError):
            saga_audit_event("nope", 0)  # type: ignore[arg-type]


class TestMain(unittest.TestCase):
    def test_main_runs(self):
        import saga_pattern

        saga_pattern.main()


if __name__ == "__main__":
    unittest.main()
