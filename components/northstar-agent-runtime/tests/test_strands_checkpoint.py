"""Strands-style resume markers and hook-based retry, driven as whole paths.

The rules this file exists for:

* a resume marker carries position and cycle index and **no state** - a
  dict with conversation state in it is refused, not read;
* the precedence between the three claims on a run is explicit, and a
  cancelled run comes back as ``"cancelled"`` - never as ``"checkpoint"``;
* retry is a **hook**: the loop emits an event and the strategy decides.
  The loop contains no retry call;
* a falsy interrupt answer (``False`` / ``0`` / ``""``) is an answer, not
  the absence of one.

The tests drive the paths, not only the parts: a marker is written at a
boundary, the run crashes, the marker is read back and the resume starts
at the right boundary; a cancel arrives while the marker exists and the
run comes back cancelled; a throttled call is retried and succeeds while a
non-throttled one is not retried at all.
"""
from __future__ import annotations

import ast
import inspect
import sys
import unittest
from pathlib import Path

RUNTIME_ROOT = Path(__file__).resolve().parents[1]
if str(RUNTIME_ROOT) not in sys.path:
    sys.path.insert(0, str(RUNTIME_ROOT))

import support  # noqa: F401
from support import RuntimeTestCase  # noqa: F401

import strands_checkpoint as sc
from strands_checkpoint import (
    Cancel,
    Checkpoint,
    CheckpointException,
    CheckpointSnapshotHook,
    ModelCallLoop,
    ModelRetryStrategy,
    ThrottledError,
    resolve_outcome,
)


class OtherError(Exception):
    """A failure that is not a throttle."""


class MarkerTests(RuntimeTestCase):
    """The marker: position, cycle index, version - and nothing else."""

    def test_a_marker_round_trips_through_its_dict(self):
        marker = Checkpoint(position=sc.POSITION_AFTER_MODEL, cycle_index=7)
        payload = marker.to_dict()
        self.assertEqual(
            payload,
            {"position": "after_model", "cycle_index": 7, "schema_version": 1},
        )
        restored = Checkpoint.from_dict(payload)
        self.assertEqual(restored, marker)
        self.assertEqual(restored.position, "after_model")
        self.assertEqual(restored.cycle_index, 7)

    def test_an_unknown_schema_version_is_refused(self):
        payload = Checkpoint(position="after_model", cycle_index=1).to_dict()
        payload["schema_version"] = 99
        with self.assertRaises(CheckpointException) as caught:
            Checkpoint.from_dict(payload)
        self.assertIn("schema_version", str(caught.exception))

    def test_a_marker_carrying_state_is_refused(self):
        """The separation is enforced, not just documented."""
        payload = Checkpoint(position="after_model", cycle_index=1).to_dict()
        payload["conversation"] = [{"role": "user", "content": "secret"}]
        with self.assertRaises(CheckpointException) as caught:
            Checkpoint.from_dict(payload)
        self.assertIn("conversation", str(caught.exception))

    def test_the_marker_has_no_field_that_could_hold_state(self):
        fields = set(Checkpoint.__dataclass_fields__)
        self.assertEqual(fields, {"position", "cycle_index", "schema_version"})

    def test_an_unknown_position_is_refused(self):
        with self.assertRaises(CheckpointException):
            Checkpoint(position="after_lunch", cycle_index=1)


class PrecedenceTests(RuntimeTestCase):
    """Three claims on one run, one order."""

    def test_an_interrupt_beats_a_checkpoint(self):
        outcome = resolve_outcome(interrupt="answer", checkpoint=Checkpoint("after_model", 1))
        self.assertEqual(outcome, sc.OUTCOME_INTERRUPT)

    def test_a_checkpoint_beats_a_pending_cancel(self):
        outcome = resolve_outcome(
            checkpoint=Checkpoint("after_model", 1),
            cancel=Cancel("stop requested", applied=False),
        )
        self.assertEqual(outcome, sc.OUTCOME_CHECKPOINT)

    def test_a_cancelled_run_comes_back_cancelled_not_checkpoint(self):
        outcome = resolve_outcome(
            checkpoint=Checkpoint("after_model", 1),
            cancel=Cancel("revoked", applied=True),
        )
        self.assertEqual(outcome, sc.OUTCOME_CANCELLED)

    def test_a_falsy_interrupt_answer_is_still_an_answer(self):
        for answer in (False, 0, ""):
            with self.subTest(answer=answer):
                outcome = resolve_outcome(interrupt=answer, checkpoint=Checkpoint("after_model", 1))
                self.assertEqual(outcome, sc.OUTCOME_INTERRUPT)
                self.assertTrue(sc.has_answer(answer))

    def test_no_claims_at_all_resolve_to_none(self):
        self.assertEqual(resolve_outcome(), sc.OUTCOME_NONE)

    def test_a_pending_cancel_is_not_in_force_and_a_plain_one_is(self):
        self.assertFalse(sc.cancel_is_in_force(None))
        self.assertFalse(sc.cancel_is_in_force(Cancel("requested", applied=False)))
        self.assertTrue(sc.cancel_is_in_force(Cancel("revoked", applied=True)))
        self.assertTrue(sc.cancel_is_in_force("revoked"))

    def test_the_resume_outcome_reads_the_same_way(self):
        marker = Checkpoint("after_model", 1)
        self.assertEqual(
            sc.resume_outcome(checkpoint=marker), sc.OUTCOME_CHECKPOINT
        )
        self.assertEqual(
            sc.resume_outcome(checkpoint=marker, cancel="revoked"),
            sc.OUTCOME_CANCELLED,
        )

    def test_the_checkpoint_error_alias_is_the_same_exception(self):
        self.assertTrue(issubclass(sc.CheckpointError, sc.CheckpointException))
        with self.assertRaises(sc.CheckpointException):
            raise sc.CheckpointError("refused")


class RetryHookTests(RuntimeTestCase):
    """Retry as a hook: the strategy decides, the loop only emits."""

    def test_a_throttled_call_is_retried(self):
        strategy = ModelRetryStrategy()
        decision = strategy.after_model_call({"error": ThrottledError("slow down")})
        self.assertTrue(decision.retry)
        self.assertEqual(decision.attempt, 1)

    def test_a_non_throttled_call_is_not_retried(self):
        strategy = ModelRetryStrategy()
        decision = strategy.after_model_call({"error": OtherError("bad request")})
        self.assertFalse(decision.retry)
        self.assertEqual(strategy.attempts, 0)

    def test_the_backoff_is_four_eight_sixteen_thirty_two_sixty_four(self):
        strategy = ModelRetryStrategy()
        waits = [strategy.backoff_for(attempt) for attempt in range(1, 6)]
        self.assertEqual(waits, [4.0, 8.0, 16.0, 32.0, 64.0])

    def test_the_backoff_is_capped_at_two_hundred_forty_seconds(self):
        strategy = ModelRetryStrategy()
        self.assertEqual(strategy.backoff_for(6), 64.0)
        strategy = ModelRetryStrategy(backoff_seconds=(4.0, 8.0), max_backoff_seconds=240.0)
        self.assertEqual(strategy.backoff_for(9), 8.0)
        self.assertLessEqual(strategy.backoff_for(9), strategy.max_backoff_seconds)

    def test_max_attempts_stops_the_retrying(self):
        strategy = ModelRetryStrategy()
        for _ in range(5):
            decision = strategy.after_model_call({"error": ThrottledError("slow down")})
            self.assertTrue(decision.retry)
        decision = strategy.after_model_call({"error": ThrottledError("slow down")})
        self.assertFalse(decision.retry)
        self.assertIn("max_attempts", decision.reason)
        self.assertEqual(strategy.max_attempts, 6)

    def test_a_success_resets_the_attempt_state(self):
        strategy = ModelRetryStrategy()
        strategy.after_model_call({"error": ThrottledError("slow down")})
        strategy.after_model_call({"error": ThrottledError("slow down")})
        self.assertEqual(strategy.attempts, 2)
        decision = strategy.after_model_call({"error": None})
        self.assertFalse(decision.retry)
        self.assertEqual(strategy.attempts, 0)

    def test_a_subclass_may_widen_what_is_retryable(self):
        class WideRetry(ModelRetryStrategy):
            def is_retryable(self, error: BaseException) -> bool:
                return isinstance(error, (ThrottledError, OtherError))

        strategy = WideRetry()
        decision = strategy.after_model_call({"error": OtherError("bad request")})
        self.assertTrue(decision.retry)

    def test_the_strategy_registers_its_callbacks_on_the_model_events(self):
        strategy = ModelRetryStrategy()
        strategy.register()
        self.assertTrue(strategy.callbacks_for(sc.EVENT_AFTER_MODEL))
        self.assertTrue(strategy.callbacks_for(sc.EVENT_AFTER_INVOCATION))

    def test_the_loop_contains_no_retry_call(self):
        """Retry is a hook; the loop emits and stops."""
        source = Path(inspect.getsourcefile(ModelCallLoop) or "").read_text(encoding="utf-8")
        tree = ast.parse(source)
        loop_class = next(
            node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "ModelCallLoop"
        )
        called = {
            node.func.attr
            for node in ast.walk(loop_class)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }
        called |= {
            node.func.id
            for node in ast.walk(loop_class)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        self.assertNotIn("retry", called)
        self.assertNotIn("should_retry", called)
        self.assertNotIn("backoff_for", called)
        # ... and the loop's only way of finding out what happened is the event.
        self.assertIn("emit", called)


class MarkerPathTests(RuntimeTestCase):
    """The whole path: mark at a boundary, crash, resume from the marker."""

    def test_the_hook_marks_both_boundaries(self):
        hook = CheckpointSnapshotHook()
        hook.after_model({"cycle_index": 1})
        hook.after_tools({"cycle_index": 2})
        self.assertEqual(
            [marker.position for marker in hook.markers],
            ["after_model", "after_tools"],
        )
        self.assertEqual([marker.cycle_index for marker in hook.markers], [1, 2])

    def test_a_marker_is_written_and_read_back_through_its_dict(self):
        written: list[dict] = []
        hook = CheckpointSnapshotHook(save=written.append)
        marker = hook.after_model({"cycle_index": 4})
        self.assertEqual(len(written), 1)
        self.assertEqual(Checkpoint.from_dict(written[0]), marker)

    def test_a_crashed_run_resumes_at_the_boundary_the_marker_names(self):
        written: list[dict] = []
        hook = CheckpointSnapshotHook(save=written.append)
        hook.after_model({"cycle_index": 3})

        # The crash: the process dies here.  What survives is the marker.
        payload = written[-1]

        # A new process reads the marker back.
        plan = sc.plan_resume(payload)
        self.assertTrue(plan.resumes)
        assert plan.marker is not None
        self.assertEqual(plan.marker.position, "after_model")
        self.assertEqual(plan.marker.cycle_index, 3)

        # The resumed run continues from that boundary - not from the start,
        # and not from the other boundary.
        self.assertEqual(plan.marker.position, sc.POSITION_AFTER_MODEL)
        self.assertNotEqual(plan.marker.position, sc.POSITION_AFTER_TOOLS)

    def test_a_crash_at_the_tools_boundary_resumes_at_the_tools_boundary(self):
        written: list[dict] = []
        hook = CheckpointSnapshotHook(save=written.append)
        hook.after_tools({"cycle_index": 5})
        plan = sc.plan_resume(written[-1])
        assert plan.marker is not None
        self.assertEqual(plan.marker.position, "after_tools")
        self.assertEqual(plan.marker.cycle_index, 5)

    def test_a_cancelled_run_with_a_marker_comes_back_cancelled(self):
        written: list[dict] = []
        hook = CheckpointSnapshotHook(save=written.append)
        hook.after_model({"cycle_index": 3})
        payload = written[-1]

        # The cancel arrives while the run is down.
        plan = sc.plan_resume(payload, cancel=Cancel("operator revoked", applied=True))
        self.assertTrue(plan.cancelled)
        self.assertFalse(plan.resumes)
        self.assertIsNone(plan.marker)
        self.assertEqual(plan.outcome, "cancelled")

    def test_a_cancelled_run_does_not_resume_from_a_marker(self):
        """The kill switch, as a fact about the run rather than a claim."""
        marker = Checkpoint("after_model", 3).to_dict()
        plan = sc.plan_resume(marker, cancel="revoked")
        self.assertEqual(plan.outcome, "cancelled")
        self.assertFalse(plan.resumes)

    def test_a_marker_read_back_as_state_is_refused_at_the_resume(self):
        payload = Checkpoint("after_model", 1).to_dict()
        payload["messages"] = ["hello"]
        with self.assertRaises(CheckpointException):
            sc.plan_resume(payload)


class RetryPathTests(RuntimeTestCase):
    """The whole path: the loop emits, the hook decides, the run finishes."""

    def test_a_throttled_call_is_retried_by_the_hook_and_then_succeeds(self):
        attempts: list[int] = []

        def provider(prompt: str) -> str:
            attempts.append(len(attempts))
            if len(attempts) == 1:
                raise ThrottledError("slow down")
            return "answer"

        strategy = ModelRetryStrategy()
        loop = ModelCallLoop(provider=provider)

        # The caller drives the retry: the loop emitted the failure, the hook
        # decided it was retryable, and the wait is the hook's number.
        result = None
        waits: list[float] = []
        while result is None and len(attempts) < 5:
            result = loop.call("hello")
            if result is None:
                decision = strategy.after_model_call(loop.emitted[-1])
                if not decision.retry:
                    break
                waits.append(decision.wait_seconds)

        self.assertEqual(result, "answer")
        self.assertEqual(len(attempts), 2)
        self.assertEqual(waits, [4.0])
        # The loop made two calls and emitted two events; it never decided
        # anything itself.
        self.assertEqual(len(loop.emitted), 2)

    def test_a_non_throttled_call_is_not_retried(self):
        attempts: list[int] = []

        def provider(prompt: str) -> str:
            attempts.append(len(attempts))
            raise OtherError("bad request")

        strategy = ModelRetryStrategy()
        loop = ModelCallLoop(provider=provider)
        loop.on(sc.EVENT_AFTER_MODEL, lambda event: strategy.after_model_call(event))
        result = loop.call("hello")
        self.assertIsNone(result)
        self.assertEqual(len(attempts), 1)
        self.assertEqual(strategy.attempts, 0)

    def test_the_hook_schedules_the_backoff_and_the_loop_never_waits(self):
        strategy = ModelRetryStrategy()
        waits = []
        for _ in range(5):
            decision = strategy.after_model_call({"error": ThrottledError("slow down")})
            waits.append(decision.wait_seconds)
        self.assertEqual(waits, [4.0, 8.0, 16.0, 32.0, 64.0])
        # The sixth failure stops rather than backing off again.
        decision = strategy.after_model_call({"error": ThrottledError("slow down")})
        self.assertFalse(decision.retry)


if __name__ == "__main__":  # pragma: no cover - manual run
    unittest.main()


if __name__ == "__main__":  # pragma: no cover - manual run
    unittest.main()
