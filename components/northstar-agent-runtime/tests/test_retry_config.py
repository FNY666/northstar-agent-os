"""Call-kind classification and declarative retry config.

The point of this suite is the matrix: a retry rule is only as good as the
cases it refuses to retry. Every rule comes from one of two places, and the
tests say which:

* **Verbatim from Dynamiq** (commit ``acc30e5``): the AgentCore idempotency
  comment, the ``SandboxCreationErrorHandling`` defaults, the double-checked
  ``_ensure_sandbox()`` locking, and the exit-124 timeout convention.
* **Northstar extensions**: the declared jitter *window* (no RNG, so a run
  replays from its record), and the gate that binds classification to the
  schedule.

Nothing here touches the network, and nothing here waits on a real clock: the
sleeper is injected and the timeout is exercised with a callable that blocks
on an event rather than a subprocess.
"""
from __future__ import annotations

import dataclasses
import sys
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from retry_config import (  # noqa: E402
    EXIT_CODE_ERROR,
    EXIT_CODE_TIMEOUT,
    CallKind,
    GateOutcome,
    RetryConfig,
    RetryConfigError,
    RetryDecision,
    RetryGate,
    RetryVerdict,
    SessionGuard,
    TimeoutResult,
    WaitWindow,
    classify_call,
    run_with_timeout,
)
from retry_contract import Failure, FailureClass, FailurePhase  # noqa: E402
from retry_contract import classify_response  # noqa: E402


def throttle() -> Failure:
    """A retryable throttle (HTTP 429), classified by ``retry_contract``."""
    return classify_response(429)


def post_write() -> Failure:
    """A failure that happened after the request may have been written."""
    return Failure(
        classification=FailureClass.NON_RETRYABLE,
        phase=FailurePhase.POST_WRITE,
        reason="connection dropped after the request was written",
        may_have_executed=True,
    )


class RetryConfigShapeTests(unittest.TestCase):
    """The configuration is frozen data with exactly the declared fields."""

    def test_the_config_is_frozen(self):
        config = RetryConfig()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            config.max_retries = 9  # type: ignore[misc]

    def test_the_field_set_is_exactly_the_declared_one(self):
        names = [f.name for f in dataclasses.fields(RetryConfig)]
        self.assertEqual(
            names,
            [
                "max_retries",
                "initial_wait_seconds",
                "max_wait_seconds",
                "exponential_base",
                "jitter",
            ],
        )

    def test_max_retries_must_be_an_integer(self):
        with self.assertRaises(RetryConfigError):
            RetryConfig(max_retries=2.5)  # type: ignore[arg-type]
        with self.assertRaises(RetryConfigError):
            RetryConfig(max_retries=True)  # type: ignore[arg-type]

    def test_max_wait_seconds_must_be_positive(self):
        with self.assertRaises(RetryConfigError):
            RetryConfig(initial_wait_seconds=1.0, max_wait_seconds=0.0)


class RetryConfigValidationTests(unittest.TestCase):
    """The configuration is refused when it does not make sense."""

    def test_defaults_are_dynamiqs_sandbox_creation_error_handling_verbatim(self):
        config = RetryConfig()
        # dynamiq/nodes/tools/code_interpreter.py line 322,
        # SandboxCreationErrorHandling -- copied, not invented.
        self.assertEqual(config.max_retries, 5)
        self.assertEqual(config.initial_wait_seconds, 2.0)
        self.assertEqual(config.max_wait_seconds, 32.0)
        self.assertEqual(config.exponential_base, 2.0)
        self.assertEqual(config.jitter, 1.0)

    def test_negative_max_retries_is_refused(self):
        with self.assertRaises(RetryConfigError):
            RetryConfig(max_retries=-1)

    def test_jitter_outside_zero_to_one_is_refused(self):
        with self.assertRaises(RetryConfigError):
            RetryConfig(jitter=1.5)
        with self.assertRaises(RetryConfigError):
            RetryConfig(jitter=-0.1)

    def test_max_wait_below_initial_wait_is_refused(self):
        with self.assertRaises(RetryConfigError):
            RetryConfig(initial_wait_seconds=10.0, max_wait_seconds=5.0)

    def test_exponential_base_outside_one_to_four_is_refused(self):
        with self.assertRaises(RetryConfigError):
            RetryConfig(exponential_base=0.5)
        with self.assertRaises(RetryConfigError):
            RetryConfig(exponential_base=4.5)

    def test_non_positive_wait_is_refused(self):
        with self.assertRaises(RetryConfigError):
            RetryConfig(initial_wait_seconds=0.0)

    def test_from_dict_to_dict_round_trips(self):
        config = RetryConfig(
            max_retries=3,
            initial_wait_seconds=1.5,
            max_wait_seconds=12.0,
            exponential_base=1.5,
            jitter=0.25,
        )
        self.assertEqual(RetryConfig.from_dict(config.to_dict()), config)
        self.assertEqual(RetryConfig.from_dict({}).max_retries, 5)

    def test_from_dict_refuses_an_unknown_key(self):
        with self.assertRaises(RetryConfigError):
            RetryConfig.from_dict({"max_retry": 3})


class RetryConfigScheduleTests(unittest.TestCase):
    """The schedule is computed, deterministic, and capped."""

    def test_schedule_grows_exponentially_and_is_capped(self):
        config = RetryConfig()
        nominals = [window.nominal for window in config.schedule()]
        self.assertEqual(nominals, [2.0, 4.0, 8.0, 16.0, 32.0])
        # 64.0 would be the next uncapped value; the ceiling holds it at 32.0.
        capped = RetryConfig(max_retries=6, initial_wait_seconds=2.0, max_wait_seconds=32.0)
        self.assertEqual(capped.nominal_waits(), (2.0, 4.0, 8.0, 16.0, 32.0, 32.0))

    def test_five_retries_means_five_declared_waits(self):
        config = RetryConfig()
        self.assertEqual(len(config.schedule()), 5)
        self.assertEqual(len(config.nominal_waits()), 5)

    def test_schedule_is_replayable(self):
        config = RetryConfig()
        self.assertEqual(config.schedule(), config.schedule())
        self.assertEqual(
            [w.as_dict() for w in config.schedule()],
            [w.as_dict() for w in RetryConfig().schedule()],
        )

    def test_jitter_is_a_declared_window_not_a_sample(self):
        config = RetryConfig(jitter=0.5)
        window = config.schedule()[0]
        self.assertEqual(window.nominal, 2.0)
        self.assertEqual(window.low, 1.0)
        self.assertEqual(window.high, 2.0)
        # No RNG: two independent computations agree exactly.
        self.assertEqual(config.schedule()[0], window)


class CallKindClassificationTests(unittest.TestCase):
    """The classification decides whether a call may be repeated."""

    def test_session_lifecycle_throttle_is_retried(self):
        verdict = classify_call(CallKind.SESSION_LIFECYCLE, throttle())
        self.assertIs(verdict.decision, RetryDecision.RETRY)
        self.assertTrue(verdict.should_retry)
        self.assertIsNotNone(verdict.window)

    def test_execution_throttle_is_never_retried(self):
        verdict = classify_call(CallKind.EXECUTION, throttle())
        self.assertIs(verdict.decision, RetryDecision.NEVER_RETRY)
        self.assertFalse(verdict.should_retry)
        self.assertIsNone(verdict.window)

    def test_unknown_kind_is_treated_as_non_idempotent(self):
        verdict = classify_call(CallKind.UNKNOWN, throttle())
        self.assertIs(verdict.decision, RetryDecision.NEVER_RETRY)
        self.assertFalse(CallKind.UNKNOWN.idempotent)
        self.assertTrue(CallKind.SESSION_LIFECYCLE.idempotent)
        self.assertFalse(CallKind.EXECUTION.idempotent)

    def test_post_write_failure_is_indeterminate_and_never_retried(self):
        verdict = classify_call(CallKind.SESSION_LIFECYCLE, post_write())
        self.assertIs(verdict.decision, RetryDecision.INDETERMINATE)
        self.assertTrue(verdict.may_have_executed)
        self.assertFalse(verdict.should_retry)

    def test_may_have_executed_flag_alone_is_indeterminate(self):
        failure = Failure(
            classification=FailureClass.RETRYABLE,
            phase=FailurePhase.PRE_WRITE,
            reason="the peer may already have run it",
            may_have_executed=True,
        )
        verdict = classify_call(CallKind.SESSION_LIFECYCLE, failure)
        self.assertIs(verdict.decision, RetryDecision.INDETERMINATE)

    def test_non_retryable_failure_is_never_retried(self):
        failure = classify_response(400)
        verdict = classify_call(CallKind.SESSION_LIFECYCLE, failure)
        self.assertIs(verdict.decision, RetryDecision.NEVER_RETRY)

    def test_spent_budget_ends_the_retries(self):
        config = RetryConfig(max_retries=2)
        verdict = classify_call(
            CallKind.SESSION_LIFECYCLE, throttle(), attempt=2, config=config
        )
        self.assertIs(verdict.decision, RetryDecision.NEVER_RETRY)
        self.assertIn("budget", verdict.reason)

    def test_failure_vocabulary_is_not_copied(self):
        # The gate classifies a bare FailureClass and an exception through
        # retry_contract, so there is exactly one vocabulary.
        verdict = classify_call(CallKind.SESSION_LIFECYCLE, FailureClass.RETRYABLE)
        self.assertIs(verdict.decision, RetryDecision.RETRY)
        verdict = classify_call(
            CallKind.SESSION_LIFECYCLE, ConnectionRefusedError("no route")
        )
        self.assertIs(verdict.decision, RetryDecision.RETRY)


class PublicVocabularyTests(unittest.TestCase):
    """The public names are the ones the module promises."""

    def test_the_exit_codes_are_the_documented_ones(self):
        self.assertEqual(EXIT_CODE_TIMEOUT, 124)
        self.assertEqual(EXIT_CODE_ERROR, 1)

    def test_the_wait_window_is_a_public_named_type(self):
        window = RetryConfig().schedule()[0]
        self.assertIsInstance(window, WaitWindow)
        self.assertEqual(window.nominal, 2.0)

    def test_the_gate_outcome_is_a_public_named_type(self):
        gate = RetryGate(RetryConfig(), sleep=lambda _s: None)
        outcome = gate.execute(CallKind.SESSION_LIFECYCLE, lambda: "ok")
        self.assertIsInstance(outcome, GateOutcome)
        self.assertTrue(outcome.ok)


class RecordShapeTests(unittest.TestCase):
    """The auditable records carry no wall-clock time."""

    def test_the_timeout_record_carries_no_timestamp(self):
        result = TimeoutResult(ok=False, exit_code=EXIT_CODE_TIMEOUT, timed_out=True)
        record = result.as_dict()
        self.assertEqual(record["exit_code"], 124)
        self.assertTrue(record["timed_out"])
        # A wall-clock field would make the record unreplayable: the same
        # timeout would produce a different record every run.
        for banned in ("timestamp", "time", "at", "when", "started", "duration", "elapsed"):
            self.assertNotIn(banned, record)

    def test_the_config_record_carries_no_timestamp(self):
        record = RetryConfig().as_dict()
        for banned in ("timestamp", "time", "at", "when", "started", "duration", "elapsed"):
            self.assertNotIn(banned, record)

    def test_the_verdict_record_names_the_schema_and_the_decision(self):
        verdict = classify_call(CallKind.SESSION_LIFECYCLE, throttle())
        self.assertIsInstance(verdict, RetryVerdict)
        record = verdict.as_dict()
        self.assertEqual(record["schema"], "northstar.retry-config.v1")
        self.assertEqual(record["decision"], "retry")
        self.assertIn("window", record)


class SessionGuardTests(unittest.TestCase):
    """Dynamiq's double-checked locking, in code."""

    def test_concurrent_callers_create_the_session_once(self):
        created = []
        gate = threading.Event()

        def create():
            created.append(object())
            gate.set()
            return created[-1]

        guard = SessionGuard(create)
        results = []
        start = threading.Barrier(8)

        def worker():
            start.wait()
            results.append(guard.get())

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(10)

        self.assertEqual(len(results), 8)
        self.assertEqual(guard.create_calls, 1)
        self.assertEqual(len(created), 1)
        # Every caller shares the one created session.
        self.assertEqual(len({id(r) for r in results}), 1)

    def test_failed_creation_releases_the_guard_and_can_be_retried(self):
        attempts = {"n": 0}

        def flaky():
            attempts["n"] += 1
            if attempts["n"] == 1:
                raise RuntimeError("provider refused")
            return "session"

        guard = SessionGuard(flaky)
        with self.assertRaises(RuntimeError):
            guard.get()
        self.assertFalse(guard.created)
        # The guard was released: the next caller may try again.
        self.assertEqual(guard.get(), "session")
        self.assertTrue(guard.created)
        self.assertEqual(guard.create_calls, 2)

    def test_second_get_does_not_create_again(self):
        guard = SessionGuard(lambda: "session")
        self.assertEqual(guard.get(), "session")
        self.assertEqual(guard.get(), "session")
        self.assertEqual(guard.create_calls, 1)


class TimeoutTests(unittest.TestCase):
    """A timeout is a failed result, not a silent hang."""

    def test_a_timed_out_call_returns_exit_124(self):
        release = threading.Event()

        def blocking():
            release.wait(30)
            return "too late"

        result = run_with_timeout(blocking, 0.05)
        release.set()
        self.assertFalse(result.ok)
        self.assertEqual(result.exit_code, EXIT_CODE_TIMEOUT)
        self.assertEqual(result.exit_code, 124)
        self.assertTrue(result.timed_out)

    def test_a_call_that_finishes_in_time_succeeds(self):
        result = run_with_timeout(lambda: "done", 5.0)
        self.assertTrue(result.ok)
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.value, "done")

    def test_a_raising_call_is_a_failed_result_not_an_exception(self):
        def boom():
            raise RuntimeError("provider exploded")

        result = run_with_timeout(boom, 5.0)
        self.assertFalse(result.ok)
        self.assertEqual(result.exit_code, 1)
        self.assertIn("provider exploded", result.error or "")


class EndToEndPathTests(unittest.TestCase):
    """One governed path, driven all the way through the gate.

    The point of these is not the parts (the parts have their own tests) but
    the *gate*: that the classification, and not the call site, decides
    whether a call runs again.
    """

    def test_throttled_idempotent_session_create_is_retried_per_the_config(self):
        config = RetryConfig(
            max_retries=3,
            initial_wait_seconds=2.0,
            max_wait_seconds=32.0,
            exponential_base=2.0,
            jitter=1.0,
        )
        waits: list[float] = []
        gate = RetryGate(config, sleep=waits.append)
        attempts = {"n": 0}

        def create_session():
            attempts["n"] += 1
            if attempts["n"] < 3:
                raise ConnectionRefusedError("provider throttled us")
            return "session-1"

        outcome = gate.execute(CallKind.SESSION_LIFECYCLE, create_session)

        self.assertTrue(outcome.ok)
        self.assertEqual(outcome.value, "session-1")
        self.assertEqual(outcome.attempts, 3)
        # The waits follow the declared schedule, in order.
        self.assertEqual(waits, [2.0, 4.0])
        self.assertEqual([w.nominal for w in outcome.windows], [2.0, 4.0])

    def test_throttled_non_idempotent_execution_is_never_re_executed(self):
        config = RetryConfig(max_retries=5, initial_wait_seconds=2.0)
        waits: list[float] = []
        gate = RetryGate(config, sleep=waits.append)
        executions = {"n": 0}

        def run_user_code():
            executions["n"] += 1
            raise ConnectionRefusedError("provider throttled us")

        outcome = gate.execute(CallKind.EXECUTION, run_user_code)

        self.assertFalse(outcome.ok)
        # The user's code ran exactly once. Not twice, not six times.
        self.assertEqual(executions["n"], 1)
        self.assertEqual(outcome.attempts, 1)
        self.assertEqual(waits, [])
        self.assertIs(outcome.verdict.decision, RetryDecision.NEVER_RETRY)
        self.assertIsNone(outcome.verdict.window)

    def test_a_timed_out_invocation_returns_an_exit_124_failed_result(self):
        release = threading.Event()

        def blocking_call():
            release.wait(30)
            return "too late"

        result = run_with_timeout(blocking_call, 0.05)
        release.set()
        self.assertFalse(result.ok)
        self.assertEqual(result.exit_code, 124)
        self.assertTrue(result.timed_out)

    def test_the_gate_runs_the_three_cases_in_one_go(self):
        """Idempotent retried, non-idempotent never re-executed, timeout 124."""
        config = RetryConfig(max_retries=2, initial_wait_seconds=1.0, max_wait_seconds=4.0)
        waits: list[float] = []
        gate = RetryGate(config, sleep=waits.append)

        # 1. A throttled session create: retried, and it succeeds.
        creates = {"n": 0}

        def create():
            creates["n"] += 1
            if creates["n"] == 1:
                raise ConnectionRefusedError("provider throttled us")
            return "s"

        created = gate.execute(CallKind.SESSION_LIFECYCLE, create)
        self.assertTrue(created.ok)
        self.assertEqual(creates["n"], 2)
        self.assertEqual(waits, [1.0])

        # 2. The same throttle on a non-idempotent execution: never re-run.
        executions = {"n": 0}

        def execute_code():
            executions["n"] += 1
            raise ConnectionRefusedError("provider throttled us")

        refused = gate.execute(CallKind.EXECUTION, execute_code)
        self.assertFalse(refused.ok)
        self.assertEqual(executions["n"], 1)
        self.assertEqual(waits, [1.0])  # no second wait was declared

        # 3. A hung invocation: a failed result with exit 124.
        release = threading.Event()
        hung = run_with_timeout(lambda: release.wait(30), 0.05)
        release.set()
        self.assertEqual(hung.exit_code, 124)
        self.assertFalse(hung.ok)

    def test_the_gate_never_reports_an_indeterminate_outcome_as_success(self):
        gate = RetryGate(RetryConfig(max_retries=3), sleep=lambda _s: None)

        def dropped_after_write():
            raise ConnectionResetError("connection dropped after the request")

        outcome = gate.execute(CallKind.SESSION_LIFECYCLE, dropped_after_write)
        self.assertFalse(outcome.ok)
        self.assertIs(outcome.verdict.decision, RetryDecision.INDETERMINATE)
        self.assertTrue(outcome.may_have_executed)
        self.assertEqual(outcome.attempts, 1)


if __name__ == "__main__":
    unittest.main()
