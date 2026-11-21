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
import io
import runpy
import sys
import threading
import unittest
from contextlib import redirect_stdout
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
import retry_config as rc  # noqa: E402
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


class VocabularyIsNotDuplicatedTests(unittest.TestCase):
    """The failure vocabulary is read from ``retry_contract``, not re-declared."""

    def test_the_failure_class_is_the_one_from_retry_contract(self):
        import retry_config
        import retry_contract

        self.assertIs(retry_config.FailureClass, retry_contract.FailureClass)
        self.assertIs(retry_config.Failure, retry_contract.Failure)

    def test_retry_config_declares_no_failure_class_of_its_own(self):
        import retry_config

        # A second vocabulary is how two halves of the runtime drift apart:
        # one half learns about a fault the other has never heard of.
        for name in dir(retry_config):
            if name.endswith("Class") and name != "FailureClass":
                value = getattr(retry_config, name)
                self.assertFalse(
                    isinstance(value, type) and issubclass(value, __import__("enum").Enum)
                    and name != "CallKind",
                    f"retry_config declares its own enum {name}",
                )

    def test_the_protected_modules_are_not_patched_by_this_module(self):
        import retry_config

        # This module must not monkeypatch the modules it reads.
        for name in ("retry_contract", "retry_policy", "provider_retry"):
            module = __import__(name)
            self.assertFalse(
                getattr(module, "_northstar_patched_by_retry_config", False),
                f"{name} was patched by retry_config",
            )
        self.assertFalse(hasattr(retry_config, "_patched_modules"))


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


class RetryGuardSecondHalfTests(unittest.TestCase):
    """The second half of every guard in ``retry_config``.

    Every guard in the module is a PAIR of conditions joined by ``or``:  a
    TYPE half ("is this a number at all?") and a BOUND half ("is it in
    range?").  The suite drove one half and left the other, so a fault
    planted in the half nobody drove survived.

    Two rules for every test here:

    * it must be a DISCRIMINATOR -- it passes on the real code and fails
      on the mutant, so it names the exact value that sits on the
      boundary the guard is about;  and
    * the BOOLEAN trap is respected.  ``isinstance(True, int)`` is True
      in Python, so the type half of a "must be a number" guard has to
      name the bool explicitly or it never refuses a boolean at all.
    """

    # -- the configuration guards --------------------------------------

    def test_max_retries_refuses_a_boolean(self):
        """`lt@167`: the type half of the budget guard, on a bool.

        ``max_retries=True`` is a bool, and bool IS an int, so the
        ``isinstance(self.max_retries, bool)`` half is the only thing
        that refuses it.  With that half inverted the boolean slips
        through and the config is accepted.
        """
        with self.assertRaises(RetryConfigError):
            RetryConfig(max_retries=True)

    def test_max_retries_of_exactly_zero_is_accepted(self):
        """`lt@167`: the boundary -- zero retries is legal.

        The budget guard is ``< 0``, so zero must be ACCEPTED.  Under
        the mutant (``<`` -> ``<=``) zero is refused, which turns a
        legal "never retry" configuration into a hard error.
        """
        config = RetryConfig(max_retries=0)
        self.assertEqual(config.max_retries, 0)
        self.assertEqual(config.schedule(), ())

    def test_a_wait_seconds_value_that_is_a_boolean_is_refused(self):
        """`or@171`: the type half, on a bool.

        ``isinstance(True, (int, float))`` is True, so the bool half of
        the guard is the only thing that refuses a boolean wait.  With
        it inverted the boolean is accepted as a wait of ``True``
        seconds.
        """
        with self.assertRaises(RetryConfigError):
            RetryConfig(initial_wait_seconds=True)
        with self.assertRaises(RetryConfigError):
            RetryConfig(max_wait_seconds=True)

    def test_a_wait_seconds_value_that_is_not_a_number_is_refused(self):
        """`or@171`: the type half, on a string and on None."""
        with self.assertRaises(RetryConfigError):
            RetryConfig(initial_wait_seconds="2.0")  # type: ignore[arg-type]
        with self.assertRaises(RetryConfigError):
            RetryConfig(max_wait_seconds=None)  # type: ignore[arg-type]

    def test_a_wait_seconds_value_of_exactly_the_initial_wait_is_accepted(self):
        """`lt@175`: the boundary -- the two waits may be equal.

        ``max_wait_seconds < initial_wait_seconds`` refuses a ceiling
        BELOW the first wait.  Equal is legal and must be accepted; the
        mutant (``<`` -> ``<=``) refuses it.
        """
        config = RetryConfig(initial_wait_seconds=5.0, max_wait_seconds=5.0)
        self.assertEqual(config.max_wait_seconds, 5.0)
        self.assertEqual(config.schedule()[0].nominal, 5.0)

    def test_a_ceiling_below_the_first_wait_is_refused(self):
        """`lt@175`: the other side of the same boundary."""
        with self.assertRaises(RetryConfigError):
            RetryConfig(initial_wait_seconds=10.0, max_wait_seconds=9.0)

    def test_an_exponential_base_that_is_a_boolean_is_refused(self):
        """`or@177`: the type half, on a bool."""
        with self.assertRaises(RetryConfigError):
            RetryConfig(exponential_base=True)

    def test_an_exponential_base_that_is_not_a_number_is_refused(self):
        """`or@177`: the type half, on a string."""
        with self.assertRaises(RetryConfigError):
            RetryConfig(exponential_base="2.0")  # type: ignore[arg-type]

    def test_an_exponential_base_of_exactly_one_is_accepted(self):
        """`or@181`: the lower bound of the range -- exactly 1.0 is legal.

        The guard is ``1.0 <= base <= 4.0``.  Exactly 1.0 is inside the
        range and must be accepted; the mutant (``or`` -> ``and``) lets
        the two bound checks fight each other and refuses it.
        """
        config = RetryConfig(exponential_base=1.0)
        self.assertEqual(config.exponential_base, 1.0)

    def test_an_exponential_base_of_exactly_four_is_accepted(self):
        """`or@181`: the upper bound of the range -- exactly 4.0 is legal."""
        config = RetryConfig(exponential_base=4.0)
        self.assertEqual(config.exponential_base, 4.0)

    def test_an_exponential_base_above_four_is_refused(self):
        """`or@181`: the other side of the upper bound."""
        with self.assertRaises(RetryConfigError):
            RetryConfig(exponential_base=4.0001)

    def test_a_jitter_that_is_a_boolean_is_refused(self):
        """`or@181`: the type half, on a bool."""
        with self.assertRaises(RetryConfigError):
            RetryConfig(jitter=True)

    def test_a_jitter_that_is_not_a_number_is_refused(self):
        """`or@181`: the type half, on a string."""
        with self.assertRaises(RetryConfigError):
            RetryConfig(jitter="0.5")  # type: ignore[arg-type]

    def test_a_jitter_of_exactly_zero_is_accepted(self):
        """`or@181`: the lower bound of the jitter range -- exactly 0.0.

        ``jitter = 0`` declares an exact wait, which the schedule
        documents as legal.  Under the mutant (``or`` -> ``and``) it is
        refused.
        """
        config = RetryConfig(jitter=0.0)
        self.assertEqual(config.jitter, 0.0)
        window = config.schedule()[0]
        self.assertEqual(window.low, window.nominal)

    def test_a_jitter_of_exactly_one_is_accepted(self):
        """`or@181`: the upper bound of the jitter range -- exactly 1.0."""
        config = RetryConfig(jitter=1.0)
        self.assertEqual(config.jitter, 1.0)
        self.assertEqual(config.schedule()[0].low, 0.0)

    def test_a_jitter_above_one_is_refused(self):
        """`or@181`: the other side of the upper bound."""
        with self.assertRaises(RetryConfigError):
            RetryConfig(jitter=1.0001)

    # -- the timeout guard ---------------------------------------------

    def test_a_timeout_seconds_that_is_a_boolean_is_refused(self):
        """`or@665`: the type half, on a bool.

        ``isinstance(True, (int, float))`` is True, so the bool half is
        the only thing that refuses a boolean timeout.  Under the
        mutant (``or`` -> ``and``) a boolean timeout is accepted, and
        ``True`` seconds means "one second".
        """
        with self.assertRaises(RetryConfigError):
            run_with_timeout(lambda: None, True)  # type: ignore[arg-type]

    def test_a_timeout_seconds_that_is_not_a_number_is_refused(self):
        """`or@665`: the type half, on a string."""
        with self.assertRaises(RetryConfigError):
            run_with_timeout(lambda: None, "1.0")  # type: ignore[arg-type]

    # -- the gate: a RETRY verdict that carries no window --------------

    @staticmethod
    def _windowless_retry_verdict() -> RetryVerdict:
        """A verdict that says RETRY but declares no wait.

        ``classify_call`` never produces one -- a RETRY verdict always
        carries a window -- so the only way to reach the gate's window
        half is to substitute one.  That is the point: the guard has to
        hold for a verdict the classifier did not produce.
        """
        return RetryVerdict(
            decision=RetryDecision.RETRY,
            kind=CallKind.SESSION_LIFECYCLE,
            failure_class=FailureClass.RETRYABLE,
            reason="a retry that declares no wait",
            window=None,
        )

    def _with_classify_call(self, replacement):
        """Run a callable with ``retry_config.classify_call`` replaced."""

        class _Patch:
            def __enter__(self):
                self.original = rc.classify_call
                rc.classify_call = replacement
                return self

            def __exit__(self, *exc):
                rc.classify_call = self.original
                return False

        return _Patch()

    def test_a_retry_verdict_without_a_window_ends_the_gate(self):
        """`or@530`: the window half of the gate's stop rule.

        The gate stops when the verdict is not RETRY **or** the verdict
        carries no window.  The second half is what stops a RETRY
        verdict that has no declared wait -- retrying with no schedule
        would wait an undeclared amount of time.

        The discriminator is a verdict whose decision is RETRY and whose
        window is None.  Under the mutant (``or`` -> ``and``) the gate
        goes on to sleep on a missing window, so the outcome claims a
        retry that was never scheduled.
        """
        gate = RetryGate(RetryConfig(max_retries=5), sleep=lambda _s: None)

        def fake_classify_call(*_args, **_kwargs):
            return self._windowless_retry_verdict()

        with self._with_classify_call(fake_classify_call):
            outcome = gate.execute(
                CallKind.SESSION_LIFECYCLE,
                lambda: (_ for _ in ()).throw(RuntimeError("throttled")),
            )

        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.attempts, 1)
        self.assertEqual(outcome.windows, ())
        self.assertIsNotNone(outcome.verdict)
        self.assertIs(outcome.verdict.decision, RetryDecision.RETRY)

    def test_a_retry_verdict_without_a_window_ends_the_classify_path_too(self):
        """`or@552`: the same window half on the returned-value path.

        The gate has two copies of the stop rule -- one for a raised
        exception and one for a returned value the caller classified as
        a failure -- and both have the window half.
        """
        gate = RetryGate(RetryConfig(max_retries=5), sleep=lambda _s: None)

        def fake_classify_call(*_args, **_kwargs):
            return self._windowless_retry_verdict()

        with self._with_classify_call(fake_classify_call):
            outcome = gate.execute(
                CallKind.SESSION_LIFECYCLE,
                lambda: "a value the caller rejects",
                classify=lambda _value: throttle(),
            )

        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.attempts, 1)
        self.assertEqual(outcome.windows, ())
        self.assertIsNotNone(outcome.verdict)
        self.assertIs(outcome.verdict.decision, RetryDecision.RETRY)

    # -- the gate: the may-have-executed flag ---------------------------

    def test_the_gate_keeps_the_indeterminate_flag_from_the_verdict(self):
        """`or@538`: the flag half of the outcome, on the classify path.

        The outcome's ``may_have_executed`` is the verdict's flag **or**
        the failure's flag.  The verdict half is what carries an
        indeterminate classification the raw failure does not repeat, so
        dropping it reports an unknown outcome as a definite one.

        The discriminator: the failure does NOT carry the flag, but the
        verdict does.  Under the mutant (``or`` -> ``and``) the outcome
        reports ``may_have_executed=False`` for a call the gate itself
        called indeterminate.
        """
        post_write_without_the_flag = Failure(
            classification=FailureClass.NON_RETRYABLE,
            phase=FailurePhase.POST_WRITE,
            reason="the connection dropped after the request was written",
            may_have_executed=False,
        )
        gate = RetryGate(RetryConfig(max_retries=5), sleep=lambda _s: None)

        outcome = gate.execute(
            CallKind.SESSION_LIFECYCLE,
            lambda: "a value the caller rejects",
            classify=lambda _value: post_write_without_the_flag,
        )

        self.assertFalse(outcome.ok)
        self.assertIs(outcome.verdict.decision, RetryDecision.INDETERMINATE)
        self.assertTrue(outcome.may_have_executed)

    def test_the_gate_keeps_the_indeterminate_flag_on_the_raised_path(self):
        """`or@560`: the flag half of the outcome, on the exception path.

        The same flag half exists on the raised-exception path.  The
        discriminator is a verdict that carries the flag while the
        classified failure does not: the exception is classified as an
        ordinary transport failure (flag False) and the verdict is the
        one that knows the call may have run.
        """
        gate = RetryGate(RetryConfig(max_retries=5), sleep=lambda _s: None)

        def fake_classify_call(*_args, **_kwargs):
            return RetryVerdict(
                decision=RetryDecision.INDETERMINATE,
                kind=CallKind.SESSION_LIFECYCLE,
                failure_class=FailureClass.NON_RETRYABLE,
                reason="the call may already have executed",
                may_have_executed=True,
            )

        with self._with_classify_call(fake_classify_call):
            outcome = gate.execute(
                CallKind.SESSION_LIFECYCLE,
                lambda: (_ for _ in ()).throw(ValueError("a plain transport failure")),
            )

        self.assertFalse(outcome.ok)
        self.assertIs(outcome.verdict.decision, RetryDecision.INDETERMINATE)
        self.assertTrue(outcome.may_have_executed)

    # -- the self-check ------------------------------------------------

    def test_the_self_check_passes_on_the_real_code(self):
        """`eq@702` / `eq@703` / `eq@704`: the self-check's own asserts.

        The self-check is the module's last line of defence.  Its
        asserts are real code, and a fault planted in one of them turns
        the self-check into a no-op that still prints "OK".
        """
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            runpy.run_module("retry_config", run_name="__main__")
        self.assertIn("retry-config OK", buffer.getvalue())

    def test_the_self_check_fails_when_the_default_retry_count_is_wrong(self):
        """`eq@702`: the self-check's first assert.

        ``assert config.max_retries == 5`` becomes ``!= 5`` under the
        mutant.  With a six-retry default the mutant's assert PASSES
        (6 != 5) and the other two asserts still hold, so the
        self-check completes without raising -- which is exactly the
        "no-op self-check" the mutation creates.  On the real code the
        assert fires.
        """
        original = rc.RetryConfig

        class SixRetries(original):
            def __init__(self, **kwargs):
                kwargs.setdefault("max_retries", 6)
                super().__init__(**kwargs)

        rc.RetryConfig = SixRetries
        try:
            with self.assertRaises(AssertionError):
                rc.main()
        finally:
            rc.RetryConfig = original

    def test_the_self_check_fails_when_the_first_wait_is_wrong(self):
        """`eq@703`: the self-check's first schedule assert.

        ``assert config.schedule()[0].nominal == 2.0`` becomes ``!= 2.0``
        under the mutant.  With a four-second first wait the mutant's
        assert PASSES (4.0 != 2.0) and the other two asserts still
        hold, so the self-check completes without raising.
        """
        original = rc.RetryConfig

        class ShiftyFirstWait(original):
            def __init__(self, **kwargs):
                kwargs.setdefault("initial_wait_seconds", 4.0)
                super().__init__(**kwargs)

        rc.RetryConfig = ShiftyFirstWait
        try:
            with self.assertRaises(AssertionError):
                rc.main()
        finally:
            rc.RetryConfig = original

    def test_the_self_check_fails_when_the_last_wait_is_wrong(self):
        """`eq@704`: the self-check's last schedule assert.

        ``assert config.schedule()[-1].nominal == 32.0`` becomes ``!=
        32.0`` under the mutant.  With a sixteen-second ceiling the
        mutant's assert PASSES (16.0 != 32.0) and the other two asserts
        still hold, so the self-check completes without raising.
        """
        original = rc.RetryConfig

        class LowCeiling(original):
            def __init__(self, **kwargs):
                kwargs.setdefault("max_wait_seconds", 16.0)
                super().__init__(**kwargs)

        rc.RetryConfig = LowCeiling
        try:
            with self.assertRaises(AssertionError):
                rc.main()
        finally:
            rc.RetryConfig = original

    def test_running_the_module_as_a_script_runs_the_self_check(self):
        """`eq@714`: the ``__main__`` guard.

        ``if __name__ == "__main__":`` becomes ``!=`` under the mutant,
        and then the self-check runs on EVERY import and NEVER runs when
        the module is run as a script -- which is how it is used.
        """
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            runpy.run_module("retry_config", run_name="__main__")
        self.assertIn("retry-config OK", buffer.getvalue())


if __name__ == "__main__":
    unittest.main()
