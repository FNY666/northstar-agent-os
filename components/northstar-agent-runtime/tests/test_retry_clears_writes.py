"""Tests for the retry-clears-writes rule (``retry_clears_writes``).

The rule under test: **before every attempt of a retried node, the pending
writes of the previous attempt are discarded**.  Without it a node that writes
and then fails applies its effect twice -- once in the attempt that failed,
once in the attempt that succeeded.

The tests below drive real paths through the module, not a mock of it: a node
that writes and fails is retried and the second attempt's writes are the only
ones that survive; a node that fails past ``max_attempts`` gives up with the
writes cleared; a node that fails with an exception no policy matches raises
at once.
"""
import asyncio
import unittest

from retry_clears_writes import (
    RETURN_CHANNEL,
    ExternalCancelledError,
    NodeCancelledError,
    NodeTimeoutError,
    PendingWrites,
    RetryPolicy,
    default_retry_on,
    run_with_retry,
)


def _no_sleep(_seconds: float) -> None:
    """Stand-in for ``time.sleep`` so the tests do not wait."""
    return None


def _no_jitter(_low: float, _high: float) -> float:
    """Stand-in for ``random.uniform(0, 1)``."""
    return 0.0


class PendingWritesTests(unittest.TestCase):
    """The write set: pending writes are discardable, committed ones are not."""

    def test_clear_drops_every_pending_write(self):
        writes = PendingWrites()
        writes.write("a", 1)
        writes.write("b", 2)
        self.assertEqual(len(writes), 2)
        self.assertEqual(writes.clear(), 2)
        self.assertEqual(len(writes), 0)
        self.assertEqual(writes.keys(), ())

    def test_committed_writes_are_not_in_the_pending_set_and_survive_clear(self):
        writes = PendingWrites()
        writes.write("a", 1)
        writes.commit("a")
        writes.write("b", 2)
        self.assertEqual(writes.keys(), ("b",))
        writes.clear()
        self.assertEqual(writes.keys(), ())
        self.assertEqual([w.key for w in writes.committed()], ["a"])
        self.assertEqual(writes.committed()[0].value, 1)

    def test_write_sequence_numbers_increase_and_survive_a_clear(self):
        writes = PendingWrites()
        writes.write("a", 1)
        writes.write("b", 2)
        writes.clear()
        writes.write("c", 3)
        self.assertEqual([w.seq for w in writes.pending()], [3])

    def test_return_channel_holds_the_node_result(self):
        writes = PendingWrites()
        writes.write("state", "x")
        writes.write(RETURN_CHANNEL, {"ok": True})
        self.assertEqual(writes.return_value(), {"ok": True})
        writes.clear()
        self.assertIsNone(writes.return_value())


class RetryPolicyTests(unittest.TestCase):
    """The policy: LangGraph's defaults and its three ``retry_on`` shapes."""

    def test_defaults_match_langgraph(self):
        policy = RetryPolicy()
        self.assertEqual(policy.initial_interval, 0.5)
        self.assertEqual(policy.backoff_factor, 2.0)
        self.assertEqual(policy.max_interval, 128.0)
        self.assertEqual(policy.max_attempts, 3)
        self.assertIs(policy.jitter, True)

    def test_retry_on_a_single_exception_class(self):
        policy = RetryPolicy(retry_on=ValueError)
        self.assertTrue(policy.should_retry_on(ValueError("x")))
        self.assertFalse(policy.should_retry_on(KeyError("x")))

    def test_retry_on_a_sequence_of_exception_classes(self):
        policy = RetryPolicy(retry_on=(ValueError, KeyError))
        self.assertTrue(policy.should_retry_on(ValueError("x")))
        self.assertTrue(policy.should_retry_on(KeyError("x")))
        self.assertFalse(policy.should_retry_on(TypeError("x")))

    def test_retry_on_a_callable_predicate(self):
        policy = RetryPolicy(retry_on=lambda exc: "retry" in str(exc))
        self.assertTrue(policy.should_retry_on(ValueError("please retry")))
        self.assertFalse(policy.should_retry_on(ValueError("no")))

    def test_an_unusable_retry_on_is_a_type_error(self):
        policy = RetryPolicy(retry_on=42)
        with self.assertRaises(TypeError):
            policy.should_retry_on(ValueError("x"))

    def test_interval_formula_and_cap(self):
        policy = RetryPolicy(initial_interval=0.5, backoff_factor=2.0, max_interval=128.0)
        self.assertEqual(policy.interval(1), 0.5)
        self.assertEqual(policy.interval(2), 1.0)
        self.assertEqual(policy.interval(3), 2.0)
        # The cap binds long before the raw exponential overflows.
        self.assertEqual(policy.interval(20), 128.0)

    def test_default_retry_on_never_retries_a_programming_error(self):
        self.assertFalse(default_retry_on(ValueError("x")))
        self.assertFalse(default_retry_on(TypeError("x")))
        # RuntimeError is on LangGraph's never-retry list as well.
        self.assertFalse(default_retry_on(RuntimeError("x")))
        self.assertTrue(default_retry_on(ConnectionError()))
        # An exception that is on no list falls through to "retry".
        self.assertTrue(default_retry_on(Exception("transient")))


class ClearingRuleTests(unittest.TestCase):
    """The rule itself: the pending writes are cleared before every attempt."""

    def test_a_failed_attempts_writes_do_not_survive_the_retry(self):
        """The double-apply proof: the old write is gone, only the new one is left."""
        writes = PendingWrites()
        calls = {"n": 0}

        def node():
            calls["n"] += 1
            writes.write("effect", f"attempt-{calls['n']}")
            if calls["n"] == 1:
                raise ConnectionError("transient")
            return "done"

        outcome = run_with_retry(
            node,
            writes=writes,
            policies=(RetryPolicy(retry_on=ConnectionError),),
            sleep=_no_sleep,
            uniform=_no_jitter,
        )
        self.assertEqual(outcome.value, "done")
        self.assertEqual(outcome.attempts, 1)
        self.assertEqual([w.value for w in outcome.writes], ["attempt-2"])
        self.assertNotIn("attempt-1", [w.value for w in outcome.writes])
        self.assertEqual(writes.keys(), ("effect",))

    def test_the_first_attempt_clears_too(self):
        """The clearing is the first line of *every* attempt, not only of retries."""
        writes = PendingWrites()
        writes.write("stale", "from an earlier phase")

        def node():
            writes.write("fresh", 1)
            return None

        outcome = run_with_retry(node, writes=writes, policies=(), sleep=_no_sleep)
        self.assertEqual([w.key for w in outcome.writes], ["fresh"])
        self.assertEqual(outcome.records[0].cleared, 1)

    def test_committed_writes_are_untouched_by_the_clearing(self):
        writes = PendingWrites()
        writes.write("kept", "committed")
        writes.commit("kept")

        def node():
            writes.write("pending", "attempt")
            return None

        run_with_retry(node, writes=writes, policies=(), sleep=_no_sleep)
        self.assertEqual([w.key for w in writes.committed()], ["kept"])
        self.assertEqual(writes.committed()[0].value, "committed")

    def test_the_resuming_flag_is_set_before_the_second_attempt(self):
        writes = PendingWrites()

        def node():
            if not writes.pending() and len(writes.committed()) == 0 and attempts_seen["n"] == 0:
                attempts_seen["n"] += 1
                raise ConnectionError("transient")
            return "ok"

        attempts_seen = {"n": 0}
        outcome = run_with_retry(
            node,
            writes=writes,
            policies=(RetryPolicy(retry_on=ConnectionError),),
            sleep=_no_sleep,
            uniform=_no_jitter,
        )
        self.assertTrue(outcome.resumed)
        self.assertTrue(outcome.records[1].resuming)
        self.assertFalse(outcome.records[0].resuming)
        self.assertEqual(outcome.attempts, 1)

    def test_the_backoff_interval_is_computed_from_the_failed_attempt_count(self):
        writes = PendingWrites()
        waits: list[float] = []

        def node():
            if len(waits) < 3:
                raise ConnectionError("transient")
            return "ok"

        policy = RetryPolicy(
            initial_interval=0.5,
            backoff_factor=2.0,
            max_interval=128.0,
            max_attempts=5,
            jitter=False,
            retry_on=ConnectionError,
        )
        outcome = run_with_retry(
            node,
            writes=writes,
            policies=(policy,),
            sleep=waits.append,
            uniform=_no_jitter,
        )
        self.assertEqual(waits, [0.5, 1.0, 2.0])
        self.assertEqual(outcome.attempts, 3)

    def test_jitter_adds_a_uniform_value_to_the_interval(self):
        writes = PendingWrites()
        waits: list[float] = []

        def node():
            if len(waits) < 1:
                raise ConnectionError("transient")
            return "ok"

        policy = RetryPolicy(
            initial_interval=0.5,
            max_attempts=3,
            jitter=True,
            retry_on=ConnectionError,
        )
        run_with_retry(
            node,
            writes=writes,
            policies=(policy,),
            sleep=waits.append,
            uniform=lambda low, high: 0.25,
        )
        self.assertEqual(waits, [0.75])


class GiveUpTests(unittest.TestCase):
    """Giving up: the attempts run out and the last exception is raised."""

    def test_the_node_fails_past_max_attempts_and_the_last_error_is_raised(self):
        writes = PendingWrites()
        calls = {"n": 0}

        def node():
            calls["n"] += 1
            writes.write("effect", calls["n"])
            raise ConnectionError(f"failure-{calls['n']}")

        policy = RetryPolicy(max_attempts=3, retry_on=ConnectionError)
        with self.assertRaises(ConnectionError) as caught:
            run_with_retry(
                node,
                writes=writes,
                policies=(policy,),
                sleep=_no_sleep,
                uniform=_no_jitter,
            )
        self.assertEqual(str(caught.exception), "failure-3")
        self.assertEqual(calls["n"], 3)
        # The failed attempt's writes are cleared, not left pending.
        self.assertEqual(writes.keys(), ())
        self.assertEqual(len(writes), 0)

    def test_an_exception_no_policy_matches_raises_at_once(self):
        writes = PendingWrites()
        calls = {"n": 0}

        def node():
            calls["n"] += 1
            writes.write("effect", 1)
            raise ValueError("not retryable")

        policy = RetryPolicy(retry_on=ConnectionError)
        with self.assertRaises(ValueError):
            run_with_retry(
                node,
                writes=writes,
                policies=(policy,),
                sleep=_no_sleep,
                uniform=_no_jitter,
            )
        self.assertEqual(calls["n"], 1)
        self.assertEqual(writes.keys(), ())


class CancellationTests(unittest.TestCase):
    """The two shapes of cancellation must not be confused."""

    def test_an_external_cancellation_propagates_untouched(self):
        writes = PendingWrites()

        def node():
            raise ExternalCancelledError("sibling failed")

        with self.assertRaises(ExternalCancelledError):
            run_with_retry(
                node,
                writes=writes,
                policies=(RetryPolicy(retry_on=Exception),),
                sleep=_no_sleep,
                uniform=_no_jitter,
            )
        self.assertEqual(writes.keys(), ())

    def test_a_node_cancelled_by_itself_becomes_a_node_cancelled_error(self):
        writes = PendingWrites()
        calls = {"n": 0}

        def node():
            calls["n"] += 1
            raise asyncio.CancelledError()

        with self.assertRaises(NodeCancelledError):
            run_with_retry(
                node,
                writes=writes,
                policies=(RetryPolicy(retry_on=Exception),),
                sleep=_no_sleep,
                uniform=_no_jitter,
            )
        # Not reported as success, and not silently retried into success.
        self.assertEqual(calls["n"], 1)
        self.assertEqual(writes.keys(), ())

    def test_a_node_cancelled_by_itself_is_not_retried_into_success(self):
        writes = PendingWrites()
        calls = {"n": 0}

        def node():
            calls["n"] += 1
            if calls["n"] == 1:
                raise asyncio.CancelledError()
            return "ok"

        with self.assertRaises(NodeCancelledError):
            run_with_retry(
                node,
                writes=writes,
                policies=(RetryPolicy(retry_on=Exception),),
                sleep=_no_sleep,
                uniform=_no_jitter,
            )
        self.assertEqual(calls["n"], 1)


class TimeoutPathTests(unittest.TestCase):
    """The timeout path clears the writes too."""

    def test_the_timeout_clears_the_pending_writes(self):
        import threading

        writes = PendingWrites()
        release = threading.Event()

        def node():
            writes.write("half-done", True)
            release.wait(2.0)
            return "late"

        try:
            with self.assertRaises(NodeTimeoutError):
                run_with_retry(
                    node,
                    writes=writes,
                    policies=(RetryPolicy(retry_on=Exception),),
                    timeout=0.05,
                    sleep=_no_sleep,
                    uniform=_no_jitter,
                )
        finally:
            release.set()
        self.assertEqual(writes.keys(), ())
        # The abandoned attempt cannot write into the next attempt.
        self.assertFalse(writes.write("after", 1))


class RealPathTests(unittest.TestCase):
    """The three paths the slice promises to drive end to end."""

    def test_path_a_a_node_that_writes_then_fails_is_retried_without_the_old_write(self):
        writes = PendingWrites()
        state = {"count": 0}

        def node():
            state["count"] += 1
            writes.write("ledger", state["count"])
            if state["count"] == 1:
                raise ConnectionError("transient")
            return state["count"]

        outcome = run_with_retry(
            node,
            writes=writes,
            policies=(RetryPolicy(retry_on=ConnectionError),),
            sleep=_no_sleep,
            uniform=_no_jitter,
        )
        self.assertEqual(outcome.value, 2)
        self.assertEqual([w.value for w in outcome.writes], [2])
        self.assertEqual(len(writes), 1)

    def test_path_b_the_node_fails_past_max_attempts_and_the_writes_are_cleared(self):
        writes = PendingWrites()
        calls = {"n": 0}

        def node():
            calls["n"] += 1
            writes.write("ledger", calls["n"])
            raise ConnectionError("always down")

        with self.assertRaises(ConnectionError):
            run_with_retry(
                node,
                writes=writes,
                policies=(RetryPolicy(max_attempts=2, retry_on=ConnectionError),),
                sleep=_no_sleep,
                uniform=_no_jitter,
            )
        self.assertEqual(calls["n"], 2)
        self.assertEqual(writes.keys(), ())
        self.assertEqual(writes.committed(), ())

    def test_path_c_a_non_retryable_exception_raises_on_the_first_failure(self):
        writes = PendingWrites()
        calls = {"n": 0}

        def node():
            calls["n"] += 1
            writes.write("ledger", calls["n"])
            raise ValueError("bad input")

        with self.assertRaises(ValueError):
            run_with_retry(
                node,
                writes=writes,
                policies=(RetryPolicy(retry_on=ConnectionError),),
                sleep=_no_sleep,
                uniform=_no_jitter,
            )
        self.assertEqual(calls["n"], 1)
        self.assertEqual(writes.keys(), ())


class ResumingConfigTests(unittest.TestCase):
    """Before the next attempt the config is marked as resuming."""

    def test_the_config_carries_the_resuming_flag_after_a_retry(self):
        from retry_clears_writes import CONFIG_KEY_RESUMING

        writes = PendingWrites()
        calls = {"n": 0}

        def node():
            calls["n"] += 1
            if calls["n"] == 1:
                raise ConnectionError("transient")
            return "ok"

        outcome = run_with_retry(
            node,
            writes=writes,
            policies=(RetryPolicy(retry_on=ConnectionError),),
            sleep=_no_sleep,
            uniform=_no_jitter,
            config={"configurable": {"other": 1}},
        )
        self.assertIs(outcome.config["configurable"][CONFIG_KEY_RESUMING], True)
        self.assertEqual(outcome.config["configurable"]["other"], 1)

    def test_a_run_without_a_retry_carries_no_resuming_flag(self):
        from retry_clears_writes import CONFIG_KEY_RESUMING

        writes = PendingWrites()
        outcome = run_with_retry(lambda: "ok", writes=writes, policies=())
        self.assertNotIn(CONFIG_KEY_RESUMING, outcome.config.get("configurable", {}))
        self.assertFalse(outcome.resumed)
