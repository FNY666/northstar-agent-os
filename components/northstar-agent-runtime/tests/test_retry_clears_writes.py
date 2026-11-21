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


class _TruthyResponse:
    """A response object that is always truthy.

    ``requests.Response.__bool__`` reports ``status < 400``, so a real
    response with a 5xx status is FALSY and the module's
    ``if exc.response`` check sends it to the "no response" arm.  This
    stand-in keeps the band check reachable.
    """

    def __init__(self, status_code: int):
        self.status_code = status_code


class _FakeHttpxResponse:
    """A response object for the stand-in httpx module."""

    def __init__(self, status_code: int):
        self.status_code = status_code


class _FakeHttpxHTTPStatusError(Exception):
    """The httpx-shaped status error used by the stand-in module."""

    def __init__(self, response):
        super().__init__("http status error")
        self.response = response


class _FakeHttpxModule:
    """A stand-in for the ``httpx`` module.

    The predicate imports ``httpx`` INSIDE its own body, so a stand-in
    placed in ``sys.modules`` is what that import finds.  The arm is
    therefore exercised whether or not the real httpx is installed.
    """

    HTTPStatusError = _FakeHttpxHTTPStatusError


class _httpx_installed:
    """Context manager: the stand-in httpx is importable inside the block."""

    def __init__(self):
        self.previous = None

    def __enter__(self):
        import sys

        self.previous = sys.modules.get("httpx")
        sys.modules["httpx"] = _FakeHttpxModule()
        return self

    def __exit__(self, *exc_info):
        import sys

        if self.previous is None:
            sys.modules.pop("httpx", None)
        else:
            sys.modules["httpx"] = self.previous
        return False


def _httpx_retry_on(status_code: int) -> bool:
    """What the default predicate says about an httpx-shaped 5xx/4xx error.

    The stand-in httpx is installed for the whole PREDICATE CALL, because
    the predicate imports httpx inside its own body -- installing it only
    while the exception was built would not be seen by that import.
    """
    with _httpx_installed():
        error = _FakeHttpxHTTPStatusError(_FakeHttpxResponse(status_code))
        return default_retry_on(error)


class SecondHalfGuardTests(unittest.TestCase):
    """The second half of each guard in the retry-clears-writes module.

    Each guard below is a conjunction or a two-armed conditional, and the
    rest of the suite drives only one of the arms.  These tests drive the
    other arm, so both halves of every guard are covered.
    """

    # -- retT@155: the "the write was recorded" half --------------------

    def test_a_write_to_an_unsealed_set_is_recorded(self):
        """`retT@155`: the success half of ``write``.

        The suite drives the sealed half -- a write to a sealed set returns
        False.  The other half is the ordinary case: an unsealed write is
        recorded and reports success.
        """
        writes = PendingWrites()
        self.assertTrue(writes.write("k", "v"))
        self.assertEqual([w.key for w in writes.pending()], ["k"])
        self.assertEqual(writes.get("k"), "v")

    # -- eq@191: the "the key matches" half of ``commit`` ---------------

    def test_commit_by_key_commits_only_the_named_key(self):
        """`eq@191`: the key-matching half of the selective commit.

        Committing everything (the ``key is None`` arm) was already
        covered; committing ONE key by name is the other arm.
        """
        writes = PendingWrites()
        writes.write("a", 1)
        writes.write("b", 2)
        selected = writes.commit("b")
        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0].key, "b")
        self.assertEqual(writes.keys(), ("a",))
        self.assertEqual(writes.committed()[0].key, "b")

    def test_commit_by_an_absent_key_commits_nothing(self):
        """`eq@191`: the negative half -- no matching key means no commit."""
        writes = PendingWrites()
        writes.write("a", 1)
        self.assertEqual(writes.commit("zzz"), ())
        self.assertEqual(writes.keys(), ("a",))
        self.assertEqual(writes.committed(), ())

    # -- lt@233 / lt@235: the 5xx band's lower edge ----------------------

    def test_a_500_status_is_retried(self):
        """`lt@233`: the lower edge of the retryable 5xx band.

        The band is ``500 <= status < 600``; 500 is inside it.  The suite
        only drove an error that is not an HTTP error at all.

        ``httpx`` is driven through a stand-in module installed in
        ``sys.modules``, so the arm is exercised whether or not httpx is
        installed on the machine running the suite -- the module's own
        ``import httpx`` inside the predicate picks it up.
        """
        self.assertTrue(_httpx_retry_on(500))

    def test_a_599_status_is_retried(self):
        """`lt@233`: the last status inside the band."""
        self.assertTrue(_httpx_retry_on(599))

    def test_a_600_status_is_not_retried(self):
        """`lt@233`: the upper edge of the band.

        600 is NOT a 5xx.  This is the discriminating input: a mutant
        that turns ``< 600`` into ``<= 600`` retries a 600, and this
        test says it does not.
        """
        self.assertFalse(_httpx_retry_on(600))

    def test_a_499_status_is_not_retried(self):
        """`lt@233`: below the band -- 499 is a client error."""
        self.assertFalse(_httpx_retry_on(499))

    def test_an_http_error_with_no_response_is_retried(self):
        """`lt@235`: the no-response arm of the requests branch.

        An ``HTTPError`` raised with no response object at all has no
        status to inspect, so it is treated as retryable.
        """
        import requests

        self.assertTrue(default_retry_on(requests.HTTPError("no response")))

    def test_a_600_status_on_a_requests_error_is_not_retried(self):
        """`lt@235`: the upper edge of the band, on the requests arm.

        ``requests.Response`` is falsy for any status at or above 400, so
        a real ``requests.Response`` never reaches the band check with a
        5xx-status payload.  The stand-in response below is always truthy,
        which is what lets the band's upper edge be reached at all.
        """
        import requests

        response = _TruthyResponse(600)
        error = requests.HTTPError(response=response)
        self.assertFalse(default_retry_on(error))

    def test_a_500_status_on_a_requests_error_is_retried(self):
        """`lt@235`: the lower edge of the band, on the requests arm."""
        import requests

        response = _TruthyResponse(500)
        error = requests.HTTPError(response=response)
        self.assertTrue(default_retry_on(error))

    # -- or@274 / lt@276: the max_attempts guard's two halves -----------

    def test_a_boolean_max_attempts_is_refused(self):
        """`or@274`: the type half of the max_attempts guard, on a bool.

        A bool IS an int in Python, so only the isinstance(..., bool)
        half can catch it.
        """
        with self.assertRaises(ValueError) as ctx:
            RetryPolicy(max_attempts=True)
        self.assertIn("max_attempts must be an integer", str(ctx.exception))

    def test_a_float_max_attempts_is_refused(self):
        """`or@274`: the other type half -- a float is not an int."""
        with self.assertRaises(ValueError):
            RetryPolicy(max_attempts=3.0)

    def test_a_zero_max_attempts_is_refused(self):
        """`lt@276`: the lower bound of the max_attempts guard."""
        with self.assertRaises(ValueError) as ctx:
            RetryPolicy(max_attempts=0)
        self.assertIn("max_attempts must be >= 1", str(ctx.exception))

    def test_a_max_attempts_of_one_is_allowed(self):
        """`lt@276`: the boundary -- one attempt is the minimum allowed."""
        policy = RetryPolicy(max_attempts=1)
        self.assertEqual(policy.max_attempts, 1)

    # -- or@280: the type half of the numeric guard ---------------------

    def test_a_boolean_interval_is_refused(self):
        """`or@280`: the type half of the numeric guard, on a bool."""
        with self.assertRaises(ValueError) as ctx:
            RetryPolicy(initial_interval=True)
        self.assertIn("initial_interval must be a number", str(ctx.exception))

    def test_a_string_backoff_factor_is_refused(self):
        """`or@280`: the type guard on the backoff factor."""
        with self.assertRaises(ValueError):
            RetryPolicy(backoff_factor="2.0")

    def test_a_string_max_interval_is_refused(self):
        """`or@280`: the type guard on the max interval."""
        with self.assertRaises(ValueError):
            RetryPolicy(max_interval="128")

    # -- lt@282: the sign of the initial interval -----------------------

    def test_a_negative_initial_interval_is_refused(self):
        """`lt@282`: the sign half of the initial-interval guard."""
        with self.assertRaises(ValueError) as ctx:
            RetryPolicy(initial_interval=-0.5)
        self.assertIn("initial_interval must be >= 0", str(ctx.exception))

    def test_a_zero_initial_interval_is_allowed(self):
        """`lt@282`: the boundary -- zero is non-negative, so it is kept."""
        policy = RetryPolicy(initial_interval=0.0)
        self.assertEqual(policy.initial_interval, 0.0)

    # -- lt@284: the lower bound of the backoff factor ------------------

    def test_a_backoff_factor_below_one_is_refused(self):
        """`lt@284`: the lower bound of the backoff-factor guard."""
        with self.assertRaises(ValueError) as ctx:
            RetryPolicy(backoff_factor=0.5)
        self.assertIn("backoff_factor must be >= 1.0", str(ctx.exception))

    def test_a_backoff_factor_of_one_is_allowed(self):
        """`lt@284`: the boundary -- a factor of 1.0 is allowed."""
        policy = RetryPolicy(backoff_factor=1.0)
        self.assertEqual(policy.backoff_factor, 1.0)

    # -- lt@286: the sign of the max interval ---------------------------

    def test_a_negative_max_interval_is_refused(self):
        """`lt@286`: the sign half of the max-interval guard."""
        with self.assertRaises(ValueError) as ctx:
            RetryPolicy(max_interval=-1.0)
        self.assertIn("max_interval must be >= 0", str(ctx.exception))

    def test_a_zero_max_interval_is_allowed(self):
        """`lt@286`: the boundary -- zero is non-negative, so it is kept."""
        policy = RetryPolicy(max_interval=0.0)
        self.assertEqual(policy.max_interval, 0.0)
