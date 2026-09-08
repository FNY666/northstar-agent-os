"""The transport policy: what a provider fault means, and what retrying it costs.

These tests are mostly about *numbers* - the schedule, the deadline, the clamp between a
workspace's table and a command-line flag - because a retry policy is only worth having if
the worst case it can produce is knowable. The end-of-file tests then check the two places a
number becomes behaviour: the loop's attempt path, and the CLI's refusal of a policy nobody
read.
"""
from __future__ import annotations

import json
import sys
import unittest
from typing import Any

import support  # noqa: F401  (bootstraps sys.path)
from support import RuntimeTestCase

from providers.base import AssistantMessage, ProviderError, UserMessage
from provider_retry import (
    ALLOWED_RETRY_KEYS,
    CONTEXT_OVERFLOW_ACTIONS,
    FAILURE_CLASSES,
    MAX_ATTEMPTS,
    MAX_DEADLINE_MS,
    MAX_DELAY_MS,
    RETRYABLE_CLASSES,
    RETRY_SCHEMA_VERSION,
    AttemptRecord,
    ProviderFault,
    RetryConfigurationError,
    RetryPolicy,
    StopRetry,
    classify,
    execute,
    merge_cli,
)


class _Http:
    """A stand-in for an SDK error's ``response`` object."""

    def __init__(self, status_code: int | None = None, headers: dict[str, str] | None = None) -> None:
        if status_code is not None:
            self.status_code = status_code
        if headers is not None:
            self.headers = dict(headers)


def _error(message: str = "", *, status: int | None = None, headers: dict[str, str] | None = None, kind: str | None = None, retry_after_ms: int | None = None) -> ProviderError:
    kwargs: dict[str, Any] = {}
    if kind is not None:
        kwargs["failure_kind"] = kind
    if status is not None:
        kwargs["status_code"] = status
    if retry_after_ms is not None:
        kwargs["retry_after_ms"] = retry_after_ms
    error = ProviderError(message, **kwargs)
    if status is not None or headers is not None:
        error.response = _Http(status, headers)  # type: ignore[attr-defined]
    return error


class ClassificationTests(unittest.TestCase):
    def test_status_codes_map_to_named_faults(self):
        cases = {
            429: "rate_limited",
            409: "rate_limited",
            425: "rate_limited",
            529: "overloaded",
            503: "overloaded",
            500: "server_error",
            502: "server_error",
            408: "timeout",
            504: "timeout",
            413: "context_overflow",
            401: "auth",
            403: "auth",
            400: "client_error",
            404: "client_error",
            422: "client_error",
            418: "client_error",
        }
        for status, expected in cases.items():
            with self.subTest(status=status):
                self.assertEqual(expected, classify(_error(status=status)).kind)

    def test_a_provider_that_names_the_fault_is_believed_first(self):
        # The status code says 500 and the prose says nothing useful; the provider's own
        # claim still wins, because it is the only party that read the response body.
        fault = classify(_error("something odd happened", status=500, kind="overloaded"))
        self.assertEqual("overloaded", fault.kind)
        self.assertEqual(500, fault.status_code)

    def test_prose_is_the_fallback_and_specific_phrases_win(self):
        for message, expected in (
            ("Error code: 429 too many requests", "rate_limited"),
            ("rate_limit_error exceeded", "rate_limited"),
            ("provider is overloaded, try again", "overloaded"),
            ("Connection reset by peer", "network"),
            ("the read operation timed out", "timeout"),
            ("prompt is too long: 210000 tokens", "context_overflow"),
            ("context_length_exceeded", "context_overflow"),
            ("invalid api key supplied", "auth"),
            ("Internal Server Error from gateway", "server_error"),
        ):
            with self.subTest(message=message):
                self.assertEqual(expected, classify(RuntimeError(message)).kind)

    def test_os_level_faults_are_network_or_timeout_without_any_text(self):
        self.assertEqual("network", classify(ConnectionError()).kind)
        self.assertEqual("timeout", classify(TimeoutError("")).kind)
        # And a fault we cannot name stays unnamed: it is *not* promoted to "transient".
        self.assertEqual("unknown", classify(ValueError("x = 1")).kind)

    def test_text_already_reached_the_consumer_outranks_everything(self):
        # Not a guess about the provider - a fact about this runtime. Once the terminal has
        # seen characters, the only honest verdict is "interrupted", whatever the cause.
        for error in (_error("boom", status=429), ConnectionError("reset")):
            self.assertEqual("stream_interrupted", classify(error, already_streamed=True).kind)

    def test_retry_after_is_read_from_attribute_header_and_prose(self):
        self.assertEqual(250, classify(_error("429", status=429, retry_after_ms=250)).retry_after_ms)
        self.assertEqual(3000, classify(_error("429", status=429, headers={"Retry-After": "3"})).retry_after_ms)
        self.assertEqual(180, classify(_error("429", status=429, headers={"retry-after-ms": "180"})).retry_after_ms)
        self.assertEqual(7000, classify(RuntimeError("throttled, retry-after: 7")).retry_after_ms)
        self.assertEqual(900, classify(RuntimeError("throttled retry-after-ms=900")).retry_after_ms)

    def test_an_http_date_retry_after_is_declined_not_guessed(self):
        # Parsing "Wed, 21 Oct 2026 07:28:00 GMT" would need a clock assumption; "no
        # instruction" is the truthful answer, and the policy then uses its own schedule.
        self.assertIsNone(classify(_error("429", status=429, headers={"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"})).retry_after_ms)

    def test_a_status_only_on_the_response_object_is_still_found(self):
        error = RuntimeError("gateway said no")
        error.response = _Http(503)  # type: ignore[attr-defined]
        fault = classify(error)
        self.assertEqual("overloaded", fault.kind)
        self.assertEqual(503, fault.status_code)

    def test_detail_is_one_line_and_bounded(self):
        fault = classify(RuntimeError("line one\nline two " + ("x" * 500)))
        self.assertNotIn("\n", fault.detail)
        self.assertLessEqual(len(fault.detail), 520)
        self.assertLessEqual(len(fault.as_dict()["detail"]), 200)

    def test_an_unknown_class_name_is_refused_not_stored(self):
        with self.assertRaises(RetryConfigurationError):
            ProviderFault("temporarily_broken")


class PolicyValidationTests(unittest.TestCase):
    def test_defaults_are_a_small_budget_not_a_big_one(self):
        policy = RetryPolicy()
        self.assertTrue(policy.enabled)
        self.assertEqual(3, policy.max_attempts)
        self.assertEqual(RETRYABLE_CLASSES, tuple(policy.retry_on))
        self.assertIn("retry=2 additional attempt(s)", policy.describe())

    def test_one_attempt_means_no_retry_and_disables_the_policy(self):
        self.assertFalse(RetryPolicy(max_attempts=1).enabled)
        self.assertIn("retry=off", RetryPolicy(max_attempts=1).describe())
        self.assertEqual(0, RetryPolicy(max_attempts=1).planned_wait_ms())

    def test_an_empty_retry_set_is_off_rather_than_everything(self):
        policy = RetryPolicy(retry_on=())
        self.assertFalse(policy.enabled)
        self.assertIn("retry=off", policy.describe())

    def test_attempts_are_capped_by_the_runtime_not_by_the_operator(self):
        for bad in (0, -1, MAX_ATTEMPTS + 1, True, "3", None):
            with self.subTest(bad=bad):
                with self.assertRaises(RetryConfigurationError) as caught:
                    RetryPolicy(max_attempts=bad)
                self.assertIn(str(MAX_ATTEMPTS), str(caught.exception))

    def test_delays_must_fit_inside_their_own_ceiling(self):
        with self.assertRaises(RetryConfigurationError):
            RetryPolicy(base_delay_ms=MAX_DELAY_MS + 1)
        with self.assertRaises(RetryConfigurationError):
            RetryPolicy(base_delay_ms=5000, max_delay_ms=1000)
        with self.assertRaises(RetryConfigurationError):
            RetryPolicy(deadline_ms=MAX_DEADLINE_MS + 1)
        with self.assertRaises(RetryConfigurationError):
            RetryPolicy(multiplier=0.5)
        with self.assertRaises(RetryConfigurationError):
            RetryPolicy(multiplier=11)

    def test_unknown_enum_values_are_listed_back_to_the_reader(self):
        with self.assertRaises(RetryConfigurationError) as caught:
            RetryPolicy(jitter="decorrelated")
        self.assertIn("none, full", str(caught.exception))
        with self.assertRaises(RetryConfigurationError) as caught:
            RetryPolicy(on_context_overflow="shrink_and_hope")
        self.assertIn(", ".join(CONTEXT_OVERFLOW_ACTIONS), str(caught.exception))

    def test_retry_on_may_only_name_faults_this_runtime_understands(self):
        with self.assertRaises(RetryConfigurationError) as caught:
            RetryPolicy(retry_on=("rate_limited", "polite_refusal"))
        text = str(caught.exception)
        self.assertIn("polite_refusal", text)
        for known in ("timeout", "overloaded"):
            self.assertIn(known, text)

    def test_the_unretryable_faults_cannot_be_asked_for(self):
        # Each refusal says why, because the tempting one is the stream: "the connection
        # dropped, surely just send it again" is exactly how a transcript starts disagreeing
        # with what the operator watched.
        for forbidden, hint in (
            ("stream_interrupted", "re-shows text"),
            ("auth", "sending it again"),
            ("client_error", "sending it again"),
            ("unknown", "not evidence"),
        ):
            with self.subTest(kind=forbidden):
                with self.assertRaises(RetryConfigurationError) as caught:
                    RetryPolicy(retry_on=(forbidden,))
                self.assertIn(hint, str(caught.exception))

    def test_a_future_schema_version_is_refused_rather_than_half_read(self):
        with self.assertRaises(RetryConfigurationError) as caught:
            RetryPolicy(schema_version="northstar.retry.v2")
        self.assertIn(RETRY_SCHEMA_VERSION, str(caught.exception))

    def test_from_mapping_reads_only_the_documented_keys(self):
        policy = RetryPolicy.from_mapping(
            {
                "schema_version": RETRY_SCHEMA_VERSION,
                "max_attempts": 5,
                "base_delay_ms": 300,
                "multiplier": 3,
                "max_delay_ms": 9000,
                "deadline_ms": 30_000,
                "jitter": "none",
                "retry_on": ["rate_limited", "timeout"],
                "respect_retry_after": False,
                "on_context_overflow": "compact_once",
            }
        )
        assert policy is not None
        self.assertEqual(5, policy.max_attempts)
        self.assertEqual(("rate_limited", "timeout"), tuple(policy.retry_on))
        self.assertFalse(policy.respect_retry_after)
        self.assertEqual("compact_once", policy.on_context_overflow)
        self.assertEqual(300 + 900 + 2700 + 8100, policy.planned_wait_ms())

    def test_a_typo_in_a_retry_table_is_an_error_not_a_default(self):
        with self.assertRaises(RetryConfigurationError) as caught:
            RetryPolicy.from_mapping({"max_atempts": 4})
        text = str(caught.exception)
        self.assertIn("max_atempts", text)
        for key in sorted(ALLOWED_RETRY_KEYS):
            self.assertIn(key, text)

    def test_from_mapping_refuses_a_scalar_and_accepts_absence(self):
        self.assertIsNone(RetryPolicy.from_mapping(None))
        with self.assertRaises(RetryConfigurationError):
            RetryPolicy.from_mapping(5)

    def test_types_are_checked_where_toml_cannot_check_them(self):
        with self.assertRaises(RetryConfigurationError):
            RetryPolicy.from_mapping({"retry_on": "rate_limited"})
        with self.assertRaises(RetryConfigurationError):
            RetryPolicy.from_mapping({"respect_retry_after": "yes"})
        with self.assertRaises(RetryConfigurationError):
            RetryPolicy.from_mapping({"jitter": 2})

    def test_a_seed_is_carried_and_the_sleeper_is_not_a_file_setting(self):
        policy = RetryPolicy.from_mapping({"max_attempts": 2}, seed=42)
        assert policy is not None
        self.assertEqual(42, policy.seed)
        self.assertNotIn("sleeper", ALLOWED_RETRY_KEYS)
        self.assertNotIn("seed", ALLOWED_RETRY_KEYS)

    def test_as_dict_is_the_shape_the_json_cli_emits(self):
        payload = RetryPolicy(max_attempts=2, jitter="none").as_dict()
        self.assertEqual(2, payload["max_attempts"])
        # Two calls is one retry, which is still a policy in force: `enabled` is about
        # whether any fault can be acted on, and it must agree with the flag.
        self.assertTrue(payload["enabled"])
        self.assertEqual(RETRY_SCHEMA_VERSION, payload["schema_version"])
        for name in ("base_delay_ms", "deadline_ms", "retry_on", "planned_wait_ms", "on_context_overflow"):
            self.assertIn(name, payload)
        self.assertNotIn("sleeper", payload)


class ScheduleTests(unittest.TestCase):
    def _plan(self, policy: RetryPolicy, attempt: int, kind: str = "rate_limited", *, waited: int = 0):
        keep, decision = policy.plan(attempt, ProviderFault(kind), waited_ms=waited)
        return keep, decision

    def test_no_jitter_produces_the_textbook_exponential(self):
        policy = RetryPolicy(max_attempts=5, base_delay_ms=100, multiplier=2, max_delay_ms=150, jitter="none")
        delays = []
        for attempt in range(1, 5):
            keep, decision = self._plan(policy, attempt)
            self.assertIsNotNone(keep)
            assert isinstance(decision, AttemptRecord)
            delays.append(decision.delay_ms)
        self.assertEqual([100, 150, 150, 150], delays)
        self.assertEqual(100 + 150 + 150 + 150, policy.planned_wait_ms())

    def test_full_jitter_is_reproducible_per_run_and_bounded(self):
        policy = RetryPolicy(max_attempts=6, base_delay_ms=1, max_delay_ms=4000, jitter="full", seed=7)
        other = RetryPolicy(max_attempts=6, base_delay_ms=1, max_delay_ms=4000, jitter="full", seed=7)
        loose = RetryPolicy(max_attempts=6, base_delay_ms=1, max_delay_ms=4000, jitter="full", seed=8)

        def run(p: RetryPolicy) -> list[int]:
            out = []
            for attempt in range(1, 6):
                _keep, decision = self._plan(p, attempt)
                assert isinstance(decision, AttemptRecord)
                out.append(decision.delay_ms)
            return out

        first, twin, different = run(policy), run(other), run(loose)
        self.assertEqual(first, twin)
        self.assertNotEqual(first, different)
        ceiling = [policy._ceiling(a) for a in range(1, 6)]
        for delay, cap in zip(first, ceiling):
            self.assertGreaterEqual(delay, 1)
            self.assertLessEqual(delay, cap)

    def test_the_provider_says_how_long_and_we_wait_at_least_that(self):
        policy = RetryPolicy(max_attempts=3, base_delay_ms=10, jitter="none", max_delay_ms=5000)
        _keep, decision = policy.plan(1, ProviderFault("rate_limited", retry_after_ms=4000))
        assert isinstance(decision, AttemptRecord)
        self.assertEqual(4000, decision.delay_ms)
        self.assertEqual("", decision.note)

    def test_an_absurd_retry_after_is_capped_and_says_so(self):
        # Waiting ten minutes because a server said so would make the runtime's deadline a
        # decoration; the cap is chosen here, and the note is what makes it auditable.
        policy = RetryPolicy(max_attempts=3, base_delay_ms=10, jitter="none", max_delay_ms=1000, deadline_ms=60_000)
        keep, decision = policy.plan(1, ProviderFault("rate_limited", retry_after_ms=600_000))
        if keep is None:
            self.assertIsInstance(decision, StopRetry)
            self.assertEqual("deadline_exceeded", decision.reason)
        else:
            assert isinstance(decision, AttemptRecord)
            self.assertLessEqual(decision.delay_ms, 1000)
            self.assertIn("we wait the cap instead", decision.note)
        self.assertIn("600000", decision.note)

    def test_respect_retry_after_false_means_our_schedule_and_no_lie(self):
        policy = RetryPolicy(max_attempts=3, base_delay_ms=10, jitter="none", respect_retry_after=False)
        _keep, decision = policy.plan(1, ProviderFault("rate_limited", retry_after_ms=9000))
        assert isinstance(decision, AttemptRecord)
        self.assertEqual(10, decision.delay_ms)

    def test_the_deadline_is_a_waiting_budget_measured_in_the_delays_chosen(self):
        policy = RetryPolicy(max_attempts=8, base_delay_ms=1000, max_delay_ms=4000, jitter="none", deadline_ms=2500)
        keep, decision = self._plan(policy, 1, waited=0)
        assert isinstance(decision, AttemptRecord)
        self.assertEqual(1000, decision.delay_ms)
        keep, decision = self._plan(policy, 2, waited=decision.waited_ms)
        self.assertIsNone(keep)
        assert isinstance(decision, StopRetry)
        self.assertEqual("deadline_exceeded", decision.reason)
        self.assertIn("1500 ms of the 2500 ms deadline is left", decision.detail)

    def test_a_delay_that_exactly_fits_the_deadline_is_still_allowed(self):
        policy = RetryPolicy(max_attempts=3, base_delay_ms=1000, jitter="none", deadline_ms=1000)
        keep, decision = self._plan(policy, 1, waited=0)
        self.assertIsNotNone(keep)
        assert isinstance(decision, AttemptRecord)
        self.assertEqual(1000, decision.waited_ms)

    def test_the_last_attempt_stops_on_the_budget_not_on_the_clock(self):
        policy = RetryPolicy(max_attempts=2, jitter="none")
        keep, decision = self._plan(policy, 2)
        self.assertIsNone(keep)
        assert isinstance(decision, StopRetry)
        self.assertEqual("attempts_exhausted", decision.reason)
        self.assertIn("2 attempt(s) is the budget", decision.detail)
        self.assertEqual({"stop": "attempts_exhausted", "detail": decision.detail}, decision.as_dict())

    def test_a_fault_outside_the_set_stops_without_touching_the_budget(self):
        policy = RetryPolicy(max_attempts=5, retry_on=("rate_limited",), jitter="none")
        keep, decision = self._plan(policy, 1, "server_error")
        self.assertIsNone(keep)
        assert isinstance(decision, StopRetry)
        self.assertEqual("not_retryable", decision.reason)
        self.assertIn("rate_limited", decision.detail)


class ClampTests(unittest.TestCase):
    """The workspace table is a ceiling on the flags, never a floor."""

    def test_a_flag_may_ask_for_fewer_attempts_but_not_more(self):
        workspace = RetryPolicy(max_attempts=2, base_delay_ms=500, deadline_ms=1000, jitter="none")
        tightened = merge_cli(workspace, max_attempts=1)
        assert tightened is not None
        self.assertEqual(1, tightened.max_attempts)
        loosened = merge_cli(RetryPolicy(max_attempts=2, jitter="none"), max_attempts=MAX_ATTEMPTS)
        assert loosened is not None
        self.assertEqual(2, loosened.max_attempts)

    def test_the_clamp_applies_to_every_knob_that_costs_something(self):
        workspace = RetryPolicy(max_attempts=4, base_delay_ms=10, max_delay_ms=200, deadline_ms=500, multiplier=1.5, jitter="none", respect_retry_after=False)
        flags = RetryPolicy(max_attempts=8, base_delay_ms=1, max_delay_ms=100_000, deadline_ms=900_000, multiplier=9, jitter="full", respect_retry_after=True)
        merged = flags.restrict(workspace)
        self.assertEqual(4, merged.max_attempts)
        self.assertEqual(200, merged.max_delay_ms)
        self.assertEqual(500, merged.deadline_ms)
        self.assertEqual(1.5, merged.multiplier)
        self.assertFalse(merged.respect_retry_after)
        # A longer base delay is *tighter* waiting behaviour, so the larger one is kept.
        self.assertEqual(10, merged.base_delay_ms)
        # The workspace owns the shape of the schedule.
        self.assertEqual("none", merged.jitter)

    def test_intersecting_the_fault_sets_can_disable_the_policy_rather_than_widen_it(self):
        workspace = RetryPolicy(max_attempts=5, retry_on=("rate_limited",), jitter="none")
        flags = RetryPolicy(max_attempts=5, retry_on=("timeout",), jitter="none")
        merged = flags.restrict(workspace)
        self.assertEqual((), tuple(merged.retry_on))
        self.assertFalse(merged.enabled)

    def test_the_ladder_may_only_be_asked_for_by_both_sides(self):
        workspace = RetryPolicy(on_context_overflow="fail")
        flags = RetryPolicy(on_context_overflow="compact_once")
        self.assertEqual("fail", flags.restrict(workspace).on_context_overflow)
        eager = RetryPolicy(on_context_overflow="compact_once")
        self.assertEqual("compact_once", eager.restrict(eager).on_context_overflow)

    def test_no_retry_is_a_choice_of_its_own_not_max_attempts_one(self):
        workspace = RetryPolicy(max_attempts=5, base_delay_ms=100, jitter="full", seed=3)
        off = merge_cli(workspace, off=True)
        assert off is not None
        self.assertEqual(1, off.max_attempts)
        self.assertEqual("none", off.jitter)
        self.assertFalse(off.enabled)
        self.assertEqual(100, off.base_delay_ms)  # remembered, so turning it back on is one flag

    def test_no_flags_means_the_workspace_table_verbatim(self):
        workspace = RetryPolicy(max_attempts=4, jitter="none", seed=9)
        self.assertIs(merge_cli(workspace), workspace)

    def test_a_workspace_with_no_opinion_still_gets_the_default_budget(self):
        merged = merge_cli(None, max_attempts=2)
        assert merged is not None
        self.assertEqual(2, merged.max_attempts)
        self.assertEqual(RetryPolicy().base_delay_ms, merged.base_delay_ms)


class ExecuteTests(unittest.TestCase):
    def test_a_policy_off_means_exactly_one_call(self):
        calls = []
        result, summary = execute(lambda: calls.append(1) or "value", policy=None)
        self.assertEqual("value", result)
        self.assertEqual(1, len(calls))
        self.assertFalse(summary.retried)
        self.assertEqual({"attempts": 1, "waited_ms": 0}, summary.as_dict())

    def test_retries_sleep_the_plan_and_report_each_one(self):
        slept: list[float] = []
        seen: list[AttemptRecord] = []
        state = {"n": 0}

        def call():
            state["n"] += 1
            if state["n"] < 3:
                raise _error("too many requests", status=429)
            return "late value"

        policy = RetryPolicy(max_attempts=4, base_delay_ms=100, jitter="none", deadline_ms=60_000)
        result, summary = execute(call, policy=policy, sleep=lambda seconds: slept.append(seconds), on_retry=seen.append)
        self.assertEqual("late value", result)
        self.assertEqual([0.1, 0.2], slept)
        self.assertEqual(2, len(seen))
        self.assertEqual((1, 2), (seen[0].attempt, seen[1].attempt))
        self.assertEqual(4, seen[0].max_attempts)
        self.assertEqual("", seen[0].note)
        self.assertEqual(3, summary.attempts)
        self.assertEqual(300, summary.waited_ms)
        self.assertEqual(["rate_limited", "rate_limited"], [kind for _attempt, kind in summary.faults])
        self.assertIn("3 provider attempt(s)", summary.line())

    def test_the_original_exception_type_survives(self):
        class _ProviderSaidNo(RuntimeError):
            pass

        def call():
            raise _ProviderSaidNo("no")

        with self.assertRaises(_ProviderSaidNo) as caught:
            execute(call, policy=RetryPolicy(max_attempts=3, jitter="none", base_delay_ms=1, sleeper=lambda _s: None))
        self.assertIn("no", str(caught.exception))

    def test_an_unretryable_fault_never_reaches_the_sleeper(self):
        slept: list[float] = []

        def call():
            raise _error("invalid api key", status=401)

        with self.assertRaises(ProviderError):
            execute(call, policy=RetryPolicy(max_attempts=5, sleeper=lambda seconds: slept.append(seconds)))
        self.assertEqual([], slept)

    def test_the_policy_carries_its_own_sleeper_for_a_caller_without_one(self):
        slept: list[float] = []
        state = {"n": 0}

        def call():
            state["n"] += 1
            if state["n"] == 1:
                raise _error("overloaded", status=529)
            return "ok"

        execute(call, policy=RetryPolicy(max_attempts=2, base_delay_ms=5, jitter="none", sleeper=lambda seconds: slept.append(seconds)))
        self.assertEqual([0.005], slept)

    def test_a_stop_is_reported_as_a_decision_not_an_action(self):
        seen: list[AttemptRecord] = []

        def call():
            raise _error("connection reset")

        # The deadline (1 ms) is below the smallest delay, so nothing is retried and nothing
        # is reported as a retry: a stop is a decision not to act.
        policy = RetryPolicy(max_attempts=3, retry_on=("network",), jitter="none", base_delay_ms=5, deadline_ms=1, sleeper=lambda _s: None)
        with self.assertRaises(RuntimeError):
            execute(call, policy=policy, on_retry=seen.append)
        self.assertEqual([], seen)


class ProviderWiringTests(unittest.TestCase):
    def test_the_sdk_retry_loop_is_off_by_default(self):
        # The reason this module exists: a second loop underneath ours multiplies the request
        # count of a run into something no policy file ever described.
        from providers.anthropic import AnthropicProvider
        from providers.openai_compat import OpenAICompatProvider

        self.assertEqual(0, AnthropicProvider(client=object())._client_kwargs["max_retries"])
        self.assertEqual(0, OpenAICompatProvider(client=object())._client_kwargs["max_retries"])

    def test_an_embedder_may_still_choose_the_sdk_loop(self):
        from providers.anthropic import AnthropicProvider

        self.assertEqual(4, AnthropicProvider(client=object(), max_retries=4)._client_kwargs["max_retries"])

    def test_a_wrapped_sdk_error_arrives_classified(self):
        class _GatewayError(Exception):
            status_code = 429

            def __init__(self) -> None:
                super().__init__("Error code: 429 {'type': 'rate_limit_error'}")
                self.headers = {"retry-after-ms": "750"}

        class _Client:
            class messages:  # noqa: N801 - shaped like the SDK surface
                @staticmethod
                def create(**_kwargs):
                    raise _GatewayError()

        from providers.anthropic import AnthropicProvider

        provider = AnthropicProvider(client=_Client())
        with self.assertRaises(ProviderError) as caught:
            provider.generate(_request())
        error = caught.exception
        self.assertEqual("rate_limited", error.failure_kind)
        self.assertEqual(429, error.status_code)
        self.assertEqual(750, error.retry_after_ms)
        # And the loop's own classification agrees with the provider's, by construction.
        self.assertEqual("rate_limited", classify(error).kind)


def _request():
    from providers.base import GenerationRequest

    return GenerationRequest(system="s", messages=(), model="m", max_tokens=16)


class LoopRetryTests(RuntimeTestCase):
    def _policy(self, **kwargs: Any) -> RetryPolicy:
        slept: list[float] = []
        self.slept = slept  # type: ignore[attr-defined]
        return RetryPolicy(base_delay_ms=10, jitter="none", deadline_ms=60_000, sleeper=lambda seconds: slept.append(seconds), **kwargs)

    def test_a_turn_survives_two_rate_limits_and_says_so_on_the_event_stream(self):
        policy = self._policy(max_attempts=4)
        runtime = self.runtime(
            [
                {"raises": _error("too many requests", status=429)},
                {"raises": _error("overloaded_error", status=529)},
                "recovered",
            ],
            retry=policy,
        )
        report = self.drive(runtime)
        self.assertEqual("success", report.result.subtype)
        notes = [event.content for event in report.events if getattr(event, "subtype", "") == "informational"]
        self.assertEqual(2, len(notes))
        self.assertIn("attempt 1/4 failed: rate_limited", notes[0])
        self.assertIn("attempt 2/4 failed: overloaded", notes[1])
        self.assertEqual([0.01, 0.02], self.slept)

    def test_the_recovered_turn_adds_nothing_to_the_transcript(self):
        # A retry is not a fact about the work product. Two runs whose transcripts must be
        # byte-identical: one clean, one that hit 429s on the way to the same answer.
        clean = self.runtime(["same answer"], retry=self._policy(max_attempts=3))
        flaky = self.runtime(
            [{"raises": _error("too many requests", status=429)}, "same answer"],
            retry=self._policy(max_attempts=3),
        )
        record = lambda runtime: [  # noqa: E731
            entry.as_dict() if hasattr(entry, "as_dict") else entry for entry in runtime._pending_state.transcript  # noqa: SLF001
        ]
        self.drive(clean)
        self.drive(flaky)
        self.assertEqual(record(clean), record(flaky))
        self.assertEqual(2, len(record(clean)))

    def test_an_authentication_fault_is_reported_immediately_and_silently(self):
        policy = self._policy(max_attempts=5)
        runtime = self.runtime([{"raises": _error("invalid api key", status=401)}], retry=policy)
        report = self.drive(runtime)
        self.assertEqual("error_during_execution", report.result.subtype)
        self.assertEqual([], self.slept)
        self.assertEqual([], [event for event in report.events if getattr(event, "subtype", "") == "informational"])
        failure = report.errors[-1]
        self.assertIn("invalid api key", failure)
        self.assertNotIn("attempt(s)", failure)

    def test_an_exhausted_budget_names_the_attempts_and_the_wait(self):
        policy = self._policy(max_attempts=3)
        runtime = self.runtime([{"raises": _error("too many requests", status=429)}] * 4, retry=policy)
        report = self.drive(runtime)
        self.assertEqual("error_during_execution", report.result.subtype)
        failure = report.errors[-1]
        self.assertIn("after 3 request(s), 30 ms of policy waiting", failure)
        self.assertEqual([0.01, 0.02], self.slept)

    def test_a_mid_stream_break_is_not_retried_once_text_has_been_shown(self):
        provider_turn = {
            "text": "partial answer",
            "stream": ["partial ", "answer"],
            "raises": _error("connection reset"),
            "stream_fail_after": 2,
        }
        runtime = self.runtime(
            [provider_turn, "would have been a duplicate"],
            stream=True,
            retry=self._policy(max_attempts=4),
        )
        report = self.drive(runtime)
        self.assertEqual("error_during_execution", report.result.subtype)
        self.assertIn("connection reset", report.errors[-1])
        # One request, no sleep, and the second scripted turn never consumed: the run ended
        # where the stream broke rather than showing the same sentence twice.
        self.assertEqual([], self.slept)
        self.assertEqual(1, len(runtime.provider.requests))
        self.assertEqual(1, runtime.provider.cursor)

    def test_a_stream_that_breaks_before_the_first_character_may_be_retried(self):
        runtime = self.runtime(
            [
                {"stream": [], "raises": _error("connection reset"), "stream_fail_after": 0},
                "the second attempt answered",
            ],
            stream=True,
            retry=self._policy(max_attempts=3),
        )
        report = self.drive(runtime)
        self.assertEqual("success", report.result.subtype)
        self.assertIn("second attempt answered", report.final_text)
        self.assertEqual(2, len(runtime.provider.requests))
        self.assertEqual([0.01], self.slept)

    def test_the_overflow_ladder_compacts_once_and_costs_no_retry_budget(self):
        seed = []
        for index in range(6):
            seed.append(UserMessage.text_block("x" * 900 + f" note {index}"))
            seed.append(AssistantMessage(content=("y" * 900 + f" reply {index}",)))
        policy = self._policy(max_attempts=3, on_context_overflow="compact_once")
        runtime = self.runtime([{"raises": _error("prompt is too long: 210000 tokens", status=413)}, "after compaction"], retry=policy, compaction_keep_messages=1)
        report = runtime.run_collect("go", resume=seed)
        self.assertEqual("success", report.result.subtype)
        self.assertIn("compact_boundary", [getattr(event, "subtype", "") for event in report.events])
        self.assertEqual([], self.slept)
        note = [event.content for event in report.events if getattr(event, "subtype", "") == "informational"]
        self.assertIn("costs no retry budget", note[0])

    def test_the_ladder_is_a_choice_and_runs_only_once(self):
        seed = []
        for index in range(6):
            seed.append(UserMessage.text_block("x" * 900 + f" note {index}"))
            seed.append(AssistantMessage(content=("y" * 900 + f" reply {index}",)))
        refused = self.runtime([{"raises": _error("prompt is too long", status=413)}, "unused"], retry=self._policy(max_attempts=3))
        report = refused.run_collect("go", resume=seed)
        self.assertEqual("error_during_execution", report.result.subtype)
        self.assertNotIn("compact_boundary", [getattr(event, "subtype", "") for event in report.events])

        # Two overflows in one run, and only the first may be degraded: a ladder that could
        # be climbed twice is a way to keep shrinking a context until nothing is left of the
        # run's own memory. The tool turn is what keeps the run alive long enough to reach the
        # second fault.
        workspace = self.workspace({"a.txt": "one\ntwo\nthree\n"})
        twice = self.runtime(
            [
                {"raises": _error("prompt is too long", status=413)},
                {"tool": {"name": "Read", "input": {"path": "a.txt"}}},
                {"raises": _error("prompt is too long", status=413)},
                "unused",
            ],
            workspace=workspace,
            retry=self._policy(max_attempts=3, on_context_overflow="compact_once"),
            compaction_keep_messages=1,
            max_turns=5,
        )
        second = twice.run_collect("go", resume=seed)
        self.assertEqual("error_during_execution", second.result.subtype)
        self.assertEqual(1, len([event for event in second.events if getattr(event, "subtype", "") == "compact_boundary"]))
        notes = [event.content for event in second.events if getattr(event, "subtype", "") == "informational"]
        self.assertEqual(2, len(notes))
        self.assertIn("costs no retry budget", notes[0])
        self.assertIn("one compaction is already spent", notes[1])

    def test_a_broken_promise_is_still_a_broken_promise_with_a_policy_attached(self):
        # The shape checks are not retried away: a provider that returns a non-Generation
        # gets one request and an execution error, exactly as it did before retry existed.
        class _Nonsense:
            name = "nonsense"
            streams = False

            def generate(self, _request):
                return "a string"

        runtime = self.runtime(provider=_Nonsense(), retry=self._policy(max_attempts=4))
        report = self.drive(runtime)
        self.assertEqual("error_during_execution", report.result.subtype)
        self.assertIn("instead of a Generation", report.errors[-1])
        self.assertEqual([], self.slept)

    def test_a_non_provider_exception_gets_no_retry(self):
        class _Leaky:
            name = "leaky"
            streams = False

            def generate(self, _request):
                raise TypeError("the provider broke its own contract")

        runtime = self.runtime(provider=_Leaky(), retry=self._policy(max_attempts=4))
        report = self.drive(runtime)
        self.assertEqual("error_during_execution", report.result.subtype)
        self.assertIn("TypeError", report.errors[-1])
        self.assertEqual([], self.slept)

    def test_a_policy_object_of_the_wrong_shape_is_a_configuration_error(self):
        # Validated when the runtime is built, because a dict in a config file and a policy
        # object mean the same thing to a TOML reader and only one of them is enforceable.
        from loop import RuntimeConfigurationError

        with self.assertRaises(RuntimeConfigurationError) as caught:
            self.runtime(["x"], retry={"max_attempts": 2})
        self.assertIn("provider_retry.RetryPolicy", str(caught.exception))

    def test_the_jitter_seed_comes_from_the_run_so_a_replay_repeats_it(self):
        from loop import AgentRuntime, RuntimeConfig

        config = RuntimeConfig(workspace=str(self.workspace()), retry=RetryPolicy(jitter="full"))
        runtime = AgentRuntime(provider=self.provider(["x"]), config=config)
        self.assertIsNotNone(runtime.retry.seed)
        twin = AgentRuntime(provider=self.provider(["x"]), config=RuntimeConfig(workspace=str(self.workspace()), retry=RetryPolicy(jitter="full", seed=runtime.retry.seed)))
        self.assertEqual(runtime.retry.seed, twin.retry.seed)


class CliRetryTests(RuntimeTestCase):
    def _invoke(self, argv: list[str], files: dict[str, str] | None = None):
        """Run the CLI against one workspace that also holds ``files``.

        A single ``workspace()`` call for the on-disk table and for ``--workspace``: asking
        twice hands back a different directory each time, and a test that writes a config file
        into one and runs against the other proves only that the CLI ignores absent files.
        ``{ws}`` is the placeholder the tests put where the path belongs.
        """
        import contextlib
        import io

        from cli import main

        workspace = self.workspace(files)
        argv = [str(workspace) if item == "{ws}" else item for item in argv]
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_dry_run_prints_the_transport_budget(self):
        code, out, _err = self._invoke(["run", "--workspace", "{ws}", "--prompt", "go", "--dry-run"])
        self.assertEqual(0, code)
        self.assertIn("retry=2 additional attempt(s) on rate_limited, overloaded, network, timeout, server_error", out)
        self.assertIn("worst case ", out)

    def test_no_retry_is_shown_as_off(self):
        _code, out, _err = self._invoke(["run", "--workspace", "{ws}", "--prompt", "go", "--dry-run", "--no-retry"])
        self.assertIn("retry=off (max_attempts=1 sends one request per turn)", out)

    def test_a_workspace_table_is_read_and_a_flag_cannot_loosen_it(self):
        table = "[retry]\nmax_attempts = 2\nbase_delay_ms = 4000\nmax_delay_ms = 8000\njitter = \"none\"\n"
        _code, out, _err = self._invoke(
            ["run", "--workspace", "{ws}", "--prompt", "go", "--dry-run", "--retry-max-attempts", "5"],
            files={".northstar/config.toml": table},
        )
        self.assertIn("retry=1 additional attempt(s)", out)
        # Asking past the runtime's own cap is refused rather than rounded: a number outside
        # the supported range is a typo someone should see, not a policy the CLI invented.
        code, _out, err = self._invoke(
            ["run", "--workspace", "{ws}", "--prompt", "go", "--dry-run", "--retry-max-attempts", "99"],
            files={".northstar/config.toml": table},
        )
        self.assertEqual(64, code)
        self.assertIn("between 1 and 8", err)
        self.assertIn("base 4000 ms", out)
        self.assertIn("no jitter", out)

    def test_a_bad_table_or_class_is_a_configuration_error_not_a_warning(self):
        code, _out, err = self._invoke(
            ["run", "--workspace", "{ws}", "--prompt", "go", "--dry-run"],
            files={".northstar/config.toml": "[retry]\nmax_atempts = 3\n"},
        )
        self.assertEqual(64, code)
        self.assertIn("unknown key(s) max_atempts", err)

        code, _out, err = self._invoke(["run", "--workspace", "{ws}", "--prompt", "go", "--dry-run", "--retry-on", "polite"])
        self.assertEqual(64, code)
        self.assertIn("names faults this runtime cannot classify", err)

        code, _out, err = self._invoke(["run", "--workspace", "{ws}", "--prompt", "go", "--dry-run", "--retry-on", "stream_interrupted"])
        self.assertEqual(64, code)
        self.assertIn("may not include stream_interrupted", err)

    def test_retry_knobs_are_documented_where_they_are_used(self):
        import contextlib
        import io

        from cli import main

        out = io.StringIO()
        with contextlib.suppress(SystemExit), contextlib.redirect_stdout(out):
            main(["run", "--help"])
        text = out.getvalue()
        for flag in ("--retry-max-attempts", "--retry-deadline-ms", "--retry-on", "--no-retry"):
            self.assertIn(flag, text)

    def test_a_plugin_bundle_cannot_ask_for_transport_knobs(self):
        # The retry budget is a workspace decision; a bundle that could set it could set the
        # number of requests its own code makes to the provider.
        import plugin_manifest

        self.assertNotIn("retry", plugin_manifest.ALLOWED_POLICY_KEYS)



class ScriptedFaultTests(unittest.TestCase):
    """A JSON script can carry a transport fault, which is what makes this whole module
    demonstrable with no key and no network - the rule the component is built on."""

    def test_a_script_turn_can_raise_a_classified_fault(self):
        from providers.scripted import ScriptedProvider

        provider = ScriptedProvider([{"raises": {"status": 429, "message": "too many requests", "retry_after_ms": 300}}, "answered"])
        with self.assertRaises(ProviderError) as caught:
            provider.generate(_request())
        self.assertEqual(429, caught.exception.status_code)
        self.assertEqual("rate_limited", caught.exception.failure_kind)
        self.assertEqual(300, caught.exception.retry_after_ms)
        self.assertEqual("answered", provider.generate(_request()).text())

    def test_an_unknown_fault_key_is_refused_at_script_build_time(self):
        # A script that silently failed to produce its fault would test the wrong thing.
        from providers.scripted import ScriptedProvider

        with self.assertRaises(ProviderError) as caught:
            ScriptedProvider([{"raises": {"status_code": 429}}])
        self.assertIn("unknown key(s) status_code", str(caught.exception))

    def test_a_malformed_fault_is_refused_not_defaulted(self):
        from providers.scripted import ScriptedProvider

        for bad in ({"status": True}, {"retry_after_ms": -1}, {"retry_after_ms": "soon"}):
            with self.subTest(bad=bad):
                with self.assertRaises(ProviderError):
                    ScriptedProvider([{"raises": bad}])


class CliRetryRehearsalTests(RuntimeTestCase):
    """The scripted provider plus a `[retry]` table: the whole feature, demonstrated offline."""

    TABLE = chr(10).join(
        ("[retry]", "max_attempts = 4", "base_delay_ms = 5", "max_delay_ms = 50", "deadline_ms = 500", 'jitter = "none"', "")
    )

    def _run(self, files, extra=()):
        import contextlib
        import io

        from cli import main

        # `--script` is a path the *operator* chose, so the CLI resolves it against the
        # process cwd like any other file argument, and this test spells it out absolutely.
        workspace = self.workspace(files)
        argv = [
            "run",
            "--workspace",
            str(workspace),
            "--script",
            str(workspace / "plan.json"),
            "--prompt",
            "draft the release notes",
        ]
        argv += [item.replace("{ws}", str(workspace)) for item in extra]
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_the_scripted_cli_retries_a_429_and_says_so(self):
        script = json.dumps(
            [
                {"raises": {"status": 429, "message": "too many requests", "retry_after_ms": 20}},
                {"raises": {"status": 529, "message": "overloaded_error"}},
                {"text": "the release notes are drafted"},
            ]
        )
        code, printed, err = self._run({"plan.json": script, ".northstar/config.toml": self.TABLE})
        self.assertEqual(0, code, printed + err)
        # Each retry narrates itself as it happens, in the order the waits were paid: the
        # first delay is the provider's 20 ms (it is longer than our 5 ms base, and we obey
        # a request to wait), the second is our own schedule doubling to 10 ms.
        self.assertIn("attempt 1/4 failed: rate_limited (too many requests) - retrying in 20 ms", printed)
        self.assertIn("attempt 2/4 failed: overloaded (overloaded_error) - retrying in 10 ms", printed)
        self.assertIn("the release notes are drafted", printed)

    def test_no_retry_turns_the_same_script_into_an_immediate_failure(self):
        script = json.dumps([{"raises": {"status": 429, "message": "too many requests"}}, "unused"])
        code, printed, err = self._run(
            {"plan.json": script, ".northstar/config.toml": self.TABLE},
            extra=["--no-retry", "--session-dir", "{ws}/sessions"],
        )
        self.assertEqual(1, code)
        combined = printed + err
        self.assertIn("provider failure on turn 1", combined)
        self.assertNotIn("retrying in", combined)
        # And the failure line says the budget was skipped, not that it was spent.
        self.assertNotIn("policy waiting", combined)

    def test_a_run_that_gives_up_reports_the_requests_it_sent(self):
        script = json.dumps([{"raises": {"status": 429, "message": "too many requests"}}] * 4)
        code, printed, err = self._run({"plan.json": script, ".northstar/config.toml": self.TABLE})
        self.assertEqual(1, code)
        self.assertIn("after 4 request(s), 35 ms of policy waiting", printed + err)

if __name__ == "__main__":  # pragma: no cover
    unittest.main()
