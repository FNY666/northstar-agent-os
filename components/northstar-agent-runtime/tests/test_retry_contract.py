"""The retry/idempotency contract: the classification matrix, end to end.

Every rule transcribed from E2B's ``packages/js-sdk/src/retry.ts`` and
``errors.ts`` has a test here. The matrix is the point: a retry contract is
only as good as the cases it refuses to retry.
"""
from __future__ import annotations

import errno
import socket
import ssl
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from retry_contract import (  # noqa: E402
    DEFAULT_RETRY_CONFIG,
    Failure,
    FailureClass,
    FailurePhase,
    IdempotencyKeyError,
    IdempotencyMismatchError,
    IndeterminateError,
    Operation,
    RetryContract,
    RetryContractConfig,
    RetryContractError,
    TargetGoneError,
    TargetUnreachableError,
    assert_same_operation,
    classify_exception,
    classify_http_result,
    classify_response,
    operation_replay_safe,
    resolve_idempotency_key,
)


class ShouldRetryHeaderTests(unittest.TestCase):
    """E2B: a present ``Should-Retry`` header is authoritative."""

    def test_should_retry_true_is_retryable(self):
        failure = classify_response(500, {"Should-Retry": "true"})
        self.assertIs(failure.classification, FailureClass.RETRYABLE)

    def test_should_retry_false_is_not_retryable_even_on_a_retryable_status(self):
        for status in (429, 502, 503, 504):
            with self.subTest(status=status):
                failure = classify_response(status, {"Should-Retry": "false"})
                self.assertIs(failure.classification, FailureClass.NON_RETRYABLE)

    def test_should_retry_absent_falls_back_to_the_status_matrix(self):
        for status in (429, 502, 503, 504):
            with self.subTest(status=status):
                self.assertIs(classify_response(status).classification, FailureClass.RETRYABLE)

    def test_should_retry_absent_on_a_non_retryable_status_is_not_retryable(self):
        for status in (200, 400, 401, 403, 404, 418, 500, 501):
            with self.subTest(status=status):
                self.assertIs(classify_response(status).classification, FailureClass.NON_RETRYABLE)

    def test_the_header_is_read_case_insensitively_on_name_and_value(self):
        for headers in ({"should-retry": "true"}, {"SHOULD-RETRY": "TRUE"}, {"Should-Retry": " True "}):
            with self.subTest(headers=headers):
                self.assertIs(classify_response(500, headers).classification, FailureClass.RETRYABLE)

    def test_an_empty_header_is_present_and_therefore_authoritative(self):
        # Present-but-empty is not "absent": it is a present header whose
        # value is not "true", so it forbids the retry.
        failure = classify_response(503, {"Should-Retry": ""})
        self.assertIs(failure.classification, FailureClass.NON_RETRYABLE)


class StatusClassificationTests(unittest.TestCase):
    def test_the_four_retryable_statuses_are_retryable(self):
        for status in (429, 502, 503, 504):
            with self.subTest(status=status):
                self.assertIs(classify_response(status).classification, FailureClass.RETRYABLE)

    def test_other_server_errors_are_not_retryable(self):
        for status in (500, 501, 505, 507):
            with self.subTest(status=status):
                self.assertIs(classify_response(status).classification, FailureClass.NON_RETRYABLE)

    def test_a_gone_status_is_a_confirmed_absent_answer(self):
        for status in (404, 410):
            with self.subTest(status=status):
                failure = classify_response(status)
                self.assertIs(failure.classification, FailureClass.NON_RETRYABLE)
                self.assertIn("confirmed absent", failure.reason)

    def test_classify_http_result_returns_none_for_success(self):
        for status in (200, 201, 204, 299):
            with self.subTest(status=status):
                self.assertIsNone(classify_http_result(status))


class TransportFailureTests(unittest.TestCase):
    """E2B: ``isRetryableFetchError`` -- only connect-phase failures retry."""

    def test_a_connection_refused_is_retryable(self):
        failure = classify_exception(ConnectionRefusedError("refused"))
        self.assertIs(failure.classification, FailureClass.RETRYABLE)
        self.assertIs(failure.phase, FailurePhase.PRE_WRITE)

    def test_a_name_resolution_failure_is_retryable(self):
        failure = classify_exception(socket.gaierror("no such host"))
        self.assertIs(failure.classification, FailureClass.RETRYABLE)

    def test_a_connect_timeout_is_retryable(self):
        failure = classify_exception(socket.timeout("timed out"))
        self.assertIs(failure.classification, FailureClass.RETRYABLE)

    def test_a_connection_reset_is_never_retried(self):
        failure = classify_exception(ConnectionResetError("reset by peer"))
        self.assertIs(failure.classification, FailureClass.NON_RETRYABLE)
        self.assertIs(failure.phase, FailurePhase.POST_WRITE)
        self.assertTrue(failure.may_have_executed)

    def test_an_errno_connection_reset_is_never_retried(self):
        error = OSError(errno.ECONNRESET, "connection reset by peer")
        failure = classify_exception(error)
        self.assertIs(failure.classification, FailureClass.NON_RETRYABLE)
        self.assertTrue(failure.may_have_executed)

    def test_an_unrecognised_transport_error_is_unknown_not_retryable(self):
        failure = classify_exception(OSError("something else entirely"))
        self.assertIs(failure.classification, FailureClass.UNKNOWN)
        self.assertFalse(failure.retryable)

    def test_a_tls_handshake_failure_is_definitively_not_retryable(self):
        # The handshake failed before any request byte was written, so the
        # operation certainly did not run -- and a retry cannot fix a
        # rejected certificate.
        failure = classify_exception(ssl.SSLError("handshake failure"))
        self.assertIs(failure.classification, FailureClass.NON_RETRYABLE)
        self.assertIs(failure.phase, FailurePhase.PRE_WRITE)
        self.assertFalse(failure.may_have_executed)

    def test_an_indeterminate_error_is_post_write_and_never_retried(self):
        failure = classify_exception(IndeterminateError("response cut short"))
        self.assertIs(failure.classification, FailureClass.NON_RETRYABLE)
        self.assertIs(failure.phase, FailurePhase.POST_WRITE)
        self.assertTrue(failure.may_have_executed)


class IdempotencyKeyTests(unittest.TestCase):
    """E2B: ``resolveIdempotencyKey`` -- ``^[a-z0-9-]{1,255}$``."""

    def test_a_valid_key_is_accepted(self):
        for key in ("a", "abc-123", "0", "call-1", "a" * 255):
            with self.subTest(key=key[:16]):
                self.assertEqual(resolve_idempotency_key(key), key)

    def test_none_means_no_key(self):
        self.assertIsNone(resolve_idempotency_key(None))

    def test_an_invalid_key_is_refused(self):
        for key in ("", "A", "Call-1", "call_1", "call 1", "call.1", "a" * 256, "call\n"):
            with self.subTest(key=key[:16]):
                with self.assertRaises(IdempotencyKeyError):
                    resolve_idempotency_key(key)

    def test_a_non_string_key_is_refused(self):
        with self.assertRaises(IdempotencyKeyError):
            resolve_idempotency_key(123)  # type: ignore[arg-type]


class ReplaySafetyTests(unittest.TestCase):
    def test_an_idempotent_method_is_replay_safe_without_a_key(self):
        for method in ("GET", "HEAD", "OPTIONS", "DELETE"):
            with self.subTest(method=method):
                self.assertTrue(operation_replay_safe(method, None))

    def test_a_non_idempotent_method_needs_a_key_to_be_replay_safe(self):
        self.assertFalse(operation_replay_safe("POST", None))
        self.assertTrue(operation_replay_safe("POST", "call-1"))

    def test_a_streamed_body_is_never_replay_safe(self):
        operation = Operation(method="GET", payload_digest="d", body_replayable=False)
        self.assertFalse(operation.replay_safe)

    def test_a_non_replayable_operation_reports_it(self):
        operation = Operation(method="POST", payload_digest="d", replayable=False)
        self.assertFalse(operation.replay_safe)

    def test_the_same_operation_needs_the_same_key_and_digest(self):
        first = Operation(method="POST", payload_digest="d1", idempotency_key="k1")
        same = Operation(method="POST", payload_digest="d1", idempotency_key="k1")
        other_digest = Operation(method="POST", payload_digest="d2", idempotency_key="k1")
        other_key = Operation(method="POST", payload_digest="d1", idempotency_key="k2")
        self.assertTrue(first.same_operation(same))
        self.assertFalse(first.same_operation(other_digest))
        self.assertFalse(first.same_operation(other_key))

    def test_assert_same_operation_refuses_a_changed_key_or_digest(self):
        first = Operation(method="POST", payload_digest="d1", idempotency_key="k1")
        with self.assertRaises(IdempotencyMismatchError):
            assert_same_operation(first, Operation(method="POST", payload_digest="d1", idempotency_key="k2"))
        with self.assertRaises(IdempotencyMismatchError):
            assert_same_operation(first, Operation(method="POST", payload_digest="d2", idempotency_key="k1"))
        with self.assertRaises(IdempotencyMismatchError):
            assert_same_operation(first, Operation(method="PUT", payload_digest="d1", idempotency_key="k1"))


class ConfigTests(unittest.TestCase):
    def test_the_defaults_are_bounded_and_sane(self):
        config = DEFAULT_RETRY_CONFIG
        self.assertEqual(config.max_retries, 2)
        self.assertEqual(config.initial_wait_ms, 100)
        self.assertEqual(config.max_wait_ms, 10_000)
        self.assertEqual(config.exponential_base, 2.0)
        self.assertEqual(config.jitter, 0.5)

    def test_an_out_of_range_configuration_is_refused(self):
        for kwargs in (
            {"max_retries": -1},
            {"max_retries": 1.5},
            {"initial_wait_ms": -1},
            {"max_wait_ms": -1},
            {"max_wait_ms": 10, "initial_wait_ms": 100},
            {"exponential_base": 0.5},
            {"jitter": -0.1},
            {"jitter": 1.5},
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(RetryContractError):
                    RetryContractConfig(**kwargs)

    def test_the_delay_grows_exponentially_and_is_capped(self):
        config = RetryContractConfig(initial_wait_ms=100, max_wait_ms=1000, exponential_base=2.0, jitter=0.0)
        delays = [config.delay_ms(attempt, lambda: 0.5) for attempt in (1, 2, 3, 4)]
        self.assertEqual(delays, [100, 200, 400, 800])

    def test_the_jitter_bounds_the_delay(self):
        config = RetryContractConfig(initial_wait_ms=100, max_wait_ms=10_000, jitter=0.5)
        low = config.delay_ms(1, lambda: 0.0)
        high = config.delay_ms(1, lambda: 1.0)
        self.assertEqual(low, 50)
        self.assertEqual(high, 100)


class ExecutorTests(unittest.TestCase):
    """The contract applied to a real call sequence."""

    def _contract(self, **kwargs):
        self.slept: list[float] = []
        return RetryContract(sleep=self.slept.append, random=lambda: 0.5, **kwargs)

    def test_a_retryable_status_is_actually_retried(self):
        calls: list[int] = []

        def _call(_operation):
            calls.append(1)
            return 503 if len(calls) == 1 else 200

        contract = self._contract()
        operation = Operation(method="GET", payload_digest="d")
        outcome = contract.execute(operation, _call, classify=classify_http_result)
        self.assertTrue(outcome.ok)
        self.assertEqual(len(calls), 2)
        self.assertEqual(outcome.attempts_made, 2)

    def test_a_retryable_status_is_retried_until_the_budget_is_spent(self):
        calls: list[int] = []

        def _call(_operation):
            calls.append(1)
            return 503

        contract = self._contract(config=RetryContractConfig(max_retries=2, jitter=0.0))
        outcome = contract.execute(
            Operation(method="GET", payload_digest="d"), _call, classify=classify_http_result
        )
        self.assertFalse(outcome.ok)
        # One initial attempt plus two retries.
        self.assertEqual(len(calls), 3)
        self.assertIs(outcome.failure.classification, FailureClass.RETRYABLE)

    def test_a_connection_reset_is_never_retried(self):
        calls: list[int] = []

        def _call(_operation):
            calls.append(1)
            raise ConnectionResetError("reset by peer")

        contract = self._contract()
        outcome = contract.execute(Operation(method="GET", payload_digest="d"), _call)
        self.assertEqual(len(calls), 1)
        self.assertFalse(outcome.ok)
        self.assertTrue(outcome.may_have_executed)

    def test_an_explicit_should_retry_false_is_never_retried(self):
        calls: list[int] = []

        def _call(_operation):
            calls.append(1)
            return (503, {"Should-Retry": "false"}, b"", False)

        contract = self._contract()
        outcome = contract.execute(
            Operation(method="GET", payload_digest="d"),
            _call,
            classify=lambda result: classify_http_result(result[0], result[1]),
        )
        self.assertEqual(len(calls), 1)
        self.assertFalse(outcome.ok)
        self.assertIs(outcome.failure.classification, FailureClass.NON_RETRYABLE)

    def test_a_connection_refusal_is_retried(self):
        calls: list[int] = []

        def _call(_operation):
            calls.append(1)
            if len(calls) < 3:
                raise ConnectionRefusedError("refused")
            return 200

        contract = self._contract()
        outcome = contract.execute(
            Operation(method="GET", payload_digest="d"), _call, classify=classify_http_result
        )
        self.assertTrue(outcome.ok)
        self.assertEqual(len(calls), 3)

    def test_a_non_idempotent_operation_without_a_key_is_not_retried(self):
        calls: list[int] = []

        def _call(_operation):
            calls.append(1)
            return 503

        contract = self._contract()
        outcome = contract.execute(
            Operation(method="POST", payload_digest="d"), _call, classify=classify_http_result
        )
        self.assertEqual(len(calls), 1)
        self.assertFalse(outcome.ok)

    def test_a_non_idempotent_operation_with_a_key_is_retried(self):
        calls: list[int] = []

        def _call(_operation):
            calls.append(1)
            return 503 if len(calls) == 1 else 200

        contract = self._contract()
        outcome = contract.execute(
            Operation(method="POST", payload_digest="d", idempotency_key="call-1"),
            _call,
            classify=classify_http_result,
        )
        self.assertTrue(outcome.ok)
        self.assertEqual(len(calls), 2)

    def test_a_streamed_body_gets_exactly_one_attempt(self):
        calls: list[int] = []

        def _call(_operation):
            calls.append(1)
            return 503

        contract = self._contract()
        outcome = contract.execute(
            Operation(method="POST", payload_digest="d", idempotency_key="call-1", body_replayable=False),
            _call,
            classify=classify_http_result,
        )
        self.assertEqual(len(calls), 1)
        self.assertFalse(outcome.ok)

    def test_every_retry_carries_the_same_idempotency_key(self):
        seen: list[str | None] = []

        def _call(operation):
            seen.append(operation.idempotency_key)
            return 503 if len(seen) == 1 else 200

        contract = self._contract()
        contract.execute(
            Operation(method="POST", payload_digest="d", idempotency_key="call-1"),
            _call,
            classify=classify_http_result,
        )
        self.assertEqual(seen, ["call-1", "call-1"])

    def test_an_unknown_outcome_is_neither_retried_nor_reported_as_success(self):
        calls: list[int] = []

        def _call(_operation):
            calls.append(1)
            raise IndeterminateError("the response was cut short")

        contract = self._contract()
        outcome = contract.execute(Operation(method="GET", payload_digest="d"), _call)
        self.assertEqual(len(calls), 1)
        self.assertFalse(outcome.ok)
        self.assertIs(outcome.failure.classification, FailureClass.NON_RETRYABLE)
        self.assertIs(outcome.failure.phase, FailurePhase.POST_WRITE)
        self.assertTrue(outcome.may_have_executed)

    def test_the_backoff_sleeps_between_attempts(self):
        contract = self._contract(config=RetryContractConfig(max_retries=2, jitter=0.0))
        calls: list[int] = []

        def _call(_operation):
            calls.append(1)
            return 503

        contract.execute(Operation(method="GET", payload_digest="d"), _call, classify=classify_http_result)
        self.assertEqual(self.slept, [100, 200])


class DeadVersusUnknownTests(unittest.TestCase):
    """E2B: a confirmed-gone target and an unreachable one are different."""

    def test_a_gone_target_raises_the_gone_error(self):
        contract = RetryContract(sleep=lambda _ms: None)

        def _call(_operation):
            return 404

        with self.assertRaises(TargetGoneError):
            contract.execute_strict(Operation(method="GET", payload_digest="d"), _call, classify=classify_http_result)

    def test_an_unreachable_target_raises_the_unreachable_error(self):
        contract = RetryContract(sleep=lambda _ms: None)

        def _call(_operation):
            raise IndeterminateError("the connection was lost")

        with self.assertRaises(TargetUnreachableError):
            contract.execute_strict(Operation(method="GET", payload_digest="d"), _call)

    def test_the_two_errors_are_distinct_types(self):
        self.assertFalse(issubclass(TargetGoneError, TargetUnreachableError))
        self.assertFalse(issubclass(TargetUnreachableError, TargetGoneError))

    def test_a_gone_target_is_not_reported_as_may_have_executed(self):
        contract = RetryContract(sleep=lambda _ms: None)

        def _call(_operation):
            return 404

        with self.assertRaises(TargetGoneError) as caught:
            contract.execute_strict(Operation(method="GET", payload_digest="d"), _call, classify=classify_http_result)
        self.assertFalse(caught.exception.may_have_executed)

    def test_an_unreachable_target_says_it_may_have_executed(self):
        contract = RetryContract(sleep=lambda _ms: None)

        def _call(_operation):
            raise IndeterminateError("the connection was lost")

        with self.assertRaises(TargetUnreachableError) as caught:
            contract.execute_strict(Operation(method="GET", payload_digest="d"), _call)
        self.assertTrue(caught.exception.may_have_executed)
