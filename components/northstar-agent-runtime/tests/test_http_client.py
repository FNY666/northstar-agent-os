"""Tests for the simulated HTTP client (retry + timeout discipline)."""

import unittest

from http_client import (
    HTTP_CLIENT_SCHEMA,
    HTTP_CLIENT_VERSION,
    Backoff,
    HTTPRetryExhausted,
    HTTPRetryPolicy,
    HTTPClient,
    HTTPClientError,
    HTTPMethod,
    HTTPRequest,
    HTTPResponse,
    HTTPStatusError,
    HTTPTimeoutError,
    InvalidRequestError,
    RequestReport,
    TransportError,
    TransportResult,
    http_client_audit_event,
)


def _ok(body=b"", latency_ms=1, status=200):
    def transport(_req, _seq):
        return TransportResult(status=status, headers=(), body=body, latency_ms=latency_ms)

    return transport


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(HTTP_CLIENT_VERSION, "http-client.v1")

    def test_schema_pin(self):
        self.assertEqual(HTTP_CLIENT_SCHEMA, "northstar.http-client.v1")


class TestRequestValidation(unittest.TestCase):
    def test_bad_scheme_refused(self):
        client = HTTPClient()
        with self.assertRaises(InvalidRequestError):
            client.get("ftp://example.com/x", seq=0, sleeper=lambda s: None)

    def test_missing_scheme_refused(self):
        client = HTTPClient()
        with self.assertRaises(InvalidRequestError):
            client.get("example.com/x", seq=0, sleeper=lambda s: None)

    def test_empty_host_refused(self):
        client = HTTPClient()
        with self.assertRaises(InvalidRequestError):
            client.get("https:///path", seq=0, sleeper=lambda s: None)

    def test_userinfo_refused(self):
        client = HTTPClient()
        with self.assertRaises(InvalidRequestError):
            client.get("https://user:pass@example.com/", seq=0,
                       sleeper=lambda s: None)

    def test_whitespace_url_refused(self):
        client = HTTPClient()
        with self.assertRaises(InvalidRequestError):
            client.get("https://example.com/a b", seq=0, sleeper=lambda s: None)

    def test_non_str_url_refused(self):
        client = HTTPClient()
        with self.assertRaises(InvalidRequestError):
            client.get(123, seq=0, sleeper=lambda s: None)  # type: ignore

    def test_bool_seq_refused(self):
        client = HTTPClient()
        with self.assertRaises(TypeError):
            client.get("https://example.com/", seq=True, sleeper=lambda s: None)

    def test_negative_seq_refused(self):
        client = HTTPClient()
        with self.assertRaises(ValueError):
            client.get("https://example.com/", seq=-1, sleeper=lambda s: None)

    def test_bad_header_value_refused(self):
        client = HTTPClient()
        with self.assertRaises(InvalidRequestError):
            client.get("https://example.com/", headers={"X": 5}, seq=0,
                       sleeper=lambda s: None)

    def test_bad_body_type_refused(self):
        client = HTTPClient()
        with self.assertRaises(InvalidRequestError):
            client.post("https://example.com/", body=object(), seq=0,
                        sleeper=lambda s: None)

    def test_oversize_body_refused_before_transport(self):
        calls = []

        def transport(req, seq):
            calls.append(req)
            return TransportResult(status=200, headers=(), body=b"", latency_ms=0)

        client = HTTPClient(transport=transport, max_body_bytes=4)
        with self.assertRaises(InvalidRequestError):
            client.post("https://example.com/", body=b"12345", seq=0,
                        sleeper=lambda s: None)
        self.assertEqual(calls, [])


class TestMethods(unittest.TestCase):
    def test_get_happy_path(self):
        client = HTTPClient(transport=_ok(body=b"hello"))
        resp = client.get("https://example.com/", seq=0, sleeper=lambda s: None)
        self.assertEqual(resp.status, 200)
        self.assertTrue(resp.is_success())
        self.assertEqual(resp.request_method, "GET")
        self.assertTrue(resp.digest.startswith("sha256:"))
        self.assertTrue(resp.body_digest.startswith("sha256:"))

    def test_post_pins_body(self):
        client = HTTPClient(transport=_ok())
        resp = client.post("https://example.com/items", body=b'{"a":1}',
                           headers={"Content-Type": "application/json"},
                           seq=1, sleeper=lambda s: None)
        self.assertEqual(resp.request_method, "POST")
        self.assertTrue(resp.body_digest.startswith("sha256:"))
        self.assertEqual(resp.body_length, 0)  # canned response body

    def test_put_delete_head_patch(self):
        client = HTTPClient(transport=_ok())
        for call in (
            lambda: client.put("https://example.com/a", body=b"x", seq=0,
                               sleeper=lambda s: None),
            lambda: client.delete("https://example.com/a", seq=0,
                                   sleeper=lambda s: None),
            lambda: client.head("https://example.com/a", seq=0,
                                 sleeper=lambda s: None),
            lambda: client.patch("https://example.com/a", body=b"x", seq=0,
                                  sleeper=lambda s: None),
        ):
            resp = call()
            self.assertEqual(resp.status, 200)

    def test_request_digest_determinism(self):
        r1 = HTTPRequest.build(HTTPMethod.GET, "https://example.com/",
                               {"B": "2", "A": "1"}, b"", 0)
        r2 = HTTPRequest.build(HTTPMethod.GET, "https://example.com/",
                               {"A": "1", "B": "2"}, b"", 0)
        self.assertEqual(r1.digest, r2.digest)  # header order normalized
        r3 = HTTPRequest.build(HTTPMethod.POST, "https://example.com/",
                               {"A": "1", "B": "2"}, b"", 0)
        self.assertNotEqual(r1.digest, r3.digest)  # method is in the pin

    def test_records_frozen(self):
        client = HTTPClient(transport=_ok())
        resp = client.get("https://example.com/", seq=0, sleeper=lambda s: None)
        with self.assertRaises(AttributeError):
            resp.status = 500  # type: ignore


class TestRetryDiscipline(unittest.TestCase):
    def test_retry_on_503_then_success(self):
        calls = {"n": 0}

        def flaky(req, seq):
            calls["n"] += 1
            if calls["n"] < 3:
                return TransportResult(status=503, headers=(), body=b"", latency_ms=1)
            return TransportResult(status=200, headers=(), body=b"ok", latency_ms=1)

        sleeps = []
        client = HTTPClient(
            transport=flaky,
            retry_policy=HTTPRetryPolicy(
                max_attempts=3, backoff=Backoff.CONSTANT, base_delay_ms=50
            ),
        )
        resp = client.get("https://example.com/", seq=0, sleeper=sleeps.append)
        self.assertEqual(resp.status, 200)
        self.assertEqual(calls["n"], 3)
        self.assertEqual(sleeps, [0.05, 0.05])  # computed, never slept

    def test_non_retryable_404_fails_fast(self):
        calls = {"n": 0}
        client = HTTPClient(transport=_ok(status=404))
        with self.assertRaises(HTTPStatusError) as ctx:
            client.get("https://example.com/", seq=0, sleeper=lambda s: None)
        self.assertEqual(ctx.exception.response.status, 404)
        self.assertEqual(client.requests_made(), 1)

    def test_exhaustion_carries_report(self):
        client = HTTPClient(
            transport=_ok(status=503),
            retry_policy=HTTPRetryPolicy(max_attempts=2),
        )
        with self.assertRaises(HTTPRetryExhausted) as ctx:
            client.get("https://example.com/", seq=7, sleeper=lambda s: None)
        report = ctx.exception.report
        self.assertIsInstance(report, RequestReport)
        self.assertEqual(report.attempts_made, 2)
        self.assertFalse(report.succeeded)
        self.assertEqual(report.final_status, 503)
        self.assertIsNotNone(ctx.exception.__cause__)

    def test_max_attempts_one_means_no_retry(self):
        calls = {"n": 0}

        def flaky(req, seq):
            calls["n"] += 1
            return TransportResult(status=503, headers=(), body=b"", latency_ms=1)

        client = HTTPClient(
            transport=flaky,
            retry_policy=HTTPRetryPolicy(max_attempts=1),
        )
        with self.assertRaises(HTTPRetryExhausted):
            client.get("https://example.com/", seq=0, sleeper=lambda s: None)
        self.assertEqual(calls["n"], 1)

    def test_transport_exception_is_retryable(self):
        calls = {"n": 0}

        def boom(req, seq):
            calls["n"] += 1
            if calls["n"] == 1:
                raise ConnectionError("dial failed")
            return TransportResult(status=200, headers=(), body=b"", latency_ms=1)

        client = HTTPClient(transport=boom)
        resp = client.get("https://example.com/", seq=0, sleeper=lambda s: None)
        self.assertEqual(resp.status, 200)
        self.assertEqual(calls["n"], 2)

    def test_timeout_exceeded_is_retryable(self):
        calls = {"n": 0}

        def slow(req, seq):
            calls["n"] += 1
            return TransportResult(status=200, headers=(), body=b"",
                                   latency_ms=10_000)

        client = HTTPClient(
            transport=slow,
            timeout_ms=100,
            retry_policy=HTTPRetryPolicy(max_attempts=2),
        )
        with self.assertRaises(HTTPRetryExhausted) as ctx:
            client.get("https://example.com/", seq=0, sleeper=lambda s: None)
        self.assertEqual(calls["n"], 2)
        self.assertIsInstance(ctx.exception.last_error, HTTPTimeoutError)


class TestPolicy(unittest.TestCase):
    def test_retry_policy_accessor(self):
        policy = HTTPRetryPolicy(max_attempts=5, backoff=Backoff.LINEAR,
                                 base_delay_ms=10, max_delay_ms=100)
        client = HTTPClient(retry_policy=policy)
        self.assertIs(client.retry_policy(), policy)

    def test_default_policy(self):
        client = HTTPClient()
        policy = client.retry_policy()
        self.assertEqual(policy.max_attempts, 3)
        self.assertEqual(policy.backoff, Backoff.EXPONENTIAL)

    def test_backoff_exact_values(self):
        policy = HTTPRetryPolicy(base_delay_ms=100, max_delay_ms=10_000,
                                 backoff=Backoff.EXPONENTIAL)
        self.assertEqual(policy.delay_ms(1), 100)
        self.assertEqual(policy.delay_ms(2), 200)
        self.assertEqual(policy.delay_ms(3), 400)
        linear = HTTPRetryPolicy(base_delay_ms=100, max_delay_ms=10_000,
                                 backoff=Backoff.LINEAR)
        self.assertEqual(linear.delay_ms(3), 300)
        const = HTTPRetryPolicy(base_delay_ms=100, max_delay_ms=10_000,
                                backoff=Backoff.CONSTANT)
        self.assertEqual(const.delay_ms(3), 100)

    def test_backoff_capped(self):
        policy = HTTPRetryPolicy(base_delay_ms=1000, max_delay_ms=1500,
                                 backoff=Backoff.EXPONENTIAL)
        self.assertEqual(policy.delay_ms(10), 1500)

    def test_bad_policy_rejected(self):
        with self.assertRaises(ValueError):
            HTTPRetryPolicy(max_attempts=0)
        with self.assertRaises(ValueError):
            HTTPRetryPolicy(max_attempts=33)
        with self.assertRaises(TypeError):
            HTTPRetryPolicy(backoff="fast")  # type: ignore

    def test_retryable_status_classification(self):
        policy = HTTPRetryPolicy()
        self.assertTrue(policy.is_retryable_status(503))
        self.assertTrue(policy.is_retryable_status(429))
        self.assertFalse(policy.is_retryable_status(404))
        self.assertFalse(policy.is_retryable_status(200))


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        client = HTTPClient(transport=_ok(body=b"secret-bytes"))
        req = HTTPRequest.build(HTTPMethod.GET, "https://example.com/",
                                {}, b"", 0)
        resp = client.get("https://example.com/", seq=0, sleeper=lambda s: None)
        event = http_client_audit_event("responded", 1, request=req,
                                        response=resp)
        self.assertEqual(event["event"], "http-client-responded")
        self.assertEqual(event["audit_seq"], 1)
        self.assertEqual(event["schema"], HTTP_CLIENT_SCHEMA)
        # Raw body bytes must never appear in the audit record.
        blob = str(event)
        self.assertNotIn("secret-bytes", blob)
        self.assertIn("sha256:", event["body_digest"])

    def test_bad_kind_refused(self):
        with self.assertRaises(ValueError):
            http_client_audit_event("nonsense", 0)

    def test_bad_seq_refused(self):
        with self.assertRaises(TypeError):
            http_client_audit_event("requested", True)


class TestStdlibOnly(unittest.TestCase):
    def test_stdlib_only(self):
        import ast
        from pathlib import Path

        tree = ast.parse(
            (Path(__file__).resolve().parent.parent / "http_client.py").read_text()
        )
        stdlib = {
            "__future__", "hashlib", "json", "threading", "time",
            "dataclasses", "enum", "typing",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(alias.name.split(".")[0], stdlib)
            elif isinstance(node, ast.ImportFrom) and node.module:
                self.assertIn(node.module.split(".")[0], stdlib)


class TestMain(unittest.TestCase):
    def test_main_self_check(self):
        import http_client

        http_client.main()  # must not raise


if __name__ == "__main__":
    unittest.main()
