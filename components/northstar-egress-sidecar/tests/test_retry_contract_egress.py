"""The retry/idempotency contract, wired onto the egress sidecar's real call.

These are end-to-end tests over the sidecar's *actual* outbound HTTP path:
a live server on a loopback port, a real policy, a real socket, and the
contract deciding whether the request is repeated. Nothing here is a mock of
the sidecar's own transport.

The invariant under test: the sidecar repeats a request only when the
contract says the repeat is safe, and it never repeats one that may already
have landed.
"""
from __future__ import annotations

import base64
import os
import socket
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

SIDECAR_DIR = Path(__file__).resolve().parent.parent
if str(SIDECAR_DIR) not in sys.path:
    sys.path.insert(0, str(SIDECAR_DIR))
os.environ.setdefault(
    "NORTHSTAR_RUNTIME_DIR", str(SIDECAR_DIR.parent / "northstar-agent-runtime")
)
if os.environ["NORTHSTAR_RUNTIME_DIR"] not in sys.path:
    sys.path.insert(0, os.environ["NORTHSTAR_RUNTIME_DIR"])

from egress_sidecar import build_context, run_one  # noqa: E402
import egress_sidecar  # noqa: E402
from retry_contract import (  # noqa: E402
    FailureClass,
    IdempotencyKeyError,
    resolve_idempotency_key,
)
import retry_contract_egress  # noqa: E402

POLICY_TOML = """\
schema_version = "northstar.egress.v1"
revision = "test.retry"

[destinations.local]
hosts = ["svc.local"]
ports = [18095, 18096, 18097, 18098, 18099, 18100, 18101, 18102]
methods = ["POST", "GET"]
path_prefixes = ["/api"]
allow_private_ips = true
tls = false
"""

#: Ports the policy allows. Each test takes its own, so a server left over
#: from an earlier test can never answer a later test's request.
FLAKY_PORT = 18095
RETRY_NO_KEY_PORT = 18096
RETRY_KEY_PORT = 18097
SAME_KEY_PORT = 18098
BAD_KEY_PORT = 18099
GONE_PORT = 18100
CUT_SHORT_PORT = 18101
DEAD_PORT = 18102


class _Counter:
    """A thread-safe counter of what the upstream server saw."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.requests: list[dict[str, str]] = []

    def record(self, entry: dict[str, str]) -> int:
        with self.lock:
            self.requests.append(entry)
            return len(self.requests)


def _make_handler(counter: _Counter, statuses: list[int]):
    """A handler that answers with ``statuses[i]`` for the i-th request.

    The last status repeats once the list is exhausted.
    """

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _respond(self):
            length = int(self.headers.get("Content-Length", 0) or 0)
            if length:
                self.rfile.read(length)
            with counter.lock:
                index = len(counter.requests)
            status = statuses[index] if index < len(statuses) else statuses[-1]
            counter.record({"idempotency-key": self.headers.get("Idempotency-Key", "")})
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")

        do_POST = _respond
        do_GET = _respond

        def log_message(self, *a):
            pass

    return Handler


def _wire(**overrides):
    base = {
        "request_id": "r-retry",
        "agent_id": "a1",
        "run_id": "run1",
        "host": "svc.local",
        "port": FLAKY_PORT,
        "method": "POST",
        "path": "/api/echo",
        "headers": {"content-type": "application/json"},
        "body_b64": base64.b64encode(b'{"x":1}').decode(),
        "timeout_ms": 5000,
    }
    base.update(overrides)
    return base


class RetryContractSidecarTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy_dir = tempfile.mkdtemp()
        Path(cls.policy_dir, "northstar-egress.toml").write_text(POLICY_TOML)

    def _serve(self, counter: _Counter, statuses: list[int], port: int):
        server = HTTPServer(("127.0.0.1", port), _make_handler(counter, statuses))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, thread

    def _ctx(self):
        ctx = build_context(policy_dir=self.policy_dir)
        ctx._resolver = lambda _h: ["127.0.0.1"]
        return ctx

    def test_a_retryable_status_is_retried_on_the_real_path(self):
        counter = _Counter()
        server, thread = self._serve(counter, [503, 200], FLAKY_PORT)
        try:
            response = run_one(_wire(method="GET", port=FLAKY_PORT), self._ctx())
        finally:
            server.shutdown()
            thread.join(timeout=2)
            server.server_close()
        self.assertEqual(response["status"], "ok")
        self.assertEqual(response["http_status"], 200)
        # The upstream saw the request twice: the contract retried it.
        self.assertEqual(len(counter.requests), 2)
        self.assertEqual(response["attempts"], 2)

    def test_a_non_idempotent_post_without_a_key_is_not_retried(self):
        counter = _Counter()
        server, thread = self._serve(counter, [503, 200], RETRY_NO_KEY_PORT)
        try:
            response = run_one(_wire(method="POST", port=RETRY_NO_KEY_PORT), self._ctx())
        finally:
            server.shutdown()
            thread.join(timeout=2)
            server.server_close()
        self.assertEqual(response["status"], "error")
        # The upstream saw it once: a POST with no idempotency key may have
        # landed, so the sidecar must not repeat it.
        self.assertEqual(len(counter.requests), 1)
        self.assertEqual(response["attempts"], 1)

    def test_a_non_idempotent_post_with_a_key_is_retried(self):
        counter = _Counter()
        server, thread = self._serve(counter, [503, 200], RETRY_KEY_PORT)
        try:
            response = run_one(_wire(method="POST", port=RETRY_KEY_PORT, idempotency_key="call-1"), self._ctx())
        finally:
            server.shutdown()
            thread.join(timeout=2)
            server.server_close()
        self.assertEqual(response["status"], "ok")
        self.assertEqual(len(counter.requests), 2)

    def test_every_retry_carries_the_same_idempotency_key(self):
        counter = _Counter()
        server, thread = self._serve(counter, [503, 200], SAME_KEY_PORT)
        try:
            run_one(_wire(method="POST", port=SAME_KEY_PORT, idempotency_key="call-1"), self._ctx())
        finally:
            server.shutdown()
            thread.join(timeout=2)
            server.server_close()
        self.assertEqual(len(counter.requests), 2)
        self.assertEqual([entry["idempotency-key"] for entry in counter.requests], ["call-1", "call-1"])

    def test_a_malformed_idempotency_key_is_refused_before_any_socket_opens(self):
        counter = _Counter()
        server, thread = self._serve(counter, [200], BAD_KEY_PORT)
        try:
            response = run_one(_wire(port=BAD_KEY_PORT, idempotency_key="Not Valid"), self._ctx())
        finally:
            server.shutdown()
            thread.join(timeout=2)
            server.server_close()
        self.assertEqual(response["status"], "rejected")
        self.assertEqual(len(counter.requests), 0)

    def test_a_connection_refused_is_retried_then_reported(self):
        # Nothing is listening on this port: the connect fails, which is a
        # pre-write failure and therefore retryable. The port is bound and
        # released so it is a real, unroutable-to-nothing port that the
        # policy still allows.
        response = run_one(_wire(method="GET", port=DEAD_PORT), self._ctx())
        self.assertEqual(response["status"], "error")
        self.assertEqual(response["attempts"], 3)  # one attempt plus two retries
        self.assertEqual(response["retry_classification"], FailureClass.RETRYABLE.value)

    def test_a_gone_answer_is_distinguished_from_an_unreachable_one(self):
        counter = _Counter()
        server, thread = self._serve(counter, [404], GONE_PORT)
        try:
            response = run_one(_wire(method="GET", port=GONE_PORT), self._ctx())
        finally:
            server.shutdown()
            thread.join(timeout=2)
            server.server_close()
        self.assertEqual(response["status"], "error")
        self.assertEqual(response["target_state"], "gone")
        self.assertFalse(response["may_have_executed"])
        # A 404 is not retryable: the upstream saw it exactly once.
        self.assertEqual(len(counter.requests), 1)

    def test_an_indeterminate_failure_is_not_retried_and_not_a_success(self):
        # A server that closes the connection mid-response: the request was
        # written, so the operation may already have run.
        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0) or 0)
                if length:
                    self.rfile.read(length)
                self.close_connection = True
                self.wfile.close()

            def log_message(self, *a):
                pass

        server = HTTPServer(("127.0.0.1", CUT_SHORT_PORT), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            response = run_one(_wire(method="POST", port=CUT_SHORT_PORT, idempotency_key="call-1"), self._ctx())
        finally:
            server.shutdown()
            thread.join(timeout=2)
            server.server_close()
        self.assertEqual(response["status"], "error")
        self.assertNotEqual(response["target_state"], "ok")
        self.assertEqual(response["attempts"], 1)
        self.assertTrue(response["may_have_executed"])


class RetryContractUnitTests(unittest.TestCase):
    """The seam's own helpers, independent of the HTTP server."""

    def test_the_payload_digest_pins_the_same_operation(self):
        first = retry_contract_egress.payload_digest("POST", "/api", b"body")
        second = retry_contract_egress.payload_digest("POST", "/api", b"body")
        third = retry_contract_egress.payload_digest("POST", "/api", b"other")
        self.assertEqual(first, second)
        self.assertNotEqual(first, third)

    def test_the_operation_carries_the_validated_key(self):
        operation = retry_contract_egress.operation_for_request(
            {"method": "POST", "path": "/api", "body_b64": ""}, idempotency_key="call-1"
        )
        self.assertEqual(operation.idempotency_key, "call-1")

    def test_a_malformed_key_is_refused_when_the_operation_is_built(self):
        with self.assertRaises(IdempotencyKeyError):
            retry_contract_egress.operation_for_request(
                {"method": "POST", "path": "/api", "body_b64": ""}, idempotency_key="BAD KEY"
            )

    def test_the_key_pattern_matches_the_e2b_rule(self):
        self.assertEqual(resolve_idempotency_key("abc-123"), "abc-123")
        with self.assertRaises(IdempotencyKeyError):
            resolve_idempotency_key("ABC-123")

    def test_the_outcome_state_distinguishes_gone_from_unreachable(self):
        gone = retry_contract_egress.RetryOutcome(
            ok=False,
            failure=retry_contract_egress.classify_response(404),
            may_have_executed=False,
        )
        unreachable = retry_contract_egress.RetryOutcome(
            ok=False,
            failure=retry_contract_egress.classify_response(500),
            may_have_executed=True,
        )
        self.assertEqual(retry_contract_egress.outcome_state(gone), "gone")
        self.assertEqual(retry_contract_egress.outcome_state(unreachable), "unreachable")

    def test_the_retry_configuration_is_declared_once(self):
        config = retry_contract_egress.DEFAULT_EGRESS_RETRY_CONFIG
        self.assertEqual(config.max_retries, 2)
        self.assertLessEqual(config.max_wait_ms, 10_000)
        self.assertGreaterEqual(config.jitter, 0.0)
        self.assertLessEqual(config.jitter, 1.0)
