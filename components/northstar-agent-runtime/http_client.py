"""Simulated HTTP client: request/response bookkeeping with retry and timeout discipline.

Research motivation: an agent runtime that calls tools, model APIs, or
peer agents over HTTP needs the same resilience primitives as any
production client -- bounded retries with backoff, per-request timeouts,
fail-fast on client errors -- but expressed as *decision records* rather
than live network I/O. This module owns that shape: it validates and pins
requests, executes them through a host-injected ``transport``, applies a
deterministic retry policy, and enforces a timeout budget. The transport
is simulated by default (no sockets, no DNS), which keeps every run
replayable from the audit record and makes the timeout discipline
*computed* rather than *waited*.

Public API:

- ``HTTPMethod`` -- ``GET`` / ``POST`` / ``PUT`` / ``DELETE`` / ``HEAD`` / ``PATCH``.
- ``HTTPRetryPolicy`` -- frozen retry configuration: ``max_attempts``,
  ``backoff`` (constant / linear / exponential), ``base_delay_ms``,
  ``max_delay_ms``, and the retryable ``retry_on_status`` set.
- ``HTTPRequest`` -- frozen, digest-pinned request record (method, url,
  headers, body digest, caller seq).
- ``HTTPResponse`` -- frozen response record (status, headers, body,
  ``latency_ms``, ``sha256:`` body digest pin).
- ``HTTPClient`` -- ``request()`` / ``get()`` / ``post()`` / ``put()`` /
  ``delete()`` / ``head()`` / ``patch()`` through an injected transport;
  ``retry_policy()`` returns the configured frozen policy.
- ``TransportResult`` -- frozen transport outcome (status, headers, body,
  ``latency_ms``).
- Errors (fail-closed taxonomy): ``HTTPClientError`` (base),
  ``InvalidRequestError``, ``TransportError``, ``HTTPTimeoutError``,
  ``HTTPStatusError`` (non-retryable status), ``HTTPRetryExhausted``
  (carries the frozen ``RequestReport`` and chains the last error).

Retry and timeout discipline:

- **Bounded attempts** -- ``max_attempts`` caps total tries (1 = no retry).
- **Fail-closed classification** -- only transport errors, timeouts, and
  statuses in ``retry_on_status`` are retried. Any other status
  (non-retryable 4xx) raises ``HTTPStatusError`` immediately without
  consuming attempts. This mirrors :mod:`retry_policy`'s "only
  ``retry_on`` is retried" rule.
- **Backoff computed, not waited** -- delays are deterministic functions
  of the attempt index and are *recorded*, not slept; ``request`` accepts
  an injectable ``sleeper`` (default: ``time.sleep``) so tests capture the
  schedule without sleeping.
- **Timeout as budget** -- each attempt's host-reported ``latency_ms``
  is checked against ``timeout_ms``. Exceeding it raises
  ``HTTPTimeoutError`` and consumes a retry attempt. This is a simulated
  budget check, not a real socket deadline.
- **Exhaustion** -- when every attempt fails, ``HTTPRetryExhausted`` is
  raised with the frozen ``RequestReport`` (every attempt, every computed
  delay) and the last error chained as ``__cause__``.

Honest scope:

- Simulated I/O only: the default transport answers ``200`` with an empty
  body and zero latency. A host injects a real transport to reach the
  network. This module cannot prove a request reached a peer, that a
  reported latency was measured honestly, or that a 200 body is truthful --
  it books host-reported outcomes (GIGO boundary, same as the rest of the
  batch line).
- ``succeeded=True`` in a report means "the transport returned an
  accepted status", never "the world changed". Retrying a non-idempotent
  ``POST`` can *repeat* the side effect; idempotency keys are the caller's
  job (see :mod:`idempotency_manager`).
- Timeouts are enforced on the transport's *reported* ``latency_ms``;
  there is no live deadline thread and no cancellation of an in-flight
  host transport.
- Digest pins bind request/response *identity* (method, url, headers,
  body bytes); pins never bind truth.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, Mapping, Optional, Tuple

#: Version pin for this module's record shape.
HTTP_CLIENT_VERSION = "http-client.v1"

#: Schema pin carried by records and audit events.
HTTP_CLIENT_SCHEMA = "northstar.http-client.v1"

#: Default retryable statuses: 408/425 (client-side transient), 429
#: (rate limit), and the 5xx server errors. Every other status is
#: fail-fast: ``HTTPStatusError`` on the first attempt, no retry.
DEFAULT_RETRY_ON_STATUS = frozenset({408, 425, 429, 500, 502, 503, 504})

#: Default per-request timeout budget in milliseconds.
DEFAULT_TIMEOUT_MS = 30_000

#: Backoff delay cap guardrail (1 hour); ``max_delay_ms`` itself is
#: capped here to bound any single recorded schedule.
MAX_DELAY_MS_CAP = 3_600_000

#: Maximum total attempts (structural loop bound).
MAX_ATTEMPTS = 32

#: Maximum request/response body size in bytes (DoS guardrail).
MAX_BODY_BYTES = 16 * 1024 * 1024


class Backoff(str, Enum):
    """Backoff delay growth between retries."""

    CONSTANT = "constant"
    LINEAR = "linear"
    EXPONENTIAL = "exponential"


class HTTPMethod(str, Enum):
    """Supported HTTP methods."""

    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    HEAD = "HEAD"
    PATCH = "PATCH"


class HTTPClientError(Exception):
    """Base error for the HTTP client."""


class InvalidRequestError(HTTPClientError):
    """Malformed request (bad URL, headers, body, or seq). Never retried."""


class TransportError(HTTPClientError):
    """The transport raised or returned an unusable outcome. Retried."""


class HTTPTimeoutError(HTTPClientError):
    """An attempt's reported latency exceeded ``timeout_ms``. Retried."""


class HTTPStatusError(HTTPClientError):
    """The server returned a non-retryable status. Never retried.

    Carries the failed ``HTTPResponse`` in ``response``.
    """

    def __init__(self, response: "HTTPResponse"):
        self.response = response
        super().__init__(
            f"non-retryable HTTP status {response.status} for "
            f"{response.request_method} {response.request_url}"
        )


class HTTPRetryExhausted(HTTPClientError):
    """Raised when every attempt failed.

    Carries the frozen :class:`RequestReport` in ``report`` and chains the
    last attempt's exception as ``__cause__``.
    """

    def __init__(self, report: "RequestReport", last_error: BaseException):
        self.report = report
        self.last_error = last_error
        super().__init__(
            f"HTTP retry exhausted after {report.attempts_made} attempt(s): "
            f"{type(last_error).__name__}: {last_error}"
        )
        self.__cause__ = last_error


def _check_seq(seq: object, name: str = "seq") -> int:
    """Validate a caller-supplied int seq: int, not bool, non-negative."""
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise TypeError(f"{name} must be an int, got {type(seq).__name__}")
    if seq < 0:
        raise ValueError(f"{name} must be non-negative, got {seq}")
    return seq


def _check_url(url: object) -> str:
    """Validate an HTTP(S) URL fail-closed."""
    if not isinstance(url, str):
        raise InvalidRequestError(
            f"url must be str, got {type(url).__name__}"
        )
    if not url or url != url.strip() or any(c.isspace() for c in url):
        raise InvalidRequestError("url must be non-empty with no whitespace")
    if "://" not in url:
        raise InvalidRequestError("url must include a scheme (http/https)")
    scheme, _, rest = url.partition("://")
    if scheme.lower() not in ("http", "https"):
        raise InvalidRequestError(
            f"url scheme must be http or https, got {scheme!r}"
        )
    authority = rest.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in authority:
        raise InvalidRequestError("url must not contain userinfo")
    host = authority.rsplit(":", 1)[0] if ":" in authority else authority
    # A trailing colon with an empty port (e.g. "host:") is rejected by
    # requiring a non-empty host after port splitting.
    if not host:
        raise InvalidRequestError("url must include a host")
    return url


def _check_headers(headers: object) -> Tuple[Tuple[str, str], ...]:
    """Validate headers: a ``str -> str`` mapping *or* a sequence of
    ``(str, str)`` pairs (canonical form used by transports).

    Returns sorted ``(name, value)`` pairs.
    """
    if headers is None:
        return ()
    if isinstance(headers, Mapping):
        items = list(headers.items())
    elif isinstance(headers, (tuple, list)):
        items = list(headers)
    else:
        raise InvalidRequestError(
            f"headers must be a mapping or a sequence of pairs, "
            f"got {type(headers).__name__}"
        )
    pairs = []
    for item in items:
        if (
            not isinstance(item, (tuple, list))
            or len(item) != 2
        ):
            raise InvalidRequestError(
                "header pairs must be (name, value) pairs"
            )
        key, value = item
        if not isinstance(key, str) or not key:
            raise InvalidRequestError("header names must be non-empty str")
        if not isinstance(value, str):
            raise InvalidRequestError(
                f"header {key!r} value must be str, got {type(value).__name__}"
            )
        pairs.append((key, value))
    return tuple(sorted(pairs))


def _check_body(body: object) -> bytes:
    """Validate a body: bytes, str, or None; return bytes."""
    if body is None:
        return b""
    if isinstance(body, str):
        body = body.encode("utf-8")
    if not isinstance(body, (bytes, bytearray)):
        raise InvalidRequestError(
            f"body must be bytes, str, or None, got {type(body).__name__}"
        )
    body = bytes(body)
    if len(body) > MAX_BODY_BYTES:
        raise InvalidRequestError(
            f"body exceeds {MAX_BODY_BYTES} bytes ({len(body)})"
        )
    return body


def _check_ms(value: object, name: str, allow_zero: bool = False) -> int:
    """Validate a millisecond budget: int, not bool, positive (or zero)."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int, got {type(value).__name__}")
    if value < 0 or (value == 0 and not allow_zero):
        raise ValueError(f"{name} must be positive, got {value}")
    return value


def _sha256_hex(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _canonical(obj: Any) -> bytes:
    """Canonical JSON encoding for digest pins (sorted keys, tight separators)."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


@dataclass(frozen=True)
class HTTPRetryPolicy:
    """Frozen retry configuration for the HTTP client."""

    max_attempts: int = 3
    backoff: Backoff = Backoff.EXPONENTIAL
    base_delay_ms: int = 100
    max_delay_ms: int = 5_000
    retry_on_status: frozenset = field(
        default_factory=lambda: DEFAULT_RETRY_ON_STATUS
    )

    def __post_init__(self) -> None:
        if isinstance(self.max_attempts, bool) or not isinstance(
            self.max_attempts, int
        ):
            raise TypeError("max_attempts must be an int")
        if not 1 <= self.max_attempts <= MAX_ATTEMPTS:
            raise ValueError(
                f"max_attempts must be in [1, {MAX_ATTEMPTS}], "
                f"got {self.max_attempts}"
            )
        if not isinstance(self.backoff, Backoff):
            raise TypeError(
                f"backoff must be a Backoff, got {type(self.backoff).__name__}"
            )
        _check_ms(self.base_delay_ms, "base_delay_ms", allow_zero=True)
        if self.max_delay_ms > MAX_DELAY_MS_CAP:
            raise ValueError(
                f"max_delay_ms exceeds cap {MAX_DELAY_MS_CAP}"
            )
        _check_ms(self.max_delay_ms, "max_delay_ms")
        if not isinstance(self.retry_on_status, frozenset):
            raise TypeError("retry_on_status must be a frozenset")
        for status in self.retry_on_status:
            if isinstance(status, bool) or not isinstance(status, int):
                raise TypeError("retry_on_status entries must be ints")
            if not 100 <= status <= 599:
                raise ValueError(
                    f"retry_on_status entries must be HTTP statuses, "
                    f"got {status}"
                )

    def delay_ms(self, retry_index: int) -> int:
        """Computed backoff delay for the 1-based retry index (never slept here)."""
        if isinstance(retry_index, bool) or not isinstance(retry_index, int):
            raise TypeError("retry_index must be an int")
        if retry_index < 1:
            raise ValueError("retry_index must be >= 1")
        if self.backoff is Backoff.CONSTANT:
            delay = self.base_delay_ms
        elif self.backoff is Backoff.LINEAR:
            delay = self.base_delay_ms * retry_index
        else:  # EXPONENTIAL
            delay = self.base_delay_ms * (2 ** (retry_index - 1))
        return min(delay, self.max_delay_ms)

    def is_retryable_status(self, status: int) -> bool:
        """True when a failed status deserves another attempt."""
        return status in self.retry_on_status

    def as_dict(self) -> Dict[str, Any]:
        return {
            "version": HTTP_CLIENT_VERSION,
            "schema": HTTP_CLIENT_SCHEMA,
            "max_attempts": self.max_attempts,
            "backoff": self.backoff.value,
            "base_delay_ms": self.base_delay_ms,
            "max_delay_ms": self.max_delay_ms,
            "retry_on_status": sorted(self.retry_on_status),
        }


@dataclass(frozen=True)
class HTTPRequest:
    """A validated, digest-pinned HTTP request record."""

    method: HTTPMethod
    url: str
    headers: Tuple[Tuple[str, str], ...]
    body_digest: str
    body_length: int
    seq: int
    digest: str

    @staticmethod
    def build(
        method: HTTPMethod, url: str, headers: object, body: bytes, seq: int
    ) -> "HTTPRequest":
        _check_seq(seq)
        if not isinstance(method, HTTPMethod):
            raise InvalidRequestError(
                f"method must be an HTTPMethod, got {type(method).__name__}"
            )
        checked_url = _check_url(url)
        checked_headers = _check_headers(headers)
        checked_body = _check_body(body)
        body_digest = _sha256_hex(checked_body)
        digest = _sha256_hex(
            _canonical(
                {
                    "method": method.value,
                    "url": checked_url,
                    "headers": [list(p) for p in checked_headers],
                    "body_digest": body_digest,
                    "seq": seq,
                }
            )
        )
        return HTTPRequest(
            method=method,
            url=checked_url,
            headers=checked_headers,
            body_digest=body_digest,
            body_length=len(checked_body),
            seq=seq,
            digest=digest,
        )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "version": HTTP_CLIENT_VERSION,
            "schema": HTTP_CLIENT_SCHEMA,
            "method": self.method.value,
            "url": self.url,
            "headers": [list(p) for p in self.headers],
            "body_digest": self.body_digest,
            "body_length": self.body_length,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class HTTPResponse:
    """A frozen HTTP response record. Pins identity, never truth."""

    request_method: str
    request_url: str
    request_digest: str
    status: int
    headers: Tuple[Tuple[str, str], ...]
    body_digest: str
    body_length: int
    latency_ms: int
    digest: str

    def is_success(self) -> bool:
        return 200 <= self.status < 300

    def as_dict(self) -> Dict[str, Any]:
        return {
            "version": HTTP_CLIENT_VERSION,
            "schema": HTTP_CLIENT_SCHEMA,
            "request_method": self.request_method,
            "request_url": self.request_url,
            "request_digest": self.request_digest,
            "status": self.status,
            "headers": [list(p) for p in self.headers],
            "body_digest": self.body_digest,
            "body_length": self.body_length,
            "latency_ms": self.latency_ms,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class TransportResult:
    """Raw outcome from the host transport: status, headers, body, latency."""

    status: int
    headers: Tuple[Tuple[str, str], ...]
    body: bytes
    latency_ms: int


@dataclass(frozen=True)
class AttemptRecord:
    """One executed attempt: outcome, computed delay, latency."""

    attempt: int  # 1-based
    outcome: str  # "success" | "retryable" | "fatal"
    status: Optional[int]
    delay_before_ms: int  # computed backoff before this attempt (0 on 1st)
    latency_ms: Optional[int]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "attempt": self.attempt,
            "outcome": self.outcome,
            "status": self.status,
            "delay_before_ms": self.delay_before_ms,
            "latency_ms": self.latency_ms,
        }


@dataclass(frozen=True)
class RequestReport:
    """Frozen ledger of a completed (or exhausted) request."""

    request_digest: str
    attempts: Tuple[AttemptRecord, ...]
    attempts_made: int
    succeeded: bool
    final_status: Optional[int]
    total_delay_ms: int

    def as_dict(self) -> Dict[str, Any]:
        return {
            "version": HTTP_CLIENT_VERSION,
            "schema": HTTP_CLIENT_SCHEMA,
            "request_digest": self.request_digest,
            "attempts": [a.as_dict() for a in self.attempts],
            "attempts_made": self.attempts_made,
            "succeeded": self.succeeded,
            "final_status": self.final_status,
            "total_delay_ms": self.total_delay_ms,
        }


def _default_transport(request: HTTPRequest, seq: int) -> TransportResult:
    """Simulated transport: always 200, empty body, zero latency.

    No sockets, no DNS -- the honest default for a bookkeeping client.
    """
    return TransportResult(status=200, headers=(), body=b"", latency_ms=0)


def _build_response(
    request: HTTPRequest, result: TransportResult, seq: int
) -> HTTPResponse:
    if not isinstance(result, TransportResult):
        raise TransportError(
            f"transport must return TransportResult, "
            f"got {type(result).__name__}"
        )
    if isinstance(result.status, bool) or not isinstance(result.status, int):
        raise TransportError("transport status must be an int")
    if not 100 <= result.status <= 599:
        raise TransportError(
            f"transport status out of range: {result.status}"
        )
    headers = _check_headers(result.headers)
    body = _check_body(result.body)
    if isinstance(result.latency_ms, bool) or not isinstance(
        result.latency_ms, int
    ):
        raise TransportError("transport latency_ms must be an int")
    if result.latency_ms < 0:
        raise TransportError("transport latency_ms must be non-negative")
    digest = _sha256_hex(
        _canonical(
            {
                "request_digest": request.digest,
                "status": result.status,
                "headers": [list(p) for p in headers],
                "body_digest": _sha256_hex(body),
                "latency_ms": result.latency_ms,
                "seq": seq,
            }
        )
    )
    return HTTPResponse(
        request_method=request.method.value,
        request_url=request.url,
        request_digest=request.digest,
        status=result.status,
        headers=headers,
        body_digest=_sha256_hex(body),
        body_length=len(body),
        latency_ms=result.latency_ms,
        digest=digest,
    )


class HTTPClient:
    """Simulated HTTP client with retry and timeout discipline."""

    def __init__(
        self,
        transport: Optional[Callable[[HTTPRequest, int], TransportResult]] = None,
        retry_policy: Optional[HTTPRetryPolicy] = None,
        timeout_ms: int = DEFAULT_TIMEOUT_MS,
        max_body_bytes: int = MAX_BODY_BYTES,
    ):
        if transport is not None and not callable(transport):
            raise TypeError("transport must be callable")
        if retry_policy is not None and not isinstance(
            retry_policy, HTTPRetryPolicy
        ):
            raise TypeError("retry_policy must be an HTTPRetryPolicy")
        _check_ms(timeout_ms, "timeout_ms")
        _check_ms(max_body_bytes, "max_body_bytes")
        self._transport = transport or _default_transport
        self._retry_policy = retry_policy or HTTPRetryPolicy()
        self._timeout_ms = timeout_ms
        self._max_body_bytes = max_body_bytes
        self._lock = threading.RLock()
        self._requests_made = 0

    def retry_policy(self) -> HTTPRetryPolicy:
        """Return the configured frozen retry policy."""
        return self._retry_policy

    def timeout_ms(self) -> int:
        """Return the per-request timeout budget in milliseconds."""
        return self._timeout_ms

    def requests_made(self) -> int:
        """Total ``request()`` calls issued through this client."""
        with self._lock:
            return self._requests_made

    def get(
        self,
        url: str,
        headers: Optional[Mapping[str, str]] = None,
        seq: int = 0,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> HTTPResponse:
        """Issue a GET through the retry/timeout pipeline."""
        return self.request(HTTPMethod.GET, url, body=None, headers=headers, seq=seq, sleeper=sleeper)

    def post(
        self,
        url: str,
        body: Any = None,
        headers: Optional[Mapping[str, str]] = None,
        seq: int = 0,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> HTTPResponse:
        """Issue a POST through the retry/timeout pipeline."""
        return self.request(HTTPMethod.POST, url, body=body, headers=headers, seq=seq, sleeper=sleeper)

    def put(
        self,
        url: str,
        body: Any = None,
        headers: Optional[Mapping[str, str]] = None,
        seq: int = 0,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> HTTPResponse:
        """Issue a PUT through the retry/timeout pipeline."""
        return self.request(HTTPMethod.PUT, url, body=body, headers=headers, seq=seq, sleeper=sleeper)

    def delete(
        self,
        url: str,
        headers: Optional[Mapping[str, str]] = None,
        seq: int = 0,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> HTTPResponse:
        """Issue a DELETE through the retry/timeout pipeline."""
        return self.request(HTTPMethod.DELETE, url, body=None, headers=headers, seq=seq, sleeper=sleeper)

    def head(
        self,
        url: str,
        headers: Optional[Mapping[str, str]] = None,
        seq: int = 0,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> HTTPResponse:
        """Issue a HEAD through the retry/timeout pipeline."""
        return self.request(HTTPMethod.HEAD, url, body=None, headers=headers, seq=seq, sleeper=sleeper)

    def patch(
        self,
        url: str,
        body: Any = None,
        headers: Optional[Mapping[str, str]] = None,
        seq: int = 0,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> HTTPResponse:
        """Issue a PATCH through the retry/timeout pipeline."""
        return self.request(HTTPMethod.PATCH, url, body=body, headers=headers, seq=seq, sleeper=sleeper)

    def request(
        self,
        method: HTTPMethod,
        url: str,
        body: Any = None,
        headers: Optional[Mapping[str, str]] = None,
        seq: int = 0,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> HTTPResponse:
        """Validate, pin, and execute a request with retries and timeout.

        ``seq`` is the caller's audit seq (validated, never wall-clock).
        ``sleeper`` is injectable: computed backoff delays are passed to it
        so tests capture the schedule without sleeping. ``body`` beyond
        the configured ``max_body_bytes`` is refused fail-closed *before*
        any transport call.
        """
        if not callable(sleeper):
            raise TypeError("sleeper must be callable")
        raw_body = _check_body(body)
        if len(raw_body) > self._max_body_bytes:
            raise InvalidRequestError(
                f"body exceeds client max_body_bytes {self._max_body_bytes}"
            )
        # Build validates method/url/headers/seq fail-closed; raises
        # InvalidRequestError (never retried) before any attempt.
        http_request = HTTPRequest.build(method, url, headers, raw_body, seq)
        with self._lock:
            self._requests_made += 1

        policy = self._retry_policy
        attempts: list[AttemptRecord] = []
        total_delay_ms = 0
        last_error: Optional[BaseException] = None

        for attempt_no in range(1, policy.max_attempts + 1):
            delay_before_ms = (
                policy.delay_ms(attempt_no - 1) if attempt_no > 1 else 0
            )
            if delay_before_ms:
                total_delay_ms += delay_before_ms
                sleeper(delay_before_ms / 1000.0)
            try:
                result = self._transport(http_request, seq)
            except HTTPClientError as exc:
                # Transport raised one of our own fail-closed errors;
                # treat timeouts as retryable, anything else as fatal.
                if isinstance(exc, HTTPTimeoutError):
                    outcome, retryable = "retryable", True
                else:
                    outcome, retryable = "fatal", False
                last_error = exc
                attempts.append(
                    AttemptRecord(
                        attempt=attempt_no,
                        outcome=outcome,
                        status=None,
                        delay_before_ms=delay_before_ms,
                        latency_ms=None,
                    )
                )
                if not retryable:
                    break
                continue
            except Exception as exc:  # host transport blew up: retryable
                last_error = TransportError(str(exc))
                last_error.__cause__ = exc
                attempts.append(
                    AttemptRecord(
                        attempt=attempt_no,
                        outcome="retryable",
                        status=None,
                        delay_before_ms=delay_before_ms,
                        latency_ms=None,
                    )
                )
                continue
            try:
                response = _build_response(http_request, result, seq)
            except HTTPClientError as exc:
                # Malformed transport outcome: retryable (host's fault),
                # but not a timeout.
                last_error = exc
                attempts.append(
                    AttemptRecord(
                        attempt=attempt_no,
                        outcome="retryable",
                        status=None,
                        delay_before_ms=delay_before_ms,
                        latency_ms=None,
                    )
                )
                continue
            if response.latency_ms > self._timeout_ms:
                last_error = HTTPTimeoutError(
                    f"attempt latency {response.latency_ms}ms exceeded "
                    f"timeout {self._timeout_ms}ms"
                )
                attempts.append(
                    AttemptRecord(
                        attempt=attempt_no,
                        outcome="retryable",
                        status=response.status,
                        delay_before_ms=delay_before_ms,
                        latency_ms=response.latency_ms,
                    )
                )
                continue
            if response.is_success():
                attempts.append(
                    AttemptRecord(
                        attempt=attempt_no,
                        outcome="success",
                        status=response.status,
                        delay_before_ms=delay_before_ms,
                        latency_ms=response.latency_ms,
                    )
                )
                return response
            if policy.is_retryable_status(response.status):
                last_error = TransportError(
                    f"retryable status {response.status}"
                )
                attempts.append(
                    AttemptRecord(
                        attempt=attempt_no,
                        outcome="retryable",
                        status=response.status,
                        delay_before_ms=delay_before_ms,
                        latency_ms=response.latency_ms,
                    )
                )
                continue
            # Non-retryable status: fail fast, no retry.
            fatal = HTTPStatusError(response)
            attempts.append(
                AttemptRecord(
                    attempt=attempt_no,
                    outcome="fatal",
                    status=response.status,
                    delay_before_ms=delay_before_ms,
                    latency_ms=response.latency_ms,
                )
            )
            raise fatal

        report = RequestReport(
            request_digest=http_request.digest,
            attempts=tuple(attempts),
            attempts_made=len(attempts),
            succeeded=False,
            final_status=attempts[-1].status if attempts else None,
            total_delay_ms=total_delay_ms,
        )
        assert last_error is not None
        raise HTTPRetryExhausted(report, last_error)


_AUDIT_KINDS = frozenset(
    {"requested", "responded", "retried", "timed-out", "exhausted", "rejected"}
)


def http_client_audit_event(
    kind: str,
    seq: int,
    request: Optional[HTTPRequest] = None,
    response: Optional[HTTPResponse] = None,
    report: Optional[RequestReport] = None,
) -> Dict[str, Any]:
    """Build an ``audit.ndjson/1``-shaped record for a client step.

    ``kind`` is one of ``requested`` / ``responded`` / ``retried`` /
    ``timed-out`` / ``exhausted`` / ``rejected``. Bodies are never emitted
    -- only ``sha256:`` digests -- so response content does not leak
    through the audit trail.
    """
    if kind not in _AUDIT_KINDS:
        raise ValueError(f"kind must be one of {sorted(_AUDIT_KINDS)}")
    _check_seq(seq)
    if request is not None and not isinstance(request, HTTPRequest):
        raise TypeError("request must be an HTTPRequest")
    if response is not None and not isinstance(response, HTTPResponse):
        raise TypeError("response must be an HTTPResponse")
    if report is not None and not isinstance(report, RequestReport):
        raise TypeError("report must be a RequestReport")
    record: Dict[str, Any] = {
        "event": f"http-client-{kind}",
        "audit_seq": seq,
        "version": HTTP_CLIENT_VERSION,
        "schema": HTTP_CLIENT_SCHEMA,
    }
    if request is not None:
        record["request_digest"] = request.digest
        record["method"] = request.method.value
        record["url"] = request.url
    if response is not None:
        record["response_digest"] = response.digest
        record["status"] = response.status
        record["body_digest"] = response.body_digest
    if report is not None:
        record["attempts_made"] = report.attempts_made
        record["total_delay_ms"] = report.total_delay_ms
    return record


def main() -> None:
    # Default simulated transport answers 200 immediately.
    client = HTTPClient()
    resp = client.get("https://example.com/health", seq=0,
                       sleeper=lambda s: None)
    assert resp.status == 200 and resp.is_success()
    assert resp.body_digest.startswith("sha256:")
    assert client.requests_made() == 1

    # POST pins the body digest; the audit record carries the digest only.
    resp2 = client.post("https://example.com/items", body=b'{"a":1}',
                        headers={"Content-Type": "application/json"}, seq=1,
                        sleeper=lambda s: None)
    assert resp2.request_digest != resp.request_digest
    audit = http_client_audit_event("responded", 2, response=resp2)
    assert audit["event"] == "http-client-responded"
    assert "body_digest" in audit and audit["body_digest"].startswith("sha256:")

    # Retryable 503s are retried; the schedule is recorded, never slept.
    calls = {"n": 0}

    def flaky(_req: HTTPRequest, _seq: int) -> TransportResult:
        calls["n"] += 1
        if calls["n"] < 3:
            return TransportResult(status=503, headers=(), body=b"", latency_ms=5)
        return TransportResult(status=200, headers=(), body=b"ok", latency_ms=5)

    sleeps: list[float] = []
    flaky_client = HTTPClient(
        transport=flaky,
        retry_policy=HTTPRetryPolicy(
            max_attempts=3, backoff=Backoff.CONSTANT, base_delay_ms=50
        ),
    )
    resp3 = flaky_client.get("https://example.com/flaky", seq=3,
                             sleeper=sleeps.append)
    assert resp3.status == 200 and calls["n"] == 3
    assert sleeps == [0.05, 0.05]

    # Non-retryable 404 fails fast on the first attempt.
    def not_found(_req: HTTPRequest, _seq: int) -> TransportResult:
        return TransportResult(status=404, headers=(), body=b"nope", latency_ms=1)

    fast = HTTPClient(transport=not_found)
    try:
        fast.get("https://example.com/missing", seq=4,
                 sleeper=lambda s: None)
        raise AssertionError("expected HTTPStatusError")
    except HTTPStatusError as exc:
        assert exc.response.status == 404

    # Bad URL is refused before any transport call.
    try:
        client.get("ftp://example.com/x", seq=5, sleeper=lambda s: None)
        raise AssertionError("expected InvalidRequestError")
    except InvalidRequestError:
        pass

    policy = client.retry_policy()
    assert isinstance(policy, HTTPRetryPolicy)
    assert policy.max_attempts == 3
    assert policy.delay_ms(1) == 100 and policy.delay_ms(2) == 200
    print("http-client OK: methods, retries, timeout, fail-closed")


if __name__ == "__main__":
    main()
