"""Retry and idempotency contract for outbound calls.

Northstar's egress sidecar is the only process that opens outbound network
connections, and every connection it opens carries a call whose side effect
may already have landed on the far side. A blind retry of a call that landed
re-executes it (a deploy posted twice, a payment captured twice). A blind
*non*-retry of a call that never landed loses the work and strands the run.

This module is the contract that separates those two cases. It answers three
questions, in order, for every failed call:

1. **Is the failure retryable?** (``FailureClass``) -- a classification, not a
   guess. It is transcribed from E2B's ``packages/js-sdk/src/retry.ts``.
2. **May this particular call be replayed?** (``Operation``) -- a per-call
   property, decided in *code* at the call site (not in a runbook): a
   non-idempotent operation without an idempotency key is never replayed.
3. **What does the caller get to know?** -- two distinct error types, so the
   caller can tell "this target is confirmed gone" (recreate it) from "this
   target could not be reached and might still be running" (resume it).

E2B mapping (source read verbatim, Apache-2.0):

======================================  =========================================
E2B (``packages/js-sdk/src/retry.ts``)   Northstar here
======================================  =========================================
``Should-Retry: true``                   ``classify_response`` -> RETRYABLE
``Should-Retry: false``                  -> NON_RETRYABLE (a present header is
                                          authoritative, including an explicit
                                          ``false``)
``Should-Retry`` absent, status in       -> RETRYABLE
{429, 502, 503, 504}
``Should-Retry`` absent, other status    -> NON_RETRYABLE
``isRetryableFetchError`` /              PRE_WRITE + connection error ->
``CONNECTION_ERROR_CODES``                RETRYABLE
post-write failure (``ECONNRESET``)      POST_WRITE -> NON_RETRYABLE, and the
                                          outcome is *indeterminate*
streaming request body                   ``Operation.body_replayable`` is
                                          False -> exactly one attempt
``resolveIdempotencyKey``                ``resolve_idempotency_key`` --
                                          ``^[a-z0-9-]{1,255}$``
``Idempotency-Key`` request header       the sidecar sends the operation's key
                                          upstream, unchanged on every retry
``SandboxNotFoundError`` /               ``TargetGoneError`` (confirmed absent)
``SandboxNotRunningError``
``SandboxUnreachableError``              ``TargetUnreachableError`` (might
                                          still be running)
``ServiceBusyError`` (503)               503 is retryable and, per E2B, changes
                                          nothing -- so it is safe to repeat
======================================  =========================================

The one place Northstar is *stricter* than E2B is deliberate: E2B retries a
retryable status whenever the caller asked for retries. Northstar refuses to
replay a call it cannot prove is replay-safe, because "the server answered
502" is not proof that the origin never saw the request. See
``RetryContract.execute`` for the gate.

Fail-closed: an indeterminate outcome is never retried and never reported as
success. It is returned as ``TargetUnreachableError`` with
``may_have_executed=True`` so the caller can decide between resume and
recreate.
"""
from __future__ import annotations

import errno
import re
import socket
import ssl
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Mapping

RETRY_CONTRACT_VERSION = "retry-contract.v1"

#: The header a server uses to declare whether a call may be repeated. E2B
#: reads it as ``Should-Retry``; the comparison here is case-insensitive on
#: the value and on the header name.
SHOULD_RETRY_HEADER = "should-retry"

#: E2B: ``RETRYABLE_STATUSES``. Consulted only when the header is absent.
RETRYABLE_STATUSES: frozenset[int] = frozenset({429, 502, 503, 504})

#: E2B: ``IDEMPOTENCY_KEY_PATTERN``.
IDEMPOTENCY_KEY_PATTERN = re.compile(r"^[a-z0-9-]{1,255}\Z")

def _errnos(*names: str) -> frozenset[int]:
    """Resolve errno names that are not present on every platform."""
    return frozenset(
        value for value in (getattr(errno, name, None) for name in names) if isinstance(value, int)
    )


#: E2B: ``CONNECTION_ERROR_CODES`` -- failures raised while *establishing* the
#: connection, before any request bytes were written.
CONNECTION_ERROR_CODES: frozenset[int] = _errnos(
    "ECONNREFUSED", "ENOTFOUND", "EAI_AGAIN", "EHOSTUNREACH",
    "ENETUNREACH", "ENETDOWN", "EHOSTDOWN",
)

#: Post-write failures: the request may already have reached the peer.
POST_WRITE_ERROR_CODES: frozenset[int] = _errnos("ECONNRESET", "EPIPE", "ESHUTDOWN")

#: HTTP methods that are idempotent by definition, so repeating them cannot
#: double an effect. Everything else needs an idempotency key to be
#: replay-safe.
IDEMPOTENT_METHODS: frozenset[str] = frozenset({"GET", "HEAD", "OPTIONS", "TRACE", "DELETE"})

#: Statuses that mean "the addressed resource is confirmed absent". E2B's
#: ``SandboxNotFoundError`` is the same idea for sandboxes.
GONE_STATUSES: frozenset[int] = frozenset({404, 410})


class FailurePhase(str, Enum):
    """Where a failure happened relative to the request bytes."""

    #: The connection was never established; no request byte reached the peer.
    PRE_WRITE = "pre_write"
    #: The request was (possibly) written; the peer may have received it.
    POST_WRITE = "post_write"
    #: We cannot tell.
    UNKNOWN = "unknown"


class FailureClass(str, Enum):
    """E2B's retry decision, as three explicit outcomes."""

    #: Repeating the call is expected to be safe and possibly useful.
    RETRYABLE = "retryable"
    #: Repeating the call is pointless or unsafe; the outcome is definite.
    NON_RETRYABLE = "non_retryable"
    #: We cannot tell whether the operation executed. Never retried, never
    #: reported as success.
    UNKNOWN = "unknown"


class RetryContractError(Exception):
    """Base class for every failure this module raises."""


class IdempotencyKeyError(RetryContractError, ValueError):
    """An idempotency key does not satisfy ``^[a-z0-9-]{1,255}$``."""


class IdempotencyMismatchError(RetryContractError):
    """A retry did not carry the same idempotency key and payload digest.

    Raised *instead of* resending. A retry that would replay a different
    operation is worse than no retry: it is a second, distinct side effect
    wearing the first operation's name.
    """


class IndeterminateError(RetryContractError):
    """A failure that happened after the request may already have been written.

    The transport could not tell whether the peer received the request: a
    read timeout, a dropped connection mid-response, a malformed status
    line. The call is *not* retried (the peer may already have executed it)
    and *not* reported as a success.
    """


class TargetGoneError(RetryContractError):
    """The target is confirmed absent: stopped, deleted, or never existed.

    The caller should *recreate* it. Retrying the call cannot help.
    """

    def __init__(self, message: str, *, may_have_executed: bool = False) -> None:
        super().__init__(message)
        self.may_have_executed = may_have_executed


class TargetUnreachableError(RetryContractError):
    """The target could not be reached and may still be running.

    The caller should *resume* it (or probe its state), not assume it is
    gone and not blindly recreate it.
    """

    def __init__(self, message: str, *, may_have_executed: bool = False) -> None:
        super().__init__(message)
        self.may_have_executed = may_have_executed


@dataclass(frozen=True)
class Failure:
    """One classified failure: what happened, and what may be done about it."""

    classification: FailureClass
    phase: FailurePhase
    reason: str
    #: True when the peer may already have executed the operation.
    may_have_executed: bool = False
    #: The HTTP status, when the failure is a response.
    status: int | None = None

    @property
    def retryable(self) -> bool:
        return self.classification is FailureClass.RETRYABLE


def resolve_idempotency_key(value: str | None) -> str | None:
    """Validate a client-supplied idempotency key.

    E2B: ``resolveIdempotencyKey``. ``None`` means "no key"; a key that is
    present must match ``^[a-z0-9-]{1,255}$``. An invalid key is a
    programming error and is refused loudly rather than silently dropped --
    a dropped key would quietly turn a replay-safe call into a replay-unsafe
    one.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        raise IdempotencyKeyError("idempotency key must be a string")
    if not IDEMPOTENCY_KEY_PATTERN.fullmatch(value):
        raise IdempotencyKeyError(
            "invalid idempotency key: expected 1-255 characters of lowercase "
            "letters, digits and hyphens"
        )
    return value


def operation_replay_safe(method: str, idempotency_key: str | None) -> bool:
    """Whether this call may be repeated without doubling a side effect.

    The rule lives here, in code, once -- so that no call site re-invents it
    and no runbook has to be consulted at 3am:

    * an idempotent HTTP method may always be repeated;
    * any other method may be repeated only when the caller supplied an
      idempotency key, so the server can collapse the duplicate.
    """
    return method.upper() in IDEMPOTENT_METHODS or idempotency_key is not None


@dataclass(frozen=True)
class RetryContractConfig:
    """Declarative retry configuration. No constants at the call site."""

    #: Extra attempts after the first one.
    max_retries: int = 2
    #: Delay before the first retry, in milliseconds.
    initial_wait_ms: int = 100
    #: Ceiling for the backoff delay, in milliseconds.
    max_wait_ms: int = 10_000
    #: Growth factor of the backoff.
    exponential_base: float = 2.0
    #: Fraction of the delay that is randomized, in ``[0, 1]``. E2B jitters
    #: between 50% and 100% of the computed delay.
    jitter: float = 0.5

    def __post_init__(self) -> None:
        if isinstance(self.max_retries, bool) or not isinstance(self.max_retries, int):
            raise RetryContractError("max_retries must be an integer")
        if self.max_retries < 0:
            raise RetryContractError("max_retries must be >= 0")
        for name in ("initial_wait_ms", "max_wait_ms"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise RetryContractError(f"{name} must be an integer")
            if value < 0:
                raise RetryContractError(f"{name} must be >= 0")
        if self.max_wait_ms < self.initial_wait_ms:
            raise RetryContractError("max_wait_ms must be >= initial_wait_ms")
        if isinstance(self.exponential_base, bool) or not isinstance(self.exponential_base, (int, float)):
            raise RetryContractError("exponential_base must be a number")
        if self.exponential_base < 1.0:
            raise RetryContractError("exponential_base must be >= 1.0")
        if isinstance(self.jitter, bool) or not isinstance(self.jitter, (int, float)):
            raise RetryContractError("jitter must be a number")
        if not 0.0 <= self.jitter <= 1.0:
            raise RetryContractError("jitter must be between 0.0 and 1.0")

    def delay_ms(self, attempt: int, random: Callable[[], float]) -> int:
        """Delay before the retry numbered ``attempt`` (1 = first retry)."""
        backoff = self.initial_wait_ms * (self.exponential_base ** (attempt - 1))
        capped = min(float(backoff), float(self.max_wait_ms))
        factor = (1.0 - self.jitter) + (self.jitter * random())
        return int(capped * factor)


#: The configuration used when a caller does not supply one.
DEFAULT_RETRY_CONFIG = RetryContractConfig()


def _header_value(headers: Mapping[str, str] | None, name: str) -> str | None:
    """Case-insensitive header lookup. A present-but-empty header is present."""
    if not headers:
        return None
    lowered = name.lower()
    for key, value in headers.items():
        if isinstance(key, str) and key.lower() == lowered:
            return value if isinstance(value, str) else ""
    return None


def classify_response(status: int, headers: Mapping[str, str] | None = None) -> Failure:
    """Classify an HTTP response.

    E2B's ``retryDelayMs``: a present ``Should-Retry`` header is authoritative
    -- including an explicit ``false``, which forbids the retry. Only when
    the header is *absent* do the retryable statuses (429/502/503/504) apply.

    A 404 or 410 is a confirmed-gone answer: the target does not exist. It is
    neither retryable nor merely unknown.
    """
    raw = _header_value(headers, SHOULD_RETRY_HEADER)
    if raw is not None:
        if raw.strip().lower() == "true":
            return Failure(FailureClass.RETRYABLE, FailurePhase.PRE_WRITE, "server declared Should-Retry: true", status=status)
        return Failure(FailureClass.NON_RETRYABLE, FailurePhase.PRE_WRITE, "server declared Should-Retry: false", status=status)
    if status in GONE_STATUSES:
        return Failure(FailureClass.NON_RETRYABLE, FailurePhase.PRE_WRITE, f"target confirmed absent (HTTP {status})", status=status)
    if status in RETRYABLE_STATUSES:
        return Failure(FailureClass.RETRYABLE, FailurePhase.PRE_WRITE, f"HTTP {status} is retryable", status=status)
    return Failure(FailureClass.NON_RETRYABLE, FailurePhase.PRE_WRITE, f"HTTP {status} is not retryable", status=status)


def classify_exception(error: BaseException) -> Failure:
    """Classify a transport failure.

    E2B's ``isRetryableFetchError``/``isConnectionError``: only failures
    raised while *establishing* the connection are retryable. A failure after
    the request was written -- ``ECONNRESET`` and friends -- is not: "the
    server may have received the request", so repeating it could execute the
    operation twice. Such a failure is indeterminate, not merely a failure,
    and is reported as such.

    A :class:`IndeterminateError` is the caller's way of saying "the request
    may already be on the wire" -- a read timeout, a dropped connection
    mid-response. It is never retried and never reported as success.
    """
    if isinstance(error, IndeterminateError):
        return Failure(
            FailureClass.NON_RETRYABLE,
            FailurePhase.POST_WRITE,
            str(error) or "the request may already have been received",
            may_have_executed=True,
        )
    if isinstance(error, ssl.SSLError):
        # A TLS handshake failure happens before any request byte is written,
        # so the operation certainly did not run. It is also not something a
        # retry can fix (a rejected certificate stays rejected), so it is
        # definitively non-retryable rather than merely unknown.
        return Failure(
            FailureClass.NON_RETRYABLE,
            FailurePhase.PRE_WRITE,
            f"the TLS handshake failed ({type(error).__name__})",
        )
    if isinstance(error, ConnectionRefusedError):
        return Failure(FailureClass.RETRYABLE, FailurePhase.PRE_WRITE, "connection refused")
    if isinstance(error, socket.gaierror):
        return Failure(FailureClass.RETRYABLE, FailurePhase.PRE_WRITE, "name resolution failed")
    if isinstance(error, socket.timeout):
        # A connect-phase timeout never reached the peer. A read timeout did,
        # and is handled by the caller below.
        return Failure(FailureClass.RETRYABLE, FailurePhase.PRE_WRITE, "connection timed out")
    if isinstance(error, (ConnectionResetError, BrokenPipeError)):
        # Post-write: the peer may already have received the request.
        return Failure(
            FailureClass.NON_RETRYABLE,
            FailurePhase.POST_WRITE,
            "connection dropped after the request was written",
            may_have_executed=True,
        )
    if isinstance(error, OSError):
        code = error.errno
        if code in CONNECTION_ERROR_CODES:
            return Failure(FailureClass.RETRYABLE, FailurePhase.PRE_WRITE, f"connection error {errno.errorcode.get(code, code)}")
        if code in POST_WRITE_ERROR_CODES:
            return Failure(
                FailureClass.NON_RETRYABLE,
                FailurePhase.POST_WRITE,
                f"connection dropped after the request was written ({errno.errorcode.get(code, code)})",
                may_have_executed=True,
            )
        return Failure(FailureClass.UNKNOWN, FailurePhase.UNKNOWN, f"transport failure {type(error).__name__}")
    return Failure(FailureClass.UNKNOWN, FailurePhase.UNKNOWN, f"transport failure {type(error).__name__}")


@dataclass(frozen=True)
class Operation:
    """One outbound call, described well enough to be replayed safely.

    The idempotency *property* of a call is decided here, in code, at the
    call site -- never in a runbook, never in a comment on a dashboard.
    """

    #: The HTTP method, used to decide replay safety.
    method: str
    #: A stable digest of the request payload. A retry must carry the same
    #: digest; a mismatch means the "retry" is a different operation.
    payload_digest: str
    #: The client-supplied idempotency key, or None.
    idempotency_key: str | None = None
    #: False when the request body is a live stream that the first attempt
    #: consumes. A streamed body cannot be replayed without buffering it, so
    #: such a call gets exactly one attempt (E2B: ``isReadableStreamLike``).
    body_replayable: bool = True
    #: Whether repeating this call is acceptable *at all*. A create-with-side-
    #: effect sets this False when it has no idempotency key.
    replayable: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "idempotency_key", resolve_idempotency_key(self.idempotency_key))
        if not isinstance(self.method, str) or not self.method.strip():
            raise RetryContractError("method must be a non-empty string")
        if not isinstance(self.payload_digest, str) or not self.payload_digest.strip():
            raise RetryContractError("payload_digest must be a non-empty string")
        if self.body_replayable is False and self.replayable:
            # A streamed body cannot be replayed, so the operation may only be
            # attempted once. Make that explicit rather than implicit.
            object.__setattr__(self, "replayable", False)

    @property
    def replay_safe(self) -> bool:
        """Whether a retry of this call cannot double a side effect."""
        if not self.replayable:
            return False
        if not self.body_replayable:
            return False
        return operation_replay_safe(self.method, self.idempotency_key)

    def same_operation(self, other: "Operation") -> bool:
        """Whether ``other`` is the same operation as this one."""
        return (
            self.method.upper() == other.method.upper()
            and self.payload_digest == other.payload_digest
            and self.idempotency_key == other.idempotency_key
        )


@dataclass(frozen=True)
class Attempt:
    """One recorded attempt of a governed call."""

    index: int
    failure: Failure | None = None
    retryable: bool = False


@dataclass
class RetryOutcome:
    """The result of a governed call. Failures are data, never exceptions."""

    ok: bool
    #: The value the call returned, when it succeeded.
    value: Any = None
    #: The classified final failure, when the call did not succeed.
    failure: Failure | None = None
    #: The attempts made, in order.
    attempts: list[Attempt] = field(default_factory=list)
    #: True when the peer may already have executed the operation.
    may_have_executed: bool = False
    #: The final HTTP status, when the call produced one.
    status: int | None = None

    @property
    def attempts_made(self) -> int:
        return len(self.attempts)


def classify_http_result(
    status: int,
    headers: Mapping[str, str] | None = None,
    *,
    ok_statuses: frozenset[int] = frozenset(range(200, 300)),
) -> Failure | None:
    """Classify an HTTP result. ``None`` means the call succeeded.

    A 2xx is success. Anything else is a classified failure: retryable,
    non-retryable, or (for a 404/410) a confirmed-gone answer.
    """
    if status in ok_statuses:
        return None
    return classify_response(status, headers)


def _failed_outcome(failure: Failure, attempts: list[Attempt]) -> RetryOutcome:
    """The independent result for a call the contract will not retry again.

    ``ok`` is False -- a failure is never dressed up as a success -- and
    ``may_have_executed`` tells the caller whether the peer may already have
    done the thing. The caller then decides between resume and recreate.
    """
    return RetryOutcome(
        ok=False,
        value=None,
        failure=failure,
        attempts=attempts,
        may_have_executed=failure.may_have_executed,
        status=failure.status,
    )


class RetryContract:
    """Governs one outbound call under the retry/idempotency contract.

    The caller supplies a ``call`` that performs one attempt and returns
    either a value or raises. The contract decides whether to try again, and
    refuses to try again when the answer is not provably safe.

    The gate, in order:

    1. The failure must classify as ``RETRYABLE`` (E2B's rule).
    2. The operation must be ``replay_safe`` (idempotent method, or an
       idempotency key; never a streamed body).
    3. The retry must be the *same* operation: same key, same payload digest.
       A mismatch raises :class:`IdempotencyMismatchError` and resends
       nothing.
    4. The retry budget and the deadline must both allow another attempt.

    An indeterminate failure (unknown, or a post-write drop) is never
    retried and never reported as success: it is raised as
    :class:`TargetUnreachableError` with ``may_have_executed=True``.
    """

    def __init__(
        self,
        *,
        config: RetryContractConfig | None = None,
        sleep: Callable[[float], None] | None = None,
        random: Callable[[], float] | None = None,
        deadline_ms: int | None = None,
    ) -> None:
        self.config = config or DEFAULT_RETRY_CONFIG
        self._sleep = sleep if sleep is not None else (lambda ms: time.sleep(ms / 1000.0))
        self._random = random if random is not None else (lambda: 0.5)
        self._deadline_ms = deadline_ms

    def _deadline_exceeded(self, wait_ms: int) -> bool:
        if self._deadline_ms is None:
            return False
        return wait_ms >= self._deadline_ms

    def execute(
        self,
        operation: Operation,
        call: Callable[[Operation], Any],
        *,
        classify: Callable[[Any], Failure] | None = None,
    ) -> RetryOutcome:
        """Run ``call`` under the contract.

        ``classify`` maps the value ``call`` returned onto a
        :class:`Failure`; the default treats any returned value as success.
        A call that *raises* is classified by :func:`classify_exception`.

        The outcome is always returned, never raised: an unknown outcome is
        an independent result that the caller decides about, not a success
        and not a silent retry. Use :meth:`execute_strict` for the raising
        flavour.
        """
        attempts: list[Attempt] = []
        retry_index = 0
        while True:
            try:
                value = call(operation)
            except Exception as error:  # noqa: BLE001 - classification is the point
                failure = classify_exception(error)
                attempts.append(Attempt(index=len(attempts), failure=failure, retryable=failure.retryable))
                if not self._may_retry(operation, failure, retry_index):
                    return _failed_outcome(failure, attempts)
                wait_ms = self.config.delay_ms(retry_index + 1, self._random)
                if self._deadline_exceeded(wait_ms):
                    return _failed_outcome(failure, attempts)
                retry_index += 1
                self._sleep(wait_ms)
                continue

            failure = classify(value) if classify is not None else None
            if failure is None:
                attempts.append(Attempt(index=len(attempts), failure=None, retryable=False))
                return RetryOutcome(ok=True, value=value, attempts=attempts)
            attempts.append(Attempt(index=len(attempts), failure=failure, retryable=failure.retryable))
            if not self._may_retry(operation, failure, retry_index):
                return _failed_outcome(failure, attempts)
            wait_ms = self.config.delay_ms(retry_index + 1, self._random)
            if self._deadline_exceeded(wait_ms):
                return _failed_outcome(failure, attempts)
            retry_index += 1
            self._sleep(wait_ms)

    def execute_strict(
        self,
        operation: Operation,
        call: Callable[[Operation], Any],
        *,
        classify: Callable[[Any], Failure] | None = None,
    ) -> Any:
        """Like :meth:`execute`, but raises the terminal error.

        The raised type is what tells the caller what to do next:
        :class:`TargetGoneError` (recreate) vs :class:`TargetUnreachableError`
        (resume / probe).
        """
        outcome = self.execute(operation, call, classify=classify)
        if outcome.ok:
            return outcome.value
        failure = outcome.failure or Failure(FailureClass.UNKNOWN, FailurePhase.UNKNOWN, "call failed")
        raise _terminal_error(failure)

    def _may_retry(self, operation: Operation, failure: Failure, retry_index: int) -> bool:
        """Whether another attempt is allowed.

        Three gates, in order:

        1. the failure must be *retryable* (E2B's classification);
        2. the operation must be *replay-safe* (idempotent method or an
           idempotency key; never a streamed body);
        3. the retry budget must not be spent.
        """
        if failure.classification is not FailureClass.RETRYABLE:
            return False
        if not operation.replay_safe:
            return False
        return retry_index < self.config.max_retries


def _terminal_error(failure: Failure) -> RetryContractError:
    """Build the terminal error for a failure the contract will not retry."""
    message = failure.reason
    if failure.status is not None:
        message = f"{message} (HTTP {failure.status})"
    if failure.status in GONE_STATUSES:
        return TargetGoneError(message, may_have_executed=failure.may_have_executed)
    if failure.classification is FailureClass.UNKNOWN or failure.phase is FailurePhase.POST_WRITE:
        return TargetUnreachableError(message, may_have_executed=True)
    return TargetUnreachableError(message, may_have_executed=failure.may_have_executed)


def assert_same_operation(original: Operation, retry: Operation) -> None:
    """Refuse a retry that is not the same operation.

    Same key *and* same payload digest. A key that matches but a payload
    that differs means the second call is a different operation wearing the
    first operation's name; resending it would double an effect under a
    false identity.
    """
    if original.idempotency_key != retry.idempotency_key:
        raise IdempotencyMismatchError(
            "refusing to retry: the idempotency key changed between attempts"
        )
    if original.payload_digest != retry.payload_digest:
        raise IdempotencyMismatchError(
            "refusing to retry: the payload digest changed between attempts"
        )
    if original.method.upper() != retry.method.upper():
        raise IdempotencyMismatchError(
            "refusing to retry: the method changed between attempts"
        )
