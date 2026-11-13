"""Declarative retry configuration and call-kind classification.

Northstar's relay retries and fails over blindly. This module puts the two
rules that make a retry safe *in code*, where a call site cannot forget them:

1. **What kind of call is this?** (``CallKind``) -- a session-lifecycle call
   (create, reconnect) is idempotent and may be retried; a code-execution call
   carries no idempotency token and must never be silently re-executed.
2. **How long do we wait, and how many times?** (``RetryConfig``) -- a frozen,
   declarative configuration object, not a constant sprinkled over the call
   sites.

The source of the rule is Dynamiq (commit ``acc30e5``), read verbatim. The
crispest statement of it is a code comment in
``dynamiq/connections/agentcore.py`` (lines 105-108), reproduced here:

    # Disable botocore's built-in retries: the default legacy mode silently
    # re-sends failed requests up to 5 times, which for the non-idempotent
    # InvokeCodeInterpreter (executeCode/executeCommand carry no idempotency
    # token) could execute user code multiple times on a transient socket
    # error. Transient throttling on the idempotent session-lifecycle calls is
    # instead retried at the application level via tenacity.

Two consequences are load-bearing and are implemented literally below:

* **A throttle does not excuse a non-idempotent call.** Throttling is
  retryable *for idempotent calls only*. ``EXECUTION`` + a retryable failure
  is ``NEVER_RETRY``, with no exception for throttling.
* **An indeterminate outcome is never retried.** A post-write failure or a
  ``may_have_executed`` flag means the peer may already have run the call:
  the result is reported as unknown, not retried and not dressed up as
  success.

Verbatim from Dynamiq (this repository's ``dynamiq`` checkout, commit
``acc30e5``):

* ``dynamiq/nodes/tools/code_interpreter.py`` line 322,
  ``SandboxCreationErrorHandling``: ``max_retries=5``,
  ``initial_wait_seconds=2.0``, ``max_wait_seconds=32.0``,
  ``exponential_base=2.0``, ``jitter=1.0``. These are the defaults of
  :class:`RetryConfig` below, copied verbatim. They are *not* Northstar's
  invention, and the module says so where they are used.
* ``dynamiq/sandboxes/bedrock_agentcore.py`` ``_ensure_sandbox()``:
  double-checked locking "so concurrent threads never create duplicate
  sessions" -- the shape of :class:`SessionGuard`.
* ``dynamiq/sandboxes/bedrock_agentcore.py`` ``_create_with_retry()`` /
  ``_reconnect_with_retry()``: tenacity's ``wait_exponential_jitter`` with
  ``retry_if_exception_type(AgentCoreThrottlingError)`` -- retry the throttle,
  and only the throttle, on the idempotent lifecycle calls.
* ``dynamiq/sandboxes/bedrock_agentcore.py`` ``run_command_shell()``: because
  the provider has no per-invocation timeout, commands are wrapped in the
  ``timeout`` coreutils command and "a non-zero exit, e.g. 124, surfaces as a
  failed result". 124 is the convention used here too.

Northstar extensions (marked as such, not presented as Dynamiq's):

* The **window** semantics of jitter. Tenacity's
  ``wait_exponential_jitter`` draws from an RNG; a run here must be replayable
  from its audit record (the same rule ``retry_policy`` follows), so jitter is
  expressed as a declared ``(low, high)`` interval per step and is never
  sampled inside this module.
* :class:`RetryGate`, which binds classification to the schedule.
* :func:`run_with_timeout`, which makes the "the provider has no per-invocation
  timeout" gap into an explicit failed result instead of an unbounded wait.

Relation to the existing modules (all read-only; this module changes none of
them):

* ``retry_contract`` -- supplies the failure vocabulary. This module imports
  ``FailureClass``/``Failure``/``classify_exception``/``classify_response``
  from there and never copies the vocabulary.
* ``retry_policy`` -- the scheduling *shape* this module mirrors: bounded
  attempts, a deterministic schedule, an injectable sleeper, no wall-clock in
  the policy.
* ``provider_retry`` -- the provider-side fault vocabulary (``rate_limited``
  and friends). This module does not extend it; it reuses
  ``retry_contract``'s classification so there is one vocabulary.
* ``idempotency_manager`` -- the payload-bound idempotency ledger. A call that
  carries an idempotency key can be replayed *as the same operation*; a call
  that carries none cannot, which is why ``EXECUTION`` is never retried.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Mapping

from retry_contract import (
    Failure,
    FailureClass,
    FailurePhase,
    classify_exception,
    classify_response,
)

#: Module version.
RETRY_CONFIG_VERSION = "retry-config.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.retry-config.v1"

#: The exit code ``timeout(1)`` uses when the command it wrapped was killed.
#: Verbatim from Dynamiq: "a non-zero exit, e.g. 124, surfaces as a failed
#: result" (``dynamiq/sandboxes/bedrock_agentcore.py``).
EXIT_CODE_TIMEOUT = 124

#: The exit code used for a call that raised (as opposed to timing out).
EXIT_CODE_ERROR = 1


class RetryConfigError(ValueError):
    """A retry configuration is unusable. Raised at construction, never mid-run."""


@dataclass(frozen=True)
class WaitWindow:
    """The declared wait for one retry step, as an interval.

    ``nominal`` is the deterministic backoff for the step:
    ``min(initial_wait_seconds * exponential_base ** i, max_wait_seconds)``.
    ``low``/``high`` bound the window a jittering scheduler may pick from.

    The interval is *declared*, never sampled here: the same configuration
    always produces the same schedule, so a run replays from its audit record.
    """

    nominal: float
    low: float
    high: float

    def as_dict(self) -> dict[str, Any]:
        return {"nominal": self.nominal, "low": self.low, "high": self.high}


@dataclass(frozen=True)
class RetryConfig:
    """Declarative retry configuration -- the retry table as data.

    The defaults are **Dynamiq's**, copied verbatim from
    ``dynamiq/nodes/tools/code_interpreter.py`` line 322
    (``SandboxCreationErrorHandling``): ``max_retries=5``,
    ``initial_wait_seconds=2.0``, ``max_wait_seconds=32.0``,
    ``exponential_base=2.0``, ``jitter=1.0``. They are not Northstar's
    invention and are not tuned here.

    Validation is fail-closed: a configuration that does not make sense is
    refused at construction, not silently repaired at call time.

    * ``max_retries`` -- extra attempts after the first one; ``>= 0``.
    * ``initial_wait_seconds`` -- the first backoff; ``> 0``.
    * ``max_wait_seconds`` -- the ceiling; ``>= initial_wait_seconds``.
    * ``exponential_base`` -- the growth factor; in ``[1.0, 4.0]``.
    * ``jitter`` -- the width of the declared wait window; in ``[0.0, 1.0]``.
    """

    max_retries: int = 5
    initial_wait_seconds: float = 2.0
    max_wait_seconds: float = 32.0
    exponential_base: float = 2.0
    jitter: float = 1.0

    def __post_init__(self) -> None:
        if isinstance(self.max_retries, bool) or not isinstance(self.max_retries, int):
            raise RetryConfigError("max_retries must be an integer")
        if self.max_retries < 0:
            raise RetryConfigError("max_retries must be >= 0")
        for name in ("initial_wait_seconds", "max_wait_seconds"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise RetryConfigError(f"{name} must be a number")
            if value <= 0:
                raise RetryConfigError(f"{name} must be > 0")
        if self.max_wait_seconds < self.initial_wait_seconds:
            raise RetryConfigError("max_wait_seconds must be >= initial_wait_seconds")
        if isinstance(self.exponential_base, bool) or not isinstance(self.exponential_base, (int, float)):
            raise RetryConfigError("exponential_base must be a number")
        if not 1.0 <= float(self.exponential_base) <= 4.0:
            raise RetryConfigError("exponential_base must be between 1.0 and 4.0")
        if isinstance(self.jitter, bool) or not isinstance(self.jitter, (int, float)):
            raise RetryConfigError("jitter must be a number")
        if not 0.0 <= float(self.jitter) <= 1.0:
            raise RetryConfigError("jitter must be between 0.0 and 1.0")

    # -- serialisation -----------------------------------------------------
    #: The keys ``from_dict`` accepts. Unknown keys are refused: a typo in a
    #: retry table looks exactly like a working retry table.
    KEYS = ("max_retries", "initial_wait_seconds", "max_wait_seconds", "exponential_base", "jitter")

    def to_dict(self) -> dict[str, Any]:
        """The configuration as plain data."""
        return {name: getattr(self, name) for name in self.KEYS}

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> "RetryConfig":
        """Build a configuration from plain data.

        Unknown keys are refused rather than ignored, and the values are
        validated by the same fail-closed rules a direct construction gets.
        """
        if not isinstance(document, Mapping):
            raise RetryConfigError("a retry configuration must be a mapping")
        unknown = sorted(set(document) - set(cls.KEYS))
        if unknown:
            raise RetryConfigError(
                f"unknown retry configuration key(s) {', '.join(unknown)} - "
                f"allowed: {', '.join(cls.KEYS)}"
            )
        return cls(**{name: document[name] for name in cls.KEYS if name in document})

    # -- schedule ----------------------------------------------------------
    def nominal_waits(self) -> tuple[float, ...]:
        """The deterministic backoff of every step, in seconds.

        ``wait_i = min(initial_wait_seconds * exponential_base ** i,
        max_wait_seconds)`` for ``i`` in ``0 .. max_retries - 1``.
        """
        return tuple(
            min(float(self.initial_wait_seconds) * (float(self.exponential_base) ** index),
                float(self.max_wait_seconds))
            for index in range(self.max_retries)
        )

    def schedule(self) -> tuple[WaitWindow, ...]:
        """The full wait schedule: one declared window per retry step.

        The window is ``[nominal * (1 - jitter), nominal]``: ``jitter = 0``
        declares an exact wait, ``jitter = 1`` declares "anywhere up to the
        nominal". The nominal is already capped at ``max_wait_seconds``, so no
        window can promise more than the configured ceiling.

        Deterministic: the same configuration always yields the same
        schedule. Nothing here samples a random number or reads a clock.
        """
        windows: list[WaitWindow] = []
        for nominal in self.nominal_waits():
            low = nominal * (1.0 - float(self.jitter))
            windows.append(WaitWindow(nominal=nominal, low=low, high=nominal))
        return tuple(windows)

    def as_dict(self) -> dict[str, Any]:
        """The configuration as an auditable record."""
        payload = self.to_dict()
        payload["schema"] = SCHEMA_PIN
        payload["version"] = RETRY_CONFIG_VERSION
        return payload


class CallKind(str, Enum):
    """What kind of call this is -- and therefore whether it may be repeated.

    The classification is decided *in code*, at the call site, and never in a
    runbook. The three kinds are:

    ``SESSION_LIFECYCLE``
        Creating or reconnecting a session. Idempotent: repeating it cannot
        double an effect, so a transient throttle is retried at the
        application level (Dynamiq's ``_create_with_retry`` /
        ``_reconnect_with_retry``).
    ``EXECUTION``
        Running user code. Non-idempotent: it carries no idempotency token,
        so repeating it can execute the user's code more than once. Never
        retried.
    ``UNKNOWN``
        We cannot tell what kind of call this is. Fail-closed: treated as
        non-idempotent, because "we could not tell" is not permission to
        repeat a side effect.
    """

    SESSION_LIFECYCLE = "session_lifecycle"
    EXECUTION = "execution"
    UNKNOWN = "unknown"

    @property
    def idempotent(self) -> bool:
        """Whether repeating a call of this kind is safe.

        Only ``SESSION_LIFECYCLE`` is idempotent. ``UNKNOWN`` is fail-closed
        and answers False.
        """
        return self is CallKind.SESSION_LIFECYCLE


class RetryDecision(str, Enum):
    """What the gate decided to do about a failed call."""

    #: The call may be tried again, and the budget allows it.
    RETRY = "retry"
    #: The call must not be tried again. The outcome is definite (the call did
    #: not run) -- or is at least not repeatable.
    NEVER_RETRY = "never_retry"
    #: The call must not be tried again, and the outcome is *unknown*: the
    #: peer may already have executed it. Reported as an unknown result, never
    #: as a success.
    INDETERMINATE = "indeterminate"


@dataclass(frozen=True)
class RetryVerdict:
    """The gate's answer for one failed call."""

    decision: RetryDecision
    kind: CallKind
    failure_class: FailureClass
    #: Why the gate decided this. Kept in the record so an audit reader can see
    #: the rule that fired, not just the outcome.
    reason: str
    #: Whether the peer may already have executed the call. True for an
    #: indeterminate outcome; the caller then has to choose between resume and
    #: recreate.
    may_have_executed: bool = False
    #: The wait window for the next attempt, when the decision is ``RETRY``.
    window: WaitWindow | None = None

    @property
    def should_retry(self) -> bool:
        return self.decision is RetryDecision.RETRY

    def as_dict(self) -> dict[str, Any]:
        payload = {
            "schema": SCHEMA_PIN,
            "decision": self.decision.value,
            "kind": self.kind.value,
            "failure_class": self.failure_class.value,
            "reason": self.reason,
            "may_have_executed": self.may_have_executed,
        }
        if self.window is not None:
            payload["window"] = self.window.as_dict()
        return payload


def classify_call(
    kind: CallKind | str,
    failure: Failure | FailureClass | BaseException,
    *,
    attempt: int = 0,
    config: RetryConfig | None = None,
) -> RetryVerdict:
    """Decide what may happen to a failed call.

    The gates, in order:

    1. **Indeterminate first.** A post-write failure, or one carrying
       ``may_have_executed``, is ``INDETERMINATE``: the peer may already have
       run the call, so it is never retried and never reported as success.
    2. **Idempotency next.** A non-idempotent kind -- ``EXECUTION``, or
       ``UNKNOWN`` (fail-closed) -- is ``NEVER_RETRY`` for *any* failure,
       throttling included. This is the AgentCore comment read literally:
       the throttle retry applies to the idempotent session-lifecycle calls.
    3. **Classification next.** A failure that is not ``RETRYABLE`` is
       ``NEVER_RETRY``.
    4. **Budget last.** A retryable, idempotent failure with the budget spent
       is ``NEVER_RETRY``.

    ``failure`` may be a :class:`~retry_contract.Failure`, a bare
    :class:`~retry_contract.FailureClass`, or an exception -- an exception is
    classified by ``retry_contract.classify_exception``, so the failure
    vocabulary is never copied here.
    """
    if isinstance(kind, str):
        try:
            kind = CallKind(kind)
        except ValueError:
            kind = CallKind.UNKNOWN
    settings = config if config is not None else RetryConfig()

    if isinstance(failure, Failure):
        resolved = failure
    elif isinstance(failure, FailureClass):
        resolved = Failure(classification=failure, phase=FailurePhase.UNKNOWN, reason=str(failure))
    elif isinstance(failure, BaseException):
        resolved = classify_exception(failure)
    else:
        raise RetryConfigError(
            "failure must be a Failure, a FailureClass or an exception, got "
            f"{type(failure).__name__}"
        )

    # 1. Indeterminate: never retried, never reported as success.
    if resolved.may_have_executed or resolved.phase is FailurePhase.POST_WRITE:
        return RetryVerdict(
            decision=RetryDecision.INDETERMINATE,
            kind=kind,
            failure_class=resolved.classification,
            reason=(
                "the call may already have executed (post-write failure); "
                "it is never retried and reported as an unknown outcome"
            ),
            may_have_executed=True,
        )

    # 2. Idempotency. A throttle does not excuse a non-idempotent call.
    if not kind.idempotent:
        reason = (
            "throttling does not excuse a non-idempotent call: "
            "repeating it could execute the operation more than once"
            if kind is CallKind.EXECUTION
            else "the call kind is unknown, which is fail-closed: treated as non-idempotent"
        )
        return RetryVerdict(
            decision=RetryDecision.NEVER_RETRY,
            kind=kind,
            failure_class=resolved.classification,
            reason=reason,
        )

    # 3. Classification.
    if resolved.classification is not FailureClass.RETRYABLE:
        return RetryVerdict(
            decision=RetryDecision.NEVER_RETRY,
            kind=kind,
            failure_class=resolved.classification,
            reason=f"the failure is not retryable ({resolved.reason})",
        )

    # 4. Budget.
    if attempt >= settings.max_retries:
        return RetryVerdict(
            decision=RetryDecision.NEVER_RETRY,
            kind=kind,
            failure_class=resolved.classification,
            reason=f"the retry budget is spent ({attempt} of {settings.max_retries} used)",
        )

    windows = settings.schedule()
    return RetryVerdict(
        decision=RetryDecision.RETRY,
        kind=kind,
        failure_class=resolved.classification,
        reason=f"the call is idempotent and the failure is retryable ({resolved.reason})",
        window=windows[attempt],
    )


@dataclass
class GateOutcome:
    """What a governed call produced.

    ``ok`` is False for every failure: a failure is never dressed up as a
    success. ``value`` holds the successful result, if any.
    """

    ok: bool
    value: Any = None
    #: How many attempts were actually made.
    attempts: int = 0
    #: The waits that were declared, in order. Empty when nothing was retried.
    windows: tuple[WaitWindow, ...] = ()
    #: The gate's verdicts, one per failed attempt.
    verdicts: tuple[RetryVerdict, ...] = ()
    #: The final verdict, when the call did not succeed.
    verdict: RetryVerdict | None = None
    #: The classified final failure.
    failure: Failure | None = None
    #: True when the peer may already have executed the call.
    may_have_executed: bool = False

    def as_dict(self) -> dict[str, Any]:
        payload = {
            "schema": SCHEMA_PIN,
            "ok": self.ok,
            "attempts": self.attempts,
            "may_have_executed": self.may_have_executed,
        }
        if self.failure is not None:
            payload["failure_class"] = self.failure.classification.value
            payload["reason"] = self.failure.reason
        if self.verdict is not None:
            payload["decision"] = self.verdict.decision.value
        return payload


class RetryGate:
    """Runs a call under the call-kind rules and the declarative config.

    This is the object that binds the two halves together: the *classification*
    decides whether another attempt is allowed, and the *configuration* decides
    how long to wait before it. Neither half can be used without the other --
    a caller cannot ask for "one more attempt" without a declared schedule.

    The sleeper is injectable (seconds, ``time.sleep``-shaped), so a test can
    assert the exact wait sequence without waiting and a run replays from its
    record.
    """

    def __init__(
        self,
        config: RetryConfig | None = None,
        *,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        self.config = config if config is not None else RetryConfig()
        self._sleep = sleep if sleep is not None else time.sleep

    def execute(
        self,
        kind: CallKind | str,
        call: Callable[[], Any],
        *,
        classify: Callable[[Any], Failure] | None = None,
    ) -> GateOutcome:
        """Run ``call`` under the gate.

        ``call`` performs one attempt and either returns a value or raises.
        A returned value is a success unless ``classify`` maps it onto a
        :class:`~retry_contract.Failure`; a raised exception is classified by
        ``retry_contract.classify_exception``.

        The outcome is always returned, never raised. A call that must not be
        repeated is not repeated -- not even once, and not even on a throttle.
        """
        windows: list[WaitWindow] = []
        verdicts: list[RetryVerdict] = []
        attempt = 0
        while True:
            try:
                value = call()
            except Exception as error:  # noqa: BLE001 - classification is the point
                failure = classify_exception(error)
                attempt += 1
                # ``attempt`` counts the attempts made so far; the budget is
                # compared against the retries already spent, so the first
                # failure asks for retry #0.
                verdict = classify_call(
                    kind, failure, attempt=attempt - 1, config=self.config
                )
                verdicts.append(verdict)
                if verdict.decision is not RetryDecision.RETRY or verdict.window is None:
                    return GateOutcome(
                        ok=False,
                        attempts=attempt,
                        windows=tuple(windows),
                        verdicts=tuple(verdicts),
                        verdict=verdict,
                        failure=failure,
                        may_have_executed=verdict.may_have_executed or failure.may_have_executed,
                    )
                windows.append(verdict.window)
                self._sleep(verdict.window.nominal)
                continue

            if classify is not None:
                failure = classify(value)
                if failure is not None:
                    attempt += 1
                    verdict = classify_call(
                        kind, failure, attempt=attempt - 1, config=self.config
                    )
                    verdicts.append(verdict)
                    if verdict.decision is not RetryDecision.RETRY or verdict.window is None:
                        return GateOutcome(
                            ok=False,
                            attempts=attempt,
                            windows=tuple(windows),
                            verdicts=tuple(verdicts),
                            verdict=verdict,
                            failure=failure,
                            may_have_executed=verdict.may_have_executed or failure.may_have_executed,
                        )
                    windows.append(verdict.window)
                    self._sleep(verdict.window.nominal)
                    continue
            return GateOutcome(ok=True, value=value, attempts=attempt + 1, windows=tuple(windows))


class SessionGuard:
    """Create a session at most once, even under concurrency.

    Verbatim from Dynamiq (``dynamiq/sandboxes/bedrock_agentcore.py``,
    ``_ensure_sandbox()``): "Uses double-checked locking so concurrent threads
    never create duplicate sessions."

    The same shape is implemented here with a plain ``threading.Lock``:

    * the fast path reads the cached session without taking the lock;
    * the slow path takes the lock, re-checks the cache, and creates;
    * concurrent callers share the one created session;
    * a *failed* creation releases the guard -- no half-made session is
      cached -- so the next caller may try again. Creating a session is an
      idempotent lifecycle call, so retrying it is safe.
    """

    def __init__(self, create_fn: Callable[[], Any]) -> None:
        if not callable(create_fn):
            raise RetryConfigError("create_fn must be callable")
        self._create_fn = create_fn
        self._lock = threading.Lock()
        self._session: Any = None
        self._created = False
        #: How many times ``create_fn`` was actually called. The proof that the
        #: guard works.
        self.create_calls = 0

    @property
    def created(self) -> bool:
        """Whether a session has been created (successfully) by this guard."""
        return self._created

    def get(self) -> Any:
        """Return the session, creating it at most once."""
        if self._created:
            return self._session
        with self._lock:
            if self._created:
                return self._session
            self.create_calls += 1
            session = self._create_fn()
            self._session = session
            self._created = True
            return session


@dataclass(frozen=True)
class TimeoutResult:
    """The result of a call that was wrapped in a timeout.

    A timeout is a *failed result*, never a silent hang and never a success.
    ``exit_code`` is 124 -- the ``timeout(1)`` convention, verbatim from
    Dynamiq's ``run_command_shell()``.
    """

    ok: bool
    exit_code: int
    value: Any = None
    error: str | None = None
    timed_out: bool = False

    def as_dict(self) -> dict[str, Any]:
        payload = {
            "schema": SCHEMA_PIN,
            "ok": self.ok,
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
        }
        if self.error is not None:
            payload["error"] = self.error
        return payload


def run_with_timeout(
    call: Callable[[], Any],
    timeout_seconds: float,
) -> TimeoutResult:
    """Run ``call`` under a timeout, turning a hang into a failed result.

    Dynamiq's ``run_command_shell()`` wraps the command in the ``timeout``
    coreutils command because "AgentCore has no per-invocation timeout
    parameter", and notes that "a non-zero exit, e.g. 124, surfaces as a
    failed result". This function is the in-process equivalent: the call runs
    on its own thread and the caller waits at most ``timeout_seconds``.

    A call that finishes in time returns its value with ``ok=True`` and
    ``exit_code=0``. A call that times out returns ``ok=False``,
    ``exit_code=124``, ``timed_out=True`` -- a failure result, never a
    success and never an unbounded wait. A call that raises returns
    ``ok=False``, ``exit_code=1``.

    No wall-clock time is recorded in the result: the record says *what*
    happened, not *when*.
    """
    if not callable(call):
        raise RetryConfigError("call must be callable")
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)):
        raise RetryConfigError("timeout_seconds must be a number")
    if timeout_seconds <= 0:
        raise RetryConfigError("timeout_seconds must be > 0")

    box: dict[str, Any] = {}

    def runner() -> None:
        try:
            box["value"] = call()
        except BaseException as error:  # noqa: BLE001 - reported as a result
            box["error"] = error

    worker = threading.Thread(target=runner, daemon=True)
    worker.start()
    worker.join(timeout_seconds)

    if worker.is_alive():
        return TimeoutResult(
            ok=False,
            exit_code=EXIT_CODE_TIMEOUT,
            error=f"the call did not finish within {timeout_seconds} seconds",
            timed_out=True,
        )
    if "error" in box:
        error = box["error"]
        return TimeoutResult(
            ok=False,
            exit_code=EXIT_CODE_ERROR,
            error=f"{type(error).__name__}: {error}",
        )
    return TimeoutResult(ok=True, exit_code=0, value=box.get("value"))


def main() -> None:
    """Self-check: the classification matrix and the schedule."""
    config = RetryConfig()
    assert config.max_retries == 5
    assert config.schedule()[0].nominal == 2.0
    assert config.schedule()[-1].nominal == 32.0

    throttled = classify_response(429)
    assert classify_call(CallKind.SESSION_LIFECYCLE, throttled).decision is RetryDecision.RETRY
    assert classify_call(CallKind.EXECUTION, throttled).decision is RetryDecision.NEVER_RETRY
    assert classify_call(CallKind.UNKNOWN, throttled).decision is RetryDecision.NEVER_RETRY

    print("retry-config OK: config validated, schedule deterministic, kinds classified")


if __name__ == "__main__":
    main()
