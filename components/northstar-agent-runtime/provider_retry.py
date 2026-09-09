"""The retry budget: what a transient provider fault means, and what it costs.

Before this module existed, retries were *somebody else's* policy. Both providers
passed ``max_retries`` to their SDK client, which meant the request count of a run was
the product of two loops nobody had read together, ``Retry-After`` was honoured by a
library with its own ceiling, and no event, span, or transcript said that turn 2 took
four HTTP requests and waited eleven seconds. A run bounded by ``max_turns`` and
``max_tool_calls`` is not bounded in the way its policy claims if the transport under it
retries without a limit that anyone reviewed.

Three rules hold this together:

* **Classification is explicit and closed.** :data:`FAILURE_CLASSES` names every fault a
  provider may produce, and the taxonomy decides *retry or stop* - not the message text,
  not a library default. ``unknown`` is deliberately not retryable: treating "we could not
  tell" as "transient" turns every bug into a request storm against the thing that is
  already failing.
* **The schedule is a pure function.** :meth:`RetryPolicy.plan` maps ``(attempt, failure,
  waited)`` to a delay or a stop, with no clock and no sleep inside it, so the whole
  policy is testable as a table of numbers. :func:`execute` is the only part that touches
  time, and it takes ``sleep`` and ``monotonic`` as arguments for exactly that reason.
* **Waiting is visible.** Every retry yields an :class:`AttemptRecord` to the caller (the
  loop turns it into an informational event and a span attribute), the total wait is
  carried in the run's summary, and ``--dry-run`` prints the policy before a token is
  spent - including ``planned_wait_ms()``, the worst case a run could sit still for.

Jitter is real but *seeded*: full jitter draws from ``random.Random(seed)`` where the seed
comes from the run, not from the wall clock, so CI can pin a schedule while a fleet of
retries still does not synchronise on the same 429 window.
"""
from __future__ import annotations

import random
import re
from dataclasses import dataclass, field
from dataclasses import replace
from typing import Any, Callable, Iterable, Mapping

#: The identity of the ``[retry]`` table, mirrored from the policy document's versioning
#: habit: a table shape we may refuse is better than one we silently misread.
RETRY_SCHEMA_VERSION = "northstar.retry.v1"

#: Ceilings on the policy itself, not on the workspace. ``MAX_ATTEMPTS`` exists because a
#: "retry forever" knob has no honest use; the delay and deadline caps exist because a run
#: that sleeps for an hour inside turn 2 is not the run anybody approved.
MAX_ATTEMPTS = 8
MAX_DELAY_MS = 120_000
MAX_DEADLINE_MS = 900_000

DEFAULT_MAX_ATTEMPTS = 3
DEFAULT_BASE_DELAY_MS = 250
DEFAULT_MULTIPLIER = 2.0
DEFAULT_MAX_DELAY_MS = 20_000
DEFAULT_DEADLINE_MS = 60_000

#: Every fault this runtime can name. Closed on purpose: a fault that is not here has to be
#: added here, with a decision about whether it is retryable, instead of being quietly
#: swallowed by a wildcard.
FAILURE_CLASSES: tuple[str, ...] = (
    "rate_limited",       # 429 - the provider asked us to come back
    "overloaded",         # 529 / 503 - the provider is full, not wrong
    "network",            # connection reset, DNS, socket closed mid-response
    "timeout",            # our own read timeout fired
    "server_error",       # 5xx that is not an overload signal
    "context_overflow",   # 413 / "prompt is too long": a request problem, not a load one
    "auth",               # 401 / 403: no retry fixes a credential
    "client_error",       # 400 / 404 / 422: the request is wrong; repeating it is rude
    "stream_interrupted", # the connection died after text was already forwarded
    "unknown",            # we could not classify it, which is not the same as transient
)

#: The faults :meth:`RetryPolicy.plan` may act on by default. ``context_overflow`` is
#: absent because the honest response to "too long" is the degradation ladder
#: (:attr:`RetryPolicy.on_context_overflow`), not the same request again.
RETRYABLE_CLASSES: tuple[str, ...] = ("rate_limited", "overloaded", "network", "timeout", "server_error")

#: Never retryable, whatever a config file claims. A broken stream has already shown the
#: operator text; re-issuing the request re-shows it, and "the transcript and the terminal
#: disagree" is the one failure mode the streaming contract exists to prevent.
NEVER_RETRYABLE_CLASSES: tuple[str, ...] = ("stream_interrupted", "auth", "client_error", "unknown")

#: A retry policy is a transport knob, so its keys are its own; they are not the policy
#: document's ceilings and a bundle has no claim on them (see plugin_manifest).
ALLOWED_RETRY_KEYS = frozenset({
    "schema_version",
    "max_attempts",
    "base_delay_ms",
    "multiplier",
    "max_delay_ms",
    "deadline_ms",
    "jitter",
    "retry_on",
    "respect_retry_after",
    "on_context_overflow",
})

JITTER_MODES: tuple[str, ...] = ("none", "full")
#: What a run may do when the provider says the request is too big. ``fail`` is the default
#: because compaction rewrites what the model is shown, and that should be a choice rather
#: than a side effect of a transport fault. There is no ``fallback_model`` on purpose:
#: handing the request to a *different model* changes who is answering, which is a policy
#: decision with its own costs (pricing, capability, audit attribution) and does not belong
#: in a retry table. Degrade the request, never the identity of the answerer.
CONTEXT_OVERFLOW_ACTIONS: tuple[str, ...] = ("fail", "compact_once")


class RetryConfigurationError(ValueError):
    """The retry table is unusable. Raised at load, never mid-run."""


@dataclass(frozen=True)
class ProviderFault:
    """One classified provider failure."""

    kind: str
    retry_after_ms: int | None = None
    detail: str = ""
    #: Provider-reported HTTP status, kept for the event line and for tests: the class is
    #: what the policy reads, the status is what a human verifies against a request log.
    status_code: int | None = None

    def __post_init__(self) -> None:
        if self.kind not in FAILURE_CLASSES:
            raise RetryConfigurationError(
                f"unknown failure class {self.kind!r}; this runtime classifies faults as: {', '.join(FAILURE_CLASSES)}"
            )

    @property
    def retryable_by_default(self) -> bool:
        return self.kind in RETRYABLE_CLASSES

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"kind": self.kind}
        if self.status_code is not None:
            payload["status_code"] = self.status_code
        if self.retry_after_ms is not None:
            payload["retry_after_ms"] = self.retry_after_ms
        if self.detail:
            payload["detail"] = self.detail[:200]
        return payload


@dataclass(frozen=True)
class AttemptRecord:
    """What happened between two provider calls: the fault, the wait, the next attempt."""

    attempt: int                  # the attempt that just failed (1-based)
    max_attempts: int
    kind: str
    delay_ms: int
    waited_ms: int                # total waited so far, this delay included
    detail: str = ""
    #: Set when the provider's own instruction was overridden, and why. Silence here would
    #: mean "we did what it said", which is worth being able to assert either way.
    note: str = ""

    def as_dict(self) -> dict[str, Any]:
        payload = {
            "attempt": self.attempt,
            "max_attempts": self.max_attempts,
            "kind": self.kind,
            "delay_ms": self.delay_ms,
            "waited_ms": self.waited_ms,
        }
        if self.detail:
            payload["detail"] = self.detail[:200]
        if self.note:
            payload["note"] = self.note
        return payload

    def line(self) -> str:
        """The operator-facing sentence, used by the loop's informational event."""
        detail = f" ({self.detail})" if self.detail else ""
        note = f"; {self.note}" if self.note else ""
        return (
            f"attempt {self.attempt}/{self.max_attempts} failed: {self.kind}{detail} - "
            f"retrying in {self.delay_ms} ms (waited {self.waited_ms} ms so far){note}"
        )


@dataclass(frozen=True)
class RetryPolicy:
    """How many times, how long apart, and until when.

    ``max_attempts`` counts *calls*, so ``1`` means "no retry" and is the value a
    cost-sensitive operator sets deliberately; ``deadline_ms`` is a wall-clock budget for
    waiting only - the request time itself is the provider's to bound (its own timeout),
    because a runtime that also cancels in-flight requests would be guessing how long a
    stream should take.
    """

    schema_version: str = RETRY_SCHEMA_VERSION
    max_attempts: int = DEFAULT_MAX_ATTEMPTS
    base_delay_ms: int = DEFAULT_BASE_DELAY_MS
    multiplier: float = DEFAULT_MULTIPLIER
    max_delay_ms: int = DEFAULT_MAX_DELAY_MS
    deadline_ms: int = DEFAULT_DEADLINE_MS
    jitter: str = "full"
    retry_on: tuple[str, ...] = RETRYABLE_CLASSES
    respect_retry_after: bool = True
    on_context_overflow: str = "fail"
    #: Seed for full jitter. The loop sets this from the run id so a given run replays the
    #: same schedule; ``None`` means "derive nothing", which is only reachable for a policy
    #: built without a run.
    seed: int | None = None
    #: Injected by a caller that must not sleep (tests, and any embedder with its own clock).
    sleeper: Callable[[float], None] | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.schema_version != RETRY_SCHEMA_VERSION:
            raise RetryConfigurationError(
                f"retry schema_version {self.schema_version!r} is not supported; this runtime reads {RETRY_SCHEMA_VERSION!r}"
            )
        if isinstance(self.max_attempts, bool) or not isinstance(self.max_attempts, int) or not 1 <= self.max_attempts <= MAX_ATTEMPTS:
            raise RetryConfigurationError(f"max_attempts must be an integer between 1 and {MAX_ATTEMPTS}; it counts calls, so 1 means no retry")
        for name, cap in (("base_delay_ms", MAX_DELAY_MS), ("max_delay_ms", MAX_DELAY_MS), ("deadline_ms", MAX_DEADLINE_MS)):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > cap:
                raise RetryConfigurationError(f"{name} must be an integer between 0 and {cap} ms, got {value!r}")
        if self.base_delay_ms > self.max_delay_ms:
            raise RetryConfigurationError("base_delay_ms is above max_delay_ms; the schedule would start past its own ceiling")
        if not isinstance(self.multiplier, (int, float)) or isinstance(self.multiplier, bool) or not 1.0 <= float(self.multiplier) <= 10.0:
            raise RetryConfigurationError("multiplier must be between 1.0 (no growth) and 10.0")
        if self.jitter not in JITTER_MODES:
            raise RetryConfigurationError(f"jitter must be one of: {', '.join(JITTER_MODES)}")
        if self.on_context_overflow not in CONTEXT_OVERFLOW_ACTIONS:
            raise RetryConfigurationError(f"on_context_overflow must be one of: {', '.join(CONTEXT_OVERFLOW_ACTIONS)}")
        unknown = sorted(set(self.retry_on) - set(FAILURE_CLASSES))
        if unknown:
            raise RetryConfigurationError(
                f"retry_on names faults this runtime cannot classify: {', '.join(unknown)}; known: {', '.join(FAILURE_CLASSES)}"
            )
        forbidden = sorted(set(self.retry_on) & set(NEVER_RETRYABLE_CLASSES))
        if forbidden:
            raise RetryConfigurationError(
                f"retry_on may not include {', '.join(forbidden)}: "
                + (
                    "a retry of a broken stream re-shows text the terminal already printed, and the "
                    "transcript/terminal agreement is not negotiable. "
                    if "stream_interrupted" in forbidden
                    else ""
                )
                + "auth and client_error faults are fixed by changing the request, not by sending it again; "
                "an unknown fault is not evidence that a retry would help."
            )

    # -- construction -------------------------------------------------------
    @classmethod
    def from_mapping(cls, document: Mapping[str, Any] | None, *, seed: int | None = None) -> "RetryPolicy | None":
        """Parse a ``[retry]`` table, or return ``None`` when the workspace has no opinion.

        Unknown keys are refused rather than ignored: a typo in a retry table looks exactly
        like a working retry table.
        """
        if document is None:
            return None
        if not isinstance(document, Mapping):
            raise RetryConfigurationError("the [retry] table must be a TOML table")
        unknown = sorted(set(document) - ALLOWED_RETRY_KEYS)
        if unknown:
            raise RetryConfigurationError(
                f"[retry]: unknown key(s) {', '.join(unknown)} - allowed: {', '.join(sorted(ALLOWED_RETRY_KEYS))}"
            )
        kwargs: dict[str, Any] = {"seed": seed}
        if "schema_version" in document:
            kwargs["schema_version"] = str(document["schema_version"])
        for name in ("max_attempts", "base_delay_ms", "max_delay_ms", "deadline_ms"):
            if name in document:
                kwargs[name] = document[name]
        if "multiplier" in document:
            kwargs["multiplier"] = document["multiplier"]
        if "jitter" in document:
            kwargs["jitter"] = str(document["jitter"])
        if "retry_on" in document:
            raw = document["retry_on"]
            if not isinstance(raw, (list, tuple)) or not all(isinstance(item, str) for item in raw):
                raise RetryConfigurationError("[retry] retry_on must be an array of failure class names")
            kwargs["retry_on"] = tuple(str(item) for item in raw)
        for name in ("respect_retry_after",):
            if name in document:
                value = document[name]
                if not isinstance(value, bool):
                    raise RetryConfigurationError(f"[retry] {name} must be a boolean")
                kwargs[name] = value
        if "on_context_overflow" in document:
            kwargs["on_context_overflow"] = str(document["on_context_overflow"])
        return cls(**kwargs)

    def restrict(self, other: "RetryPolicy | None") -> "RetryPolicy":
        """Clamp this policy to no looser than ``other`` (the workspace's own table).

        The CLI may tighten what a repository asked for and never loosen it, which is the
        same rule every other ceiling in this component follows. A flag cannot be used to
        turn "this repo waits at most twice" into "wait eight times".
        """
        if other is None:
            return self
        retry_on = tuple(kind for kind in self.retry_on if kind in other.retry_on)
        return RetryPolicy(
            schema_version=self.schema_version,
            max_attempts=min(self.max_attempts, other.max_attempts),
            base_delay_ms=max(self.base_delay_ms, other.base_delay_ms),
            multiplier=min(self.multiplier, other.multiplier),
            max_delay_ms=min(self.max_delay_ms, other.max_delay_ms),
            deadline_ms=min(self.deadline_ms, other.deadline_ms),
            # The workspace owns the *shape* of the schedule; the CLI owns whether to use it.
            jitter=other.jitter,
            # An empty intersection is a legitimate outcome, and it means "no retries": a
            # workspace that only ever retries on rate limits cannot be talked into retrying
            # timeouts by a command-line flag.
            retry_on=retry_on,
            respect_retry_after=self.respect_retry_after and other.respect_retry_after,
            # Degrading the request is allowed to be *stricter* on one side only: if either
            # the workspace or the operator said "fail", it fails.
            on_context_overflow="compact_once" if (self.on_context_overflow, other.on_context_overflow) == ("compact_once", "compact_once") else "fail",
            seed=self.seed if self.seed is not None else other.seed,
            sleeper=self.sleeper or other.sleeper,
        )

    # -- the schedule, as data ---------------------------------------------
    @property
    def enabled(self) -> bool:
        return self.max_attempts > 1 and bool(self.retry_on)

    def _ceiling(self, attempt: int) -> int:
        """The un-jittered delay for the pause *after* ``attempt`` (1-based)."""
        delay = float(self.base_delay_ms) * (float(self.multiplier) ** (attempt - 1))
        return int(min(delay, self.max_delay_ms))

    def _draw(self, ceiling_ms: int) -> int:
        if self.jitter != "full" or ceiling_ms <= 1:
            return ceiling_ms
        rng = random.Random(None if self.seed is None else self.seed + ceiling_ms)
        # Full jitter (the AWS-recommended shape): uniform on [base/2, ceiling] rather
        # than [0, ceiling], because a policy that can choose ~0 ms has to be allowed to,
        # but should not do it on the first retry of a run whose provider is shedding load.
        return max(1, int(rng.uniform(max(1, self.base_delay_ms // 2), ceiling_ms)))

    def plan(self, attempt: int, fault: ProviderFault, *, waited_ms: int = 0) -> tuple[RetryPolicy | None, AttemptRecord | StopRetry]:
        """Decide what to do after ``attempt`` calls failed with ``fault``.

        Returns ``(policy_to_continue, record)`` where the record is either a
        :class:`RetryPolicy`-carrying delay to sleep or a :class:`StopRetry` naming the
        reason. Kept separate from :func:`execute` so the whole decision table is testable
        without a clock, a sleeper, or a fake provider.
        """
        if fault.kind in NEVER_RETRYABLE_CLASSES or fault.kind not in self.retry_on:
            return None, StopRetry("not_retryable", f"{fault.kind} is not in retry_on ({', '.join(self.retry_on) or 'nothing'})")
        if attempt >= self.max_attempts:
            return None, StopRetry("attempts_exhausted", f"{self.max_attempts} attempt(s) is the budget")
        delay = self._draw(self._ceiling(attempt))
        note = ""
        if fault.retry_after_ms is not None and self.respect_retry_after:
            delay = max(delay, min(fault.retry_after_ms, self.max_delay_ms))
            if fault.retry_after_ms > self.max_delay_ms:
                # Reported only when we overrode the instruction, because that is the case a
                # reader needs warned about; "we did what it asked" is the default and needs
                # no narration.
                note = (
                    f"provider asked for {fault.retry_after_ms} ms, above this policy's max_delay_ms of "
                    f"{self.max_delay_ms}; we wait the cap instead"
                )
        if delay > self.deadline_ms - waited_ms:
            # Refusing to *start* a wait we cannot finish is the whole point of a deadline:
            # the alternative is a run that stops mid-request after ten minutes of sleep.
            return None, StopRetry(
                "deadline_exceeded",
                f"the next wait is {delay} ms and only {max(0, self.deadline_ms - waited_ms)} ms of the {self.deadline_ms} ms deadline is left",
            )
        return self, AttemptRecord(
            attempt=attempt,
            max_attempts=self.max_attempts,
            kind=fault.kind,
            delay_ms=delay,
            waited_ms=waited_ms + delay,
            detail=fault.detail,
            note=note,
        )

    def planned_wait_ms(self) -> int:
        """The most this policy can make a single turn wait, jitter at its ceiling.

        Printed by ``--dry-run``: an operator approving a run should see that a policy of
        eight attempts with a 20 s ceiling can cost two minutes per turn before any model
        time is counted.
        """
        if not self.enabled:
            return 0
        return sum(self._ceiling(attempt) for attempt in range(1, self.max_attempts))

    def describe(self) -> str:
        """One line, for ``--dry-run`` and ``doctor``."""
        if not self.enabled:
            return "retry=off (max_attempts=1 sends one request per turn)"
        jitter = "full jitter, seeded" if self.jitter == "full" and self.seed is not None else ("full jitter" if self.jitter == "full" else "no jitter")
        return (
            f"retry={self.max_attempts - 1} additional attempt(s) on {', '.join(self.retry_on)}; "
            f"base {self.base_delay_ms} ms x{self.multiplier:g} up to {self.max_delay_ms} ms, "
            f"{jitter}, deadline {self.deadline_ms} ms (worst case {self.planned_wait_ms()} ms/turn)"
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "max_attempts": self.max_attempts,
            "base_delay_ms": self.base_delay_ms,
            "multiplier": self.multiplier,
            "max_delay_ms": self.max_delay_ms,
            "deadline_ms": self.deadline_ms,
            "jitter": self.jitter,
            "retry_on": list(self.retry_on),
            "respect_retry_after": self.respect_retry_after,
            "on_context_overflow": self.on_context_overflow,
            "enabled": self.enabled,
            "planned_wait_ms": self.planned_wait_ms(),
        }


@dataclass(frozen=True)
class StopRetry:
    """The decision not to retry, with the reason a caller can put in an event."""

    reason: str
    detail: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {"stop": self.reason, **({"detail": self.detail} if self.detail else {})}


# --------------------------------------------------------------------------
# classification
# --------------------------------------------------------------------------

_STATUS_CLASSES: dict[int, str] = {
    408: "timeout",
    409: "rate_limited",
    413: "context_overflow",
    425: "rate_limited",
    429: "rate_limited",
    500: "server_error",
    502: "server_error",
    503: "overloaded",
    504: "timeout",
    529: "overloaded",
}
_MESSAGE_PATTERNS: tuple[tuple[str, str], ...] = (
    ("rate_limit", "rate_limited"),
    ("rate limit", "rate_limited"),
    ("too many requests", "rate_limited"),
    ("overloaded", "overloaded"),
    ("overloaded_error", "overloaded"),
    ("no capacity", "overloaded"),
    ("prompt is too long", "context_overflow"),
    ("context length", "context_overflow"),
    ("context_length_exceeded", "context_overflow"),
    ("request too large", "context_overflow"),
    ("too many tokens", "context_overflow"),
    ("invalid api key", "auth"),
    ("authentication", "auth"),
    ("unauthorized", "auth"),
    ("forbidden", "auth"),
    ("permission", "auth"),
    ("connection reset", "network"),
    ("connection refused", "network"),
    ("connection aborted", "network"),
    ("broken pipe", "network"),
    ("incomplete chunked read", "network"),
    ("timed out", "timeout"),
    ("timeout", "timeout"),
    ("internal server error", "server_error"),
    ("bad gateway", "server_error"),
    ("service unavailable", "overloaded"),
)
_RETRY_AFTER_SECONDS = re.compile(r"retry-after[\"']?\s*[:=]\s*\"?(\d+(?:\.\d+)?)", re.IGNORECASE)
_RETRY_AFTER_MS = re.compile(r"retry-after-ms[\"']?\s*[:=]\s*\"?(\d+)", re.IGNORECASE)


def _status_of(error: BaseException) -> int | None:
    for name in ("status_code", "status", "code", "http_status"):
        value = getattr(error, name, None)
        if isinstance(value, int) and not isinstance(value, bool) and 100 <= value < 600:
            return value
    response = getattr(error, "response", None)
    value = getattr(response, "status_code", None)
    if isinstance(value, int) and not isinstance(value, bool) and 100 <= value < 600:
        return value
    return None


def _retry_after_ms(error: BaseException) -> int | None:
    for name in ("retry_after_ms", "retry_after"):
        value = getattr(error, name, None)
        if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0:
            return int(value) if name.endswith("ms") else int(float(value) * 1000)
    response = getattr(error, "response", None)
    headers = getattr(response, "headers", None)
    direct = getattr(error, "headers", None)
    if headers is None:
        headers = direct
    getter = getattr(headers, "get", None)
    if callable(getter):
        # ``retry-after-ms`` is the modern header and wins; plain ``Retry-After`` is seconds
        # (an HTTP-date is legal there too, and we decline to parse a calendar in a retry
        # path: an unparsed value means "no instruction", which the policy handles by using
        # its own schedule rather than guessing at the clock).
        for header, scale in (("retry-after-ms", 1), ("Retry-After", 1000)):
            raw = getter(header)
            if raw is None:
                continue
            try:
                return max(0, int(float(raw) * scale))
            except (TypeError, ValueError):
                continue
    text = str(error)
    matched = _RETRY_AFTER_MS.search(text)
    if matched:
        return int(matched.group(1))
    matched = _RETRY_AFTER_SECONDS.search(text)
    if matched:
        return int(float(matched.group(1)) * 1000)
    return None


def classify(error: BaseException, *, already_streamed: bool = False) -> ProviderFault:
    """Name a provider failure, from whatever the transport could tell us.

    Attribute-first: a real SDK carries a status code, and reading it beats matching its
    prose. Message patterns are the fallback for a provider that only has a string (the
    ``scripted`` one, and our own wrapped errors), and they are ordered so that a specific
    phrase wins over a generic one. ``already_streamed`` is not a guess about the provider
    but a fact about *this* runtime - text reached the terminal - and it outranks everything
    else, because an interrupting connection after that point is a different problem.
    """
    status = _status_of(error)
    detail = (str(error) or type(error).__name__).strip().replace("\n", " ")
    if already_streamed:
        return ProviderFault("stream_interrupted", status_code=status, detail=detail)
    kind: str | None = None
    declared = getattr(error, "failure_kind", None)
    if isinstance(declared, str) and declared in FAILURE_CLASSES:
        kind = declared
    if kind is None and status is not None:
        kind = _STATUS_CLASSES.get(status)
        if kind is None:
            kind = "auth" if status in (401, 403, 407) else "client_error" if 400 <= status < 500 else "server_error" if status >= 500 else "unknown"
    if kind is None:
        lowered = detail.lower()
        for needle, candidate in _MESSAGE_PATTERNS:
            if needle in lowered:
                kind = candidate
                break
    if kind is None:
        kind = "network" if isinstance(error, (ConnectionError, TimeoutError)) else "unknown"
    return ProviderFault(kind, retry_after_ms=_retry_after_ms(error), detail=detail, status_code=status)


# --------------------------------------------------------------------------
# execution
# --------------------------------------------------------------------------


def execute(
    call: Callable[[], Any],
    *,
    policy: RetryPolicy | None,
    on_retry: Callable[[AttemptRecord], None] | None = None,
    classify_error: Callable[[BaseException], ProviderFault] | None = None,
    sleep: Callable[[float], None] | None = None,
) -> tuple[Any, RetrySummary]:
    """Call ``call()`` under ``policy``, returning ``(result, summary)``.

    The injections are the reason this exists as a separate object rather than inline in the
    loop: a test can assert the *exact* sleep sequence without waiting, and an embedder can
    hand us its own timer instead of letting a governed run block a host thread nobody
    budgeted. The deadline is spent on *waiting*, and the accounting is done by summing the
    delays the policy chose - not by reading a wall clock - so the same test that pins the
    schedule pins the deadline decision too. A non-retryable fault or an exhausted budget re-raises the provider's own
    exception - the loop already knows how to turn that into an error result, and wrapping it
    here would lose the type a caller may be matching on.
    """
    summary = RetrySummary()
    if policy is None or not policy.enabled:
        return call(), summary
    classifier = classify_error or classify
    nap = sleep if sleep is not None else (policy.sleeper or _real_sleep)
    attempt = 0
    while True:
        attempt += 1
        try:
            result = call()
        except Exception as error:  # noqa: BLE001 - classified, then re-raised or retried
            fault = classifier(error)
            summary = summary.with_fault(attempt, fault)
            keep, decision = policy.plan(attempt, fault, waited_ms=summary.waited_ms)
            if keep is None:
                summary = summary.with_stop(attempt, decision)
                raise
            assert isinstance(decision, AttemptRecord)  # plan() returns one of the two
            if on_retry is not None:
                on_retry(decision)
            summary = summary.with_retry(decision)
            nap(decision.delay_ms / 1000.0)
        else:
            return result, summary


@dataclass(frozen=True)
class RetrySummary:
    """What a retry policy actually cost this turn."""

    attempts: int = 1
    waited_ms: int = 0
    faults: tuple[tuple[int, str], ...] = ()
    stop: str = ""
    detail: str = ""

    def with_fault(self, attempt: int, fault: ProviderFault) -> "RetrySummary":
        return RetrySummary(self.attempts, self.waited_ms, self.faults + ((attempt, fault.kind),), self.stop, self.detail)

    def with_retry(self, record: AttemptRecord) -> "RetrySummary":
        return RetrySummary(record.attempt + 1, record.waited_ms, self.faults, self.stop, self.detail)

    def with_stop(self, attempt: int, stop: "StopRetry") -> "RetrySummary":
        return RetrySummary(self.attempts, self.waited_ms, self.faults, stop.reason, stop.detail)

    @property
    def retried(self) -> bool:
        return len(self.faults) > 0

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"attempts": self.attempts, "waited_ms": self.waited_ms}
        if self.faults:
            payload["faults"] = [{"attempt": attempt, "kind": kind} for attempt, kind in self.faults]
        if self.stop:
            payload["stop"] = self.stop
            if self.detail:
                payload["stop_detail"] = self.detail
        return payload

    def line(self) -> str:
        if not self.faults:
            return ""
        kinds = ", ".join(kind for _attempt, kind in self.faults)
        tail = f", stopped: {self.stop}" if self.stop else ""
        return f"{self.attempts} provider attempt(s) ({kinds}), waited {self.waited_ms} ms{tail}"


def _real_sleep(seconds: float) -> None:
    import time

    time.sleep(seconds)


def merge_cli(
    policy: RetryPolicy | None,
    *,
    max_attempts: int | None = None,
    deadline_ms: int | None = None,
    retry_on: Iterable[str] | None = None,
    off: bool = False,
) -> RetryPolicy | None:
    """Apply the CLI's knobs on top of the workspace table, never loosening past it.

    ``off`` is not ``max_attempts = 1`` written by hand: it means "the operator wants to see
    the fault the first time it happens", and it survives a workspace that asked for retries,
    because refusing to retry can never be a loosening.
    """
    base = policy or RetryPolicy()
    if off:
        return RetryPolicy(
            max_attempts=1,
            base_delay_ms=base.base_delay_ms,
            max_delay_ms=base.max_delay_ms,
            deadline_ms=base.deadline_ms,
            jitter="none",
            retry_on=base.retry_on,
            respect_retry_after=base.respect_retry_after,
            on_context_overflow=base.on_context_overflow,
            seed=base.seed,
            sleeper=base.sleeper,
        )
    kwargs: dict[str, Any] = {}
    if max_attempts is not None:
        kwargs["max_attempts"] = max_attempts
    if deadline_ms is not None:
        kwargs["deadline_ms"] = deadline_ms
    if retry_on is not None:
        kwargs["retry_on"] = tuple(retry_on)
    if not kwargs:
        return policy
    return replace(base, **kwargs).restrict(policy)


__all__ = [
    "ALLOWED_RETRY_KEYS",
    "CONTEXT_OVERFLOW_ACTIONS",
    "DEFAULT_BASE_DELAY_MS",
    "DEFAULT_DEADLINE_MS",
    "DEFAULT_MAX_ATTEMPTS",
    "DEFAULT_MAX_DELAY_MS",
    "FAILURE_CLASSES",
    "JITTER_MODES",
    "MAX_ATTEMPTS",
    "MAX_DEADLINE_MS",
    "MAX_DELAY_MS",
    "NEVER_RETRYABLE_CLASSES",
    "RETRYABLE_CLASSES",
    "RETRY_SCHEMA_VERSION",
    "AttemptRecord",
    "ProviderFault",
    "RetryConfigurationError",
    "RetryPolicy",
    "RetrySummary",
    "StopRetry",
    "classify",
    "execute",
    "merge_cli",
]
