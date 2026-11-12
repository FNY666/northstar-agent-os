"""The retry/idempotency contract, wired onto the egress sidecar's real call.

The egress sidecar is the only process in Northstar that opens an outbound
network connection, so this is *the* seam where a retry can duplicate a
side effect that already landed. This module owns that seam: it wraps the
one upstream request in :class:`retry_contract.RetryContract`, so the
classification rules from E2B decide -- not a comment, not a runbook -- when
a call may be repeated.

What the contract changes here, concretely:

* A **retryable** failure (a 429/502/503/504 without a ``Should-Retry``
  header, a ``Should-Retry: true`` answer, or a failure to *establish* the
  connection) is retried, with the same ``Idempotency-Key`` on every attempt.
* A **post-write** failure (``ECONNRESET`` and friends: "the server may have
  received the request") is never retried. The answer says the operation may
  already have executed, and the caller gets that fact.
* An **explicit ``Should-Retry: false``** is authoritative: no retry.
* A **404/410** is a confirmed-gone answer: distinct from unreachable, and
  distinct from success.

The idempotency key and the payload digest are computed once, before the
first attempt, from the wire request. Every attempt carries the *same* key
and the *same* digest; a retry that would carry a different digest is
refused rather than sent.
"""
from __future__ import annotations

import hashlib
import os
import sys
from typing import Any, Callable, Mapping

_RUNTIME = os.environ.get("NORTHSTAR_RUNTIME_DIR", "").strip()
if _RUNTIME:
    if _RUNTIME not in sys.path:
        sys.path.insert(0, _RUNTIME)
else:
    _fallback = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "northstar-agent-runtime")
    if os.path.isdir(_fallback) and _fallback not in sys.path:
        sys.path.insert(0, _fallback)

from retry_contract import (  # noqa: E402
    Failure,
    FailureClass,
    GONE_STATUSES,
    Operation,
    RetryContract,
    RetryContractConfig,
    RetryOutcome,
    classify_exception,
    classify_http_result,
    classify_response,
    resolve_idempotency_key,
)

#: The header the upstream service reads to collapse a duplicate call.
IDEMPOTENCY_HEADER = "idempotency-key"

#: The configuration used by the sidecar's outbound path. Declared once, so
#: no constant is scattered at a call site.
DEFAULT_EGRESS_RETRY_CONFIG = RetryContractConfig(
    max_retries=2,
    initial_wait_ms=100,
    max_wait_ms=2_000,
    exponential_base=2.0,
    jitter=0.5,
)


def payload_digest(method: str, path: str, body: bytes) -> str:
    """The digest that pins "this is the same operation" across attempts."""
    digest = hashlib.sha256()
    digest.update(str(method or "").upper().encode("utf-8"))
    digest.update(b"\x1f")
    digest.update(str(path or "").encode("utf-8"))
    digest.update(b"\x1f")
    digest.update(body or b"")
    return digest.hexdigest()


def operation_for_request(
    value: Mapping[str, Any],
    *,
    idempotency_key: str | None = None,
    config: RetryContractConfig | None = None,
) -> Operation:
    """Build the :class:`Operation` describing one wire request.

    The idempotency key is validated once, here. A malformed key is refused
    before any socket opens rather than being dropped (dropping it would
    quietly turn a replay-safe call into an unsafe one).
    """
    import base64
    import binascii

    method = str(value.get("method") or "")
    path = str(value.get("path") or "")
    raw_body = value.get("body_b64", "") or ""
    try:
        body = base64.b64decode(raw_body, validate=True) if raw_body else b""
    except (binascii.Error, ValueError):
        body = b""
    key = resolve_idempotency_key(idempotency_key)
    return Operation(
        method=method,
        payload_digest=payload_digest(method, path, body),
        idempotency_key=key,
        body_replayable=True,
    )


def outcome_state(outcome: RetryOutcome) -> str:
    """The caller's actionable state after a governed call.

    Three distinct states, never one vague one:

    * ``ok`` -- the call succeeded.
    * ``gone`` -- the target is confirmed absent (HTTP 404/410). The caller
      should *recreate* it.
    * ``unreachable`` -- the target could not be reached and may still be
      running. The caller should *resume* or probe it.

    This is E2B's ``SandboxNotRunningError`` (confirmed stopped) versus
    ``SandboxUnreachableError`` (might still be running). Collapsing them
    would force the caller to guess: recreating a target that is still
    running loses its state, and resuming a target that is gone wastes a
    retry budget on a corpse.
    """
    if outcome.ok:
        return "ok"
    failure = outcome.failure
    if failure is not None and failure.status in GONE_STATUSES:
        return "gone"
    return "unreachable"


def outcome_fields(outcome: RetryOutcome) -> dict[str, Any]:
    """The wire fields describing a governed call's outcome."""
    failure = outcome.failure
    return {
        "target_state": outcome_state(outcome),
        "may_have_executed": bool(outcome.may_have_executed),
        "attempts": outcome.attempts_made,
        "retry_classification": (
            failure.classification.value if failure is not None else "none"
        ),
    }


def governed_egress_call(
    operation: Operation,
    attempt: Callable[[Operation], Any],
    *,
    classify_result: Callable[[Any], Failure | None] | None = None,
    config: RetryContractConfig | None = None,
    sleep: Callable[[float], None] | None = None,
) -> RetryOutcome:
    """Run one upstream egress call under the retry/idempotency contract.

    ``attempt`` performs one upstream request with the operation's
    idempotency key attached. ``classify_result`` maps the returned value
    onto a :class:`Failure` (or ``None`` for success).
    """
    contract = RetryContract(
        config=config or DEFAULT_EGRESS_RETRY_CONFIG,
        sleep=sleep,
    )
    return contract.execute(operation, attempt, classify=classify_result)


__all__ = [
    "DEFAULT_EGRESS_RETRY_CONFIG",
    "Failure",
    "FailureClass",
    "IDEMPOTENCY_HEADER",
    "Operation",
    "RetryContract",
    "RetryContractConfig",
    "RetryOutcome",
    "classify_exception",
    "classify_http_result",
    "classify_response",
    "governed_egress_call",
    "operation_for_request",
    "outcome_fields",
    "outcome_state",
    "payload_digest",
    "resolve_idempotency_key",
]
