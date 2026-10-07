"""Production failure bundles with incident state and recovery.

P0 production wiring: when a production action fails, capture a failure
bundle (frozen, digest-pinned), transition the run into an incident
state, and support recovery through a fixed state machine. The state
transition log is append-only: every transition is recorded and nothing
is ever rewritten, so an operator can later prove *which* incident
happened and *how* the run recovered from it.

State machine::

    NORMAL --report_failure--> FAILED --begin_recovery--> RECOVERING
                                                --complete_recovery--> NORMAL
    NORMAL --degrade--> DEGRADED --begin_recovery--> RECOVERING

Fail-closed rules:

* One incident at a time: ``report_failure`` while already ``FAILED``
  (or ``RECOVERING``) is refused — the active incident must be
  recovered first.
* Recovery is a fixed two-step path: ``begin_recovery`` then
  ``complete_recovery``. Skipping straight from ``FAILED`` to
  ``NORMAL`` is refused.
* ``complete_recovery`` archives the active bundle (digest-pinned) so
  the incident record survives the return to ``NORMAL``.

Deterministic: no wall-clock reads — callers supply ``created_seq`` and
transition ``seq`` as integer sequence numbers. Digest comparisons use
:func:`hmac.compare_digest`. The canonicalizer is the shared
``canonical_json`` module with a local fallback so this file stays
importable standalone (blocked-import subprocess test in the test
module verifies this).

Honest scope:

* A failure bundle is a *record* of a failure, not a diagnosis: it
  captures what failed and a digest of the state at failure time; it
  does not explain *why* the failure happened.
* ``state_snapshot_hash`` is an opaque digest supplied by the caller —
  this module checks its shape (64 hex chars), not its truthfulness.
  A caller that hashes the wrong state produces a well-formed bundle
  of the wrong state.
* The transition log is append-only in memory; persisting it across
  restarts is the caller's job (see ``audit_chain.DurableAuditWriter``).
"""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping, Sequence

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


FAILURE_BUNDLE_VERSION = "northstar.failure-bundle.v1"

#: Schema pin for sealed bundles.
SCHEMA_PIN = "northstar.failure-bundle.v1"

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


class IncidentState(Enum):
    """Incident states of a production run. The value is the wire form."""

    NORMAL = "normal"
    DEGRADED = "degraded"
    FAILED = "failed"
    RECOVERING = "recovering"


class FailureBundleError(ValueError):
    """Malformed bundle input or illegal incident-state transition."""


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise FailureBundleError(f"{field_name} must be a non-empty str")
    return value


def _check_hex64(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not _HEX64_RE.match(value):
        raise FailureBundleError(
            f"{field_name} must be a 64-char lowercase hex sha256 digest"
        )
    return value


def _check_seq(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise FailureBundleError(f"{field_name} must be a non-negative int")
    return value


@dataclass(frozen=True)
class FailureBundle:
    """A frozen, digest-pinned record of one production failure.

    ``state_snapshot_hash`` is the sha256 hex digest of whatever state
    snapshot the caller captured at failure time (opaque to this
    module). ``stack_context`` is a short human-readable failure
    context (frame names, checkpoint id) — never a full traceback with
    secrets.
    """

    incident_id: str
    failed_action: str
    error: str
    stack_context: str
    state_snapshot_hash: str
    created_seq: int

    def __post_init__(self) -> None:
        _check_nonempty_str(self.incident_id, "incident_id")
        _check_nonempty_str(self.failed_action, "failed_action")
        _check_nonempty_str(self.error, "error")
        if not isinstance(self.stack_context, str):
            raise FailureBundleError("stack_context must be a str")
        _check_hex64(self.state_snapshot_hash, "state_snapshot_hash")
        _check_seq(self.created_seq, "created_seq")

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "incident_id": self.incident_id,
            "failed_action": self.failed_action,
            "error": self.error,
            "stack_context": self.stack_context,
            "state_snapshot_hash": self.state_snapshot_hash,
            "created_seq": self.created_seq,
        }


def bundle_digest(bundle: FailureBundle) -> str:
    """Deterministic sha256 hex digest of a bundle (canonical JSON)."""
    if not isinstance(bundle, FailureBundle):
        raise FailureBundleError("bundle must be a FailureBundle")
    return jcs_sha256_hex(bundle.as_dict())


def verify_bundle_digest(bundle: FailureBundle, expected: str) -> bool:
    """Constant-time check that ``bundle`` pins to ``expected`` digest."""
    _check_hex64(expected, "expected")
    return hmac.compare_digest(bundle_digest(bundle), expected)


@dataclass(frozen=True)
class StateTransition:
    """One append-only entry of the incident state log."""

    seq: int
    from_state: IncidentState
    to_state: IncidentState
    reason: str

    def __post_init__(self) -> None:
        _check_seq(self.seq, "seq")
        if not isinstance(self.from_state, IncidentState):
            raise FailureBundleError("from_state must be an IncidentState")
        if not isinstance(self.to_state, IncidentState):
            raise FailureBundleError("to_state must be an IncidentState")
        if not isinstance(self.reason, str) or not self.reason:
            raise FailureBundleError("reason must be a non-empty str")


class IncidentManager:
    """Owns the incident state machine for one production run.

    ``report_failure`` captures a :class:`FailureBundle` and moves
    ``NORMAL``/``DEGRADED`` to ``FAILED``. ``begin_recovery`` moves
    ``FAILED``/``DEGRADED`` to ``RECOVERING``. ``complete_recovery``
    moves ``RECOVERING`` to ``NORMAL`` and archives the active bundle.
    Every transition is appended to an in-memory log; the log is never
    mutated in place.
    """

    def __init__(self) -> None:
        self._state = IncidentState.NORMAL
        self._active: FailureBundle | None = None
        self._archived: list[FailureBundle] = []
        self._log: list[StateTransition] = []

    @property
    def state(self) -> IncidentState:
        return self._state

    @property
    def active_bundle(self) -> FailureBundle | None:
        return self._active

    def transitions(self) -> tuple[StateTransition, ...]:
        return tuple(self._log)

    def archived_bundles(self) -> tuple[FailureBundle, ...]:
        return tuple(self._archived)

    def _record(self, seq: int, to_state: IncidentState, reason: str) -> None:
        self._log.append(
            StateTransition(
                seq=_check_seq(seq, "seq"),
                from_state=self._state,
                to_state=to_state,
                reason=_check_nonempty_str(reason, "reason"),
            )
        )
        self._state = to_state

    def degrade(self, reason: str, *, seq: int) -> IncidentState:
        """Move ``NORMAL`` to ``DEGRADED`` (partial failure, still serving)."""
        if self._state is not IncidentState.NORMAL:
            raise FailureBundleError(
                f"degrade refused: state is {self._state.value}, want normal"
            )
        self._record(seq, IncidentState.DEGRADED, reason)
        return self._state

    def report_failure(
        self,
        failed_action: str,
        error: str,
        *,
        state_snapshot_hash: str,
        stack_context: str = "",
        seq: int,
    ) -> FailureBundle:
        """Capture a failure bundle and transition to ``FAILED``.

        Fail-closed: refused while already ``FAILED`` or ``RECOVERING``
        — one incident at a time.
        """
        if self._state in (IncidentState.FAILED, IncidentState.RECOVERING):
            raise FailureBundleError(
                f"report_failure refused: incident already active "
                f"(state={self._state.value})"
            )
        bundle = FailureBundle(
            incident_id=f"inc-{_check_seq(seq, 'seq')}-{_check_nonempty_str(failed_action, 'failed_action')}",
            failed_action=failed_action,
            error=error,
            stack_context=stack_context,
            state_snapshot_hash=state_snapshot_hash,
            created_seq=seq,
        )
        self._active = bundle
        self._record(seq, IncidentState.FAILED, f"failure: {failed_action}")
        return bundle

    def begin_recovery(self, reason: str, *, seq: int) -> IncidentState:
        """Move ``FAILED``/``DEGRADED`` to ``RECOVERING``."""
        if self._state not in (IncidentState.FAILED, IncidentState.DEGRADED):
            raise FailureBundleError(
                f"begin_recovery refused: state is {self._state.value}, "
                "want failed or degraded"
            )
        self._record(seq, IncidentState.RECOVERING, reason)
        return self._state

    def complete_recovery(self, reason: str, *, seq: int) -> IncidentState:
        """Move ``RECOVERING`` to ``NORMAL`` and archive the bundle."""
        if self._state is not IncidentState.RECOVERING:
            raise FailureBundleError(
                f"complete_recovery refused: state is {self._state.value}, "
                "want recovering"
            )
        if self._active is not None:
            self._archived.append(self._active)
            self._active = None
        self._record(seq, IncidentState.NORMAL, reason)
        return self._state


def main() -> None:
    mgr = IncidentManager()
    assert mgr.state is IncidentState.NORMAL
    digest = "ab" * 32
    bundle = mgr.report_failure(
        "tool.exec",
        "exit 1",
        state_snapshot_hash=digest,
        stack_context="loop.step:42",
        seq=7,
    )
    assert mgr.state is IncidentState.FAILED
    assert verify_bundle_digest(bundle, bundle_digest(bundle))
    mgr.begin_recovery("operator ack", seq=8)
    assert mgr.state is IncidentState.RECOVERING
    mgr.complete_recovery("healthcheck green", seq=9)
    assert mgr.state is IncidentState.NORMAL
    assert len(mgr.archived_bundles()) == 1
    assert len(mgr.transitions()) == 3
    print("failure-bundle OK: report -> recover -> archive")


if __name__ == "__main__":
    main()
