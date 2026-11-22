"""Experience Middleware for BackendRouter Integration.

Connects Experience Layering (history + policy) with the Northstar
BackendRouter and RouteLedger.

Design
------
Middleware pattern, minimal invasion:
- ``BackendRouter`` / ``RouteLedger`` accept an optional ``experience_middleware``.
- ``experience_middleware=None`` reproduces the previous behaviour exactly.
- Fail-open: any Experience infrastructure error must never block execution.
- All Experience-specific logic lives in this module.

The feedback loop
-----------------
Point #1 (``BackendRouter.select``) asks for admission before routing.
Point #2 (``RouteLedger._append_receipt_locked``) records the outcome.

INVARIANT: both points must derive the fingerprint the *same* way, otherwise
the loop is dead -- a block recorded at #2 would never be visible at #1.
``generate_fingerprint`` is therefore the single source of truth for both.
It may only read fields that exist on BOTH ``RouteRequest`` (point #1) and
``RouteEvent`` (point #2); ``input_digest`` fails that test because the ledger
does not persist it, so the fingerprint is ``actor_id:step_id``.

Probe allowance
---------------
A block cannot lift itself: successes only come from admitted runs, and the
block withholds admission. Left alone, a fingerprint that once dipped below
the success threshold would stay blocked forever. So every Nth blocked
attempt is let through as a *probe*, which regenerates evidence. The interval
backs off geometrically while probes keep failing (bounding wasted work) and
resets the moment one succeeds (restoring fast recovery).
"""
from __future__ import annotations

import collections
import logging
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


def _default_error_sink(where: str, error: BaseException) -> None:
    """Fallback trace for swallowed errors when no sink is supplied."""
    logger.warning(
        "experience middleware fail-open at %s: %s: %s",
        where, type(error).__name__, error,
    )


class PolicyDeniedError(Exception):
    """Raised when Experience policy denies admission.

    Carries ``is_policy_denial = True`` so callers can distinguish an explicit
    policy decision (must propagate) from an infrastructure error (fail-open)
    without importing this module.
    """

    is_policy_denial = True

    def __init__(self, reason: str, confidence: float = 0.0):
        self.reason = reason
        self.confidence = confidence
        super().__init__(f"Policy denied: {reason}")


@dataclass
class AdmissionResult:
    """Result of an admission check."""

    decision: str  # "admit" | "warn" | "block" | "probe"
    reason: str
    confidence: float
    execution_authorized: bool
    metadata: dict[str, Any]
    # True when this attempt was let through only to regenerate evidence for a
    # fingerprint that policy would otherwise have blocked.
    probe: bool = False


class ExperienceMiddleware:
    """Middleware connecting BackendRouter with Experience Layering."""

    def __init__(
        self,
        experience: Optional[Any] = None,
        *,
        probe_interval: int = 5,
        probe_backoff: float = 2.0,
        probe_max_interval: int = 100,
        error_sink: Optional[Callable[[str, BaseException], None]] = None,
    ):
        self.experience = experience
        self.enabled = experience is not None
        self.probe_interval = probe_interval
        self.probe_backoff = probe_backoff
        self.probe_max_interval = probe_max_interval
        # Per-fingerprint probe state. In-memory by design: it only paces
        # probes, so losing it on restart costs at most one extra probe.
        self._blocked_streak: dict[str, int] = {}
        self._current_interval: dict[str, int] = {}
        # Probes handed out whose outcome has not been recorded yet. Only a
        # *probe* failure justifies backing off -- an ordinary admitted run
        # failing says nothing about whether the escape hatch is working.
        self._probe_pending: dict[str, int] = {}
        self._lock = threading.Lock()
        # Fail-open must stay *observable*: a swallowed error that leaves no
        # trace makes "Experience has been down for three hours" look exactly
        # like "nothing failed in three hours".
        self._error_sink = error_sink or _default_error_sink
        self._error_counts: collections.Counter = collections.Counter()
        self._recent_errors: collections.deque = collections.deque(maxlen=50)

    # -- fingerprint ----------------------------------------------------
    def generate_fingerprint(self, context: dict[str, Any]) -> str:
        """Derive the goal fingerprint from request/event context.

        Only fields present in **both** ``RouteRequest`` (point #1) and
        ``RouteEvent`` (point #2) may be used, or the two points disagree and
        the feedback loop silently does nothing.

        That constraint rules out ``input_digest``: it exists on RouteRequest
        but the ledger does not persist it onto RouteEvent/RouteReceipt, so
        point #2 cannot recompute it. The shared fields are actor_id, task_id,
        thread_id, run_id, workspace_id, policy_revision and step_id.

        We deliberately exclude ``run_id``: it changes per run, which would
        fragment history and stop repeated failures from ever accumulating.
        ``step_id`` is the task-type axis, so the fingerprint means "this actor
        doing this kind of step" -- coarse enough to accumulate evidence,
        specific enough to stay meaningful.
        """
        actor_id = context.get("actor_id") or "unknown"
        step_id = context.get("step_id") or context.get("task_type") or "default"
        return f"{actor_id}:{step_id}"

    # -- point #1 -------------------------------------------------------
    def check_admission(self, fingerprint: str, context: dict[str, Any]) -> AdmissionResult:
        """Check admission before a routing decision. Never raises."""
        if not self.enabled:
            return AdmissionResult(
                decision="admit",
                reason="experience_disabled",
                confidence=0.0,
                execution_authorized=True,
                metadata={"experience_enabled": False},
            )

        try:
            from experience_layering import evaluate_policy

            stats = self.experience.query_statistics(fingerprint)
            # query_statistics omits success_count/lost_count entirely for a
            # fingerprint with no history (it returns only total_runs=0), so
            # these must be read defensively -- indexing them raised KeyError,
            # which fail-open swallowed, making the admission check a silent
            # no-op for every previously-unseen fingerprint.
            policy_eval = evaluate_policy(
                fingerprint=fingerprint,
                total_runs=stats.get("total_runs", 0),
                success_count=stats.get("success_count", 0),
                lost_count=stats.get("lost_count", 0),
                policy=None,
            )
            if not policy_eval.execution_authorized:
                return self._consider_probe(fingerprint, policy_eval, stats)
            with self._lock:
                # An admitted run is fresh evidence that the path works.
                self._blocked_streak.pop(fingerprint, None)
                self._current_interval.pop(fingerprint, None)
            return AdmissionResult(
                decision=policy_eval.decision,
                reason=policy_eval.reason,
                confidence=policy_eval.confidence,
                execution_authorized=policy_eval.execution_authorized,
                metadata={
                    "experience_enabled": True,
                    "total_runs": stats["total_runs"],
                    "success_rate": stats.get("success_rate", 0.0),
                    "lost_rate": stats.get("lost_rate", 0.0),
                    **self._history_status(),
                },
            )
        except Exception as error:  # fail-open
            self._note_error("check_admission", error)
            return AdmissionResult(
                decision="admit",
                reason=f"experience_error: {error}",
                confidence=0.0,
                execution_authorized=True,
                metadata={"experience_enabled": True, "error": str(error)},
            )

    def _consider_probe(self, fingerprint, policy_eval, stats) -> AdmissionResult:
        """Decide whether a blocked attempt may run anyway, as a probe.

        Without this, a block is permanent: successes only come from admitted
        runs, so the block withholds its own cure.
        """
        with self._lock:
            streak = self._blocked_streak.get(fingerprint, 0) + 1
            self._blocked_streak[fingerprint] = streak
            interval = self._current_interval.get(fingerprint, self.probe_interval)
            allowed = streak % interval == 0
            if allowed:
                self._probe_pending[fingerprint] = (
                    self._probe_pending.get(fingerprint, 0) + 1
                )

        base = {
            "experience_enabled": True,
            "total_runs": stats["total_runs"],
            "success_rate": stats.get("success_rate", 0.0),
            "lost_rate": stats.get("lost_rate", 0.0),
            **self._history_status(),
            "blocked_streak": streak,
            "probe_interval": interval,
        }
        if allowed:
            return AdmissionResult(
                decision="probe",
                reason=f"probe_allowance (every {interval}th blocked attempt): {policy_eval.reason}",
                confidence=policy_eval.confidence,
                execution_authorized=True,
                metadata=base,
                probe=True,
            )
        return AdmissionResult(
            decision=policy_eval.decision,
            reason=policy_eval.reason,
            confidence=policy_eval.confidence,
            execution_authorized=False,
            metadata=base,
        )

    # -- point #2 -------------------------------------------------------
    def record_success(self, fingerprint: str, context: dict[str, Any]) -> None:
        """Record a successful outcome. Never raises."""
        if not self.enabled:
            return
        try:
            from experience_layering import ExperienceRecord

            self.experience.settle(ExperienceRecord(
                fingerprint=fingerprint,
                outcome="success",
                reason=None,
                timestamp=context.get("timestamp"),
                metadata={"run_id": context.get("run_id")},
            ))
            with self._lock:
                # Fresh success: the path works again, restore probe pacing.
                self._blocked_streak.pop(fingerprint, None)
                self._current_interval.pop(fingerprint, None)
                self._probe_pending.pop(fingerprint, None)
        except Exception as error:  # fail-open
            self._note_error("record_success", error)

    def record_lost(self, fingerprint: str, reason: str, context: dict[str, Any]) -> None:
        """Record a lost/failed outcome. Never raises."""
        if not self.enabled:
            return
        try:
            self.experience.record_lost(
                fingerprint=fingerprint,
                reason=reason,
                timestamp=context.get("timestamp"),
                run_id=context.get("run_id"),
                metadata={"failure_class": reason},
            )
            with self._lock:
                # Only a failed *probe* means the escape hatch is not working;
                # an ordinary failure says nothing about probe pacing.
                if self._probe_pending.get(fingerprint, 0) > 0:
                    self._probe_pending[fingerprint] -= 1
                    interval = self._current_interval.get(fingerprint, self.probe_interval)
                    self._current_interval[fingerprint] = min(
                        max(int(interval * self.probe_backoff), self.probe_interval),
                        self.probe_max_interval,
                    )
        except Exception as error:  # fail-open
            self._note_error("record_lost", error)

    # -- observability --------------------------------------------------
    def _note_error(self, where: str, error: BaseException) -> None:
        """Trace an error we deliberately swallowed.

        Fail-open is a deliberate choice, but a *silent* one is
        indistinguishable from "nothing happened". Every swallowed error lands
        here so a dead Experience layer can be told apart from an idle one.
        """
        self._error_counts[where] += 1
        self._recent_errors.append((where, type(error).__name__, str(error)))
        try:
            self._error_sink(where, error)
        except Exception:
            pass  # a broken sink must not escalate into a real failure

    @property
    def error_counts(self) -> dict[str, int]:
        """Swallowed-error tally per call site (empty means none)."""
        return dict(self._error_counts)

    def recent_errors(self, limit: Optional[int] = None) -> list[tuple[str, str, str]]:
        """Most recent swallowed errors as (where, type, message)."""
        items = list(self._recent_errors)
        return items[-limit:] if limit else items

    def _history_status(self) -> dict[str, Any]:
        """Completeness of the history an admission decision was made from. Never raises.

        Reported, not acted on: the decision itself is unchanged, so a deployment that wants
        "incomplete history means defer" can build that on this signal without this layer
        quietly changing what it authorizes.
        """
        status = getattr(self.experience, "history_status", None)
        if status is None:
            return {}
        try:
            info = status()
            return {
                "history_complete": bool(info["complete"]),
                "skipped_lines": int(info["skipped_lines"]),
                "history_issues": list(info.get("issues", [])),
            }
        except Exception as error:  # observability must not break admission
            self._note_error("history_status", error)
            return {}


def create_middleware(experience: Optional[Any] = None) -> ExperienceMiddleware:
    """Convenience constructor."""
    return ExperienceMiddleware(experience)
