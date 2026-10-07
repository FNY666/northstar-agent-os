"""Failure bundles for budget exhaustion: incident records with budget detail.

Integration of :mod:`failure_bundle` and :mod:`per_call_budget`.

A budget refusal (:class:`per_call_budget.BudgetExhausted`) is normally a
silent gate event: the call is refused and the caller moves on. For a
production run that is the wrong shape — a budget overrun is an
*incident*: the run can no longer make progress on its current plan, an
operator needs to know which ceiling fired and how much headroom was
left, and the state machine should park the run in ``FAILED`` until a
human acknowledges and recovers it.

This module wires the two together:

* :class:`FailureBudgetManager` owns one :class:`IncidentManager` and
  one :class:`PerCallBudget`. Calls go through
  :meth:`FailureBudgetManager.guarded_charge`, which is the budget
  gate's ``check_and_charge`` plus automatic incident capture: on
  ``BudgetExhausted`` it reports a failure bundle into the incident
  manager (moving the run to ``FAILED``) and attaches a structured
  :class:`FailureBudgetBundle` carrying the budget numbers. The
  original ``BudgetExhausted`` is re-raised — the call is still refused,
  but the refusal is now recorded as an incident.
* The failure bundle's ``state_snapshot_hash`` is the digest of the
  budget ledger at failure time (``PerCallBudget.as_dict()``), so an
  auditor can verify *which* ledger state the incident was recorded
  against. The budget bundle's ``incident_id`` matches the failure
  bundle's ``incident_id`` exactly, linking the two records.

Fail-closed rules:

* One incident at a time (inherited from :class:`IncidentManager`): a
  second ``BudgetExhausted`` while ``FAILED``/``RECOVERING`` is still
  re-raised as ``BudgetExhausted``, but no second bundle is created —
  the active incident must be recovered first.
* Recovery follows the fixed two-step path
  (``begin_recovery`` -> ``complete_recovery``); the budget gate itself
  does not auto-recover the incident.

Deterministic: no wall-clock — callers supply integer ``seq`` numbers,
as in both underlying modules. Digest comparisons use
:func:`hmac.compare_digest`.

Honest scope: the bundle records *that* a budget ceiling refused a call
and the ledger state at that moment; it does not explain *why* the run
burned budget, and estimates remain estimates (see
:mod:`per_call_budget`). A clean manager state means "no budget
incident recorded", never "the budget is sufficient for the plan".
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Any

from failure_bundle import (
    FAILURE_BUNDLE_VERSION,
    FailureBundle,
    FailureBundleError,
    IncidentManager,
    IncidentState,
    bundle_digest,
    verify_bundle_digest,
)
from per_call_budget import (
    CEILING_PER_CALL,
    CEILING_RUN,
    BudgetExhausted,
    PerCallBudget,
)

#: Version pin for the failure+budget wiring described here.
FAILURE_BUDGET_COMBO_VERSION = "failure-budget-combo.v1"

#: Schema pin for sealed failure-budget bundles.
SCHEMA_PIN = "northstar.failure-budget-combo.v1"

#: Which budget ceiling fired: re-exported so callers import one module.
BUDGET_CEILING_PER_CALL = CEILING_PER_CALL
BUDGET_CEILING_RUN = CEILING_RUN

#: Ceilings a FailureBudgetBundle recognises. Anything else is rejected.
CEILINGS: tuple[str, ...] = (CEILING_PER_CALL, CEILING_RUN)


class FailureBudgetComboError(ValueError):
    """Malformed failure-budget bundle input."""


def _check_nonempty_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise FailureBudgetComboError(f"{field_name} must be a non-empty str")
    return value


def _check_seq(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise FailureBudgetComboError(f"{field_name} must be a non-negative int")
    return value


def _check_usd(value: Any, field_name: str, *, allow_none: bool = False) -> float | None:
    if value is None and allow_none:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise FailureBudgetComboError(f"{field_name} must be a number")
    amount = float(value)
    if amount < 0:
        raise FailureBudgetComboError(f"{field_name} must be non-negative")
    return amount


@dataclass(frozen=True)
class FailureBudgetBundle:
    """A frozen, structured record of one budget-exhaustion incident.

    ``incident_id`` is the id of the matching :class:`FailureBundle`
    created by the incident manager — the two records link on it.
    ``ceiling`` names which budget ceiling refused the call
    (``"per_call"`` or ``"run"``). ``needed_usd`` is the refused call's
    estimate; ``available_usd`` the remaining run budget at refusal time
    (``None`` when the run has no ceiling, i.e. the refusal came from
    the per-call ceiling); ``max_budget_usd``/``total_spent_usd`` pin the
    run-level position.
    """

    incident_id: str
    ceiling: str
    call_type: str
    needed_usd: float
    available_usd: float | None
    max_budget_usd: float | None
    total_spent_usd: float
    created_seq: int

    def __post_init__(self) -> None:
        _check_nonempty_str(self.incident_id, "incident_id")
        if self.ceiling not in CEILINGS:
            raise FailureBudgetComboError(
                f"ceiling must be one of {list(CEILINGS)}, got {self.ceiling!r}"
            )
        _check_nonempty_str(self.call_type, "call_type")
        _check_usd(self.needed_usd, "needed_usd")
        _check_usd(self.available_usd, "available_usd", allow_none=True)
        _check_usd(self.max_budget_usd, "max_budget_usd", allow_none=True)
        _check_usd(self.total_spent_usd, "total_spent_usd")
        _check_seq(self.created_seq, "created_seq")

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA_PIN,
            "incident_id": self.incident_id,
            "ceiling": self.ceiling,
            "call_type": self.call_type,
            "needed_usd": self.needed_usd,
            "available_usd": self.available_usd,
            "max_budget_usd": self.max_budget_usd,
            "total_spent_usd": self.total_spent_usd,
            "created_seq": self.created_seq,
        }


def failure_budget_digest(bundle: FailureBudgetBundle) -> str:
    """Deterministic sha256 hex digest of a budget bundle (canonical JSON)."""
    if not isinstance(bundle, FailureBudgetBundle):
        raise FailureBudgetComboError("bundle must be a FailureBudgetBundle")
    # Same construction as failure_bundle.bundle_digest (canonical JSON via
    # the shared canonicalizer with local fallback).
    try:  # the single canonicalizer
        from canonical_json import jcs_sha256_hex
    except Exception:  # pragma: no cover - must stay importable standalone
        import json as _json

        def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
            return hashlib.sha256(
                _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                            ensure_ascii=True).encode("utf-8")
            ).hexdigest()

    return jcs_sha256_hex(bundle.as_dict())


def verify_failure_budget_digest(bundle: FailureBudgetBundle, expected: str) -> bool:
    """Constant-time check that ``bundle`` pins to ``expected`` digest."""
    if not isinstance(expected, str) or len(expected) != 64:
        raise FailureBudgetComboError("expected must be a 64-char hex digest")
    return hmac.compare_digest(failure_budget_digest(bundle), expected)


def budget_bundle_from_exhaustion(
    exc: BudgetExhausted,
    *,
    budget: PerCallBudget,
    incident_id: str,
    seq: int,
) -> FailureBudgetBundle:
    """Build a :class:`FailureBudgetBundle` from a caught ``BudgetExhausted``.

    Reads the numbers off the exception (``call_type``, ``needed``,
    ``available``, ``ceiling``) and the run position off ``budget``.
    ``incident_id`` is the matching failure bundle's id; ``seq`` the
    caller-supplied sequence number.
    """
    if not isinstance(exc, BudgetExhausted):
        raise FailureBudgetComboError("exc must be a BudgetExhausted")
    if not isinstance(budget, PerCallBudget):
        raise FailureBudgetComboError("budget must be a PerCallBudget")
    return FailureBudgetBundle(
        incident_id=_check_nonempty_str(incident_id, "incident_id"),
        ceiling=exc.ceiling,
        call_type=exc.call_type,
        needed_usd=float(exc.needed),
        available_usd=None if exc.available is None else float(exc.available),
        max_budget_usd=budget.max_budget_usd,
        total_spent_usd=float(budget.total_spent_usd),
        created_seq=_check_seq(seq, "seq"),
    )


def failure_budget_audit_event(bundle: FailureBudgetBundle, seq: int) -> dict[str, Any]:
    """Audit-shaped record for the ``audit.ndjson/1`` envelope."""
    if not isinstance(bundle, FailureBudgetBundle):
        raise FailureBudgetComboError("bundle must be a FailureBudgetBundle")
    record = bundle.as_dict()
    record["audit_seq"] = _check_seq(seq, "seq")
    return record


class FailureBudgetManager:
    """Owns the incident machine plus the budget gate for one run.

    ``guarded_charge`` is the only way to spend through this manager:
    it delegates to :meth:`PerCallBudget.check_and_charge`, and on
    ``BudgetExhausted`` it automatically reports a failure bundle (the
    run moves to ``FAILED``) before re-raising the original exception,
    so callers still see the refusal but it is now a recorded incident.

    The remaining public surface (``degrade``, ``begin_recovery``,
    ``complete_recovery``, ``transitions``, ``archived_bundles``) is the
    :class:`IncidentManager` protocol, unchanged.
    """

    def __init__(
        self,
        max_budget_usd: float | None = None,
        per_call_ceilings: dict[str, float] | None = None,
    ) -> None:
        kwargs: dict[str, Any] = {"max_budget_usd": max_budget_usd}
        if per_call_ceilings is not None:
            kwargs["per_call_ceilings"] = per_call_ceilings
        self._budget = PerCallBudget(**kwargs)
        self._incidents = IncidentManager()
        self._budget_bundles: list[FailureBudgetBundle] = []

    @property
    def state(self) -> IncidentState:
        return self._incidents.state

    @property
    def budget(self) -> PerCallBudget:
        return self._budget

    @property
    def incidents(self) -> IncidentManager:
        return self._incidents

    def budget_bundles(self) -> tuple[FailureBudgetBundle, ...]:
        """All budget-exhaustion bundles recorded, in order."""
        return tuple(self._budget_bundles)

    def active_budget_bundle(self) -> FailureBudgetBundle | None:
        """The budget bundle attached to the active incident, if any."""
        active = self._incidents.active_bundle
        if active is None:
            return None
        for bundle in reversed(self._budget_bundles):
            if bundle.incident_id == active.incident_id:
                return bundle
        return None

    def guarded_charge(
        self, call_type: str, estimated_cost_usd: float, *, seq: int
    ) -> float | None:
        """Charge a call through the budget gate with incident capture.

        Returns the remaining run budget (or ``None`` when there is no
        run ceiling) on success, exactly like
        :meth:`PerCallBudget.check_and_charge`.

        On ``BudgetExhausted``: reports a failure bundle into the
        incident manager — the bundle's ``state_snapshot_hash`` is the
        digest of the budget ledger at failure time — attaches the
        structured :class:`FailureBudgetBundle`, and re-raises the
        original exception. While an incident is already active the
        exception is still re-raised, but no second bundle is created
        (one incident at a time).
        """
        _check_seq(seq, "seq")
        try:
            return self._budget.check_and_charge(call_type, estimated_cost_usd)
        except BudgetExhausted as exc:
            self._record_budget_incident(exc, seq=seq)
            raise

    def _record_budget_incident(self, exc: BudgetExhausted, *, seq: int) -> None:
        # Snapshot the ledger *before* reporting: this is the state the
        # incident is recorded against.
        ledger_digest = failure_budget_ledger_digest(self._budget)
        error = (
            f"budget-exhausted({exc.ceiling}) for {exc.call_type}: "
            f"needed ${float(exc.needed):.6f}"
        )
        stack_context = (
            f"budget-guard seq={seq} spent=${float(self._budget.total_spent_usd):.6f} "
            f"remaining={'none' if exc.available is None else f'${float(exc.available):.6f}'}"
        )
        try:
            failure = self._incidents.report_failure(
                f"budget.{exc.call_type}",
                error,
                state_snapshot_hash=ledger_digest,
                stack_context=stack_context,
                seq=seq,
            )
        except FailureBundleError:
            # An incident is already active: the refusal is still an
            # exception to the caller (re-raised by guarded_charge), but
            # it joins the existing incident rather than opening a new one.
            return
        self._budget_bundles.append(
            budget_bundle_from_exhaustion(
                exc, budget=self._budget, incident_id=failure.incident_id, seq=seq
            )
        )

    def degrade(self, reason: str, *, seq: int) -> IncidentState:
        return self._incidents.degrade(reason, seq=seq)

    def begin_recovery(self, reason: str, *, seq: int) -> IncidentState:
        return self._incidents.begin_recovery(reason, seq=seq)

    def complete_recovery(self, reason: str, *, seq: int) -> IncidentState:
        return self._incidents.complete_recovery(reason, seq=seq)

    def transitions(self):  # -> tuple[StateTransition, ...]
        return self._incidents.transitions()

    def archived_bundles(self) -> tuple[FailureBundle, ...]:
        return self._incidents.archived_bundles()


def failure_budget_ledger_digest(budget: PerCallBudget) -> str:
    """Digest of the budget ledger dict (the incident's state snapshot)."""
    if not isinstance(budget, PerCallBudget):
        raise FailureBudgetComboError("budget must be a PerCallBudget")
    try:  # the single canonicalizer
        from canonical_json import jcs_sha256_hex
    except Exception:  # pragma: no cover - must stay importable standalone
        import json as _json

        def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
            return hashlib.sha256(
                _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                            ensure_ascii=True).encode("utf-8")
            ).hexdigest()

    return jcs_sha256_hex(budget.as_dict())


def main() -> None:
    mgr = FailureBudgetManager(max_budget_usd=1.0)
    assert mgr.state is IncidentState.NORMAL
    mgr.guarded_charge("tool", 0.005, seq=0)
    assert mgr.state is IncidentState.NORMAL
    try:
        mgr.guarded_charge("tool", 0.02, seq=1)  # over the $0.01 per-call ceiling
    except BudgetExhausted as exc:
        assert exc.ceiling == CEILING_PER_CALL
    else:
        raise AssertionError("expected BudgetExhausted")
    assert mgr.state is IncidentState.FAILED
    budget_bundle = mgr.active_budget_bundle()
    assert budget_bundle is not None
    assert budget_bundle.ceiling == "per_call"
    assert budget_bundle.call_type == "tool"
    failure = mgr.incidents.active_bundle
    assert failure is not None
    assert failure.incident_id == budget_bundle.incident_id
    assert verify_bundle_digest(failure, bundle_digest(failure))
    mgr.begin_recovery("operator ack", seq=2)
    mgr.complete_recovery("budget raised", seq=3)
    assert mgr.state is IncidentState.NORMAL
    assert len(mgr.archived_bundles()) == 1
    assert mgr.active_budget_bundle() is None
    print("failure-budget-combo OK: overrun -> incident -> recover")


if __name__ == "__main__":
    main()
