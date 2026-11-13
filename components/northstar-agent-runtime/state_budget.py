"""Hard cap on agent state size, enforced at every transition.

Absorbed from Jido's ``lib/jido/agent/state_budget.ex`` (agentjido/jido,
rank 7 in the frontier round).  Jido is Elixir/BEAM and Northstar is not, so
only the *pattern* travels: the agent declares a ``max_state_size`` and every
state transition is checked against it, so "state will be summarized
eventually" becomes "state cannot exceed this size, period".

Northstar's gap this closes (read from the code, not assumed):

* ``long_horizon.py`` rebuilds a :class:`RoundState` per round and keeps
  ``verified_progress`` / ``failures`` / ``context`` growing; nothing in the
  runtime caps the size of that state.
* ``compaction.py`` compacts the *transcript* by token threshold.  It is a
  brake on context, not a cap on state, and compaction is itself the
  consent-boundary risk (scope qualifiers get dropped, cancellation gets
  lost) -- so a brake is the wrong place to enforce a hard bound.
* ``context_budget.py`` budgets tokens, not bytes of state.

This module is the missing guard: a byte cap on the agent's state that is
checked **at every transition**, not at checkpoint time.

Unit of measurement
-------------------
The size of a state is the number of bytes of its **canonical JSON**
serialization: sorted keys, compact separators, UTF-8.  Canonicalization is
what makes the number reproducible and independent of dict insertion order --
two states that differ only in key order have the same measured size.  Python
object memory is *not* used: it is not reproducible across runs, and a budget
that cannot be reproduced cannot be audited.

The canonicalizer is the runtime's shared ``canonical_json`` module (RFC 8785
JCS) with a local ``json.dumps`` fallback, the same pattern
``ai_constitution.py`` and ``failure_bundle.py`` use.

Scope
-----
This module does not implement compaction and does not touch
``compaction.py``.  It only exposes what a caller needs to drive one:
:meth:`StateBudget.bytes_over_budget` (how many bytes to reclaim) and
:meth:`StateBudget.would_fit` (whether a delta would fit), plus the
transition-time enforcement itself.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: object) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(
            obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")


#: The only unit this module measures in: bytes of canonical JSON.
UNIT = "bytes"

#: Version pin for this module's record shape.
STATE_BUDGET_VERSION = "state-budget.v1"


class StateBudgetError(Exception):
    """Base class for every state-budget refusal."""


class OverBudget(StateBudgetError):
    """A transition was refused because it would exceed the state budget.

    Attributes:
        current_size: the measured size of the state *before* the refused
            transition, in bytes.
        max_state_size: the declared hard cap, in bytes.
        delta_bytes: how many bytes this delta would have added.
        projected_size: the size the state would have reached, in bytes.
    """

    def __init__(
        self,
        current_size: int,
        max_state_size: int,
        delta_bytes: int,
        projected_size: int,
    ) -> None:
        self.current_size = current_size
        self.max_state_size = max_state_size
        self.delta_bytes = delta_bytes
        self.projected_size = projected_size
        super().__init__(
            f"state budget exceeded: {current_size} bytes now, "
            f"delta adds {delta_bytes} -> {projected_size} bytes, "
            f"cap is {max_state_size} bytes"
        )


def measure_state(state: Any) -> int:
    """Measure a state in bytes of canonical JSON.

    Public and deterministic: the same state measured twice gives the same
    number, and two states that differ only in key order measure the same.
    A state that cannot be canonicalized is a refusal, not a guess --
    an unmeasurable state cannot be shown to fit a budget.
    """
    try:
        return len(jcs_canonical_json(state))
    except Exception as exc:  # noqa: BLE001 - fail closed on any bad state
        raise StateBudgetError(
            f"state cannot be canonicalized for measurement: {exc}"
        ) from exc


def _check_mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise StateBudgetError(f"{name} must be a mapping")
    return value


def _apply_delta(state: Mapping[str, Any], delta: Mapping[str, Any]) -> dict[str, Any]:
    """Apply a delta to a state: a shallow key-wise update."""
    merged = dict(state)
    merged.update(delta)
    return merged


@dataclass(frozen=True)
class TransitionResult:
    """The outcome of an accepted transition.

    Attributes:
        state: the new state (the old state with the delta applied).
        budget: the new budget, with ``current_size`` updated.
        current_size: the measured size of the new state, in bytes.
    """

    state: dict[str, Any]
    budget: "StateBudget"
    current_size: int


@dataclass(frozen=True)
class TransitionOutcome:
    """The outcome of a transition attempt: accepted, or explicitly refused.

    Attributes:
        accepted: whether the delta was applied.
        state: the resulting state (unchanged on refusal).
        budget: the resulting budget (unchanged on refusal).
        refusal: the :class:`OverBudget` detail when refused, else ``None``.
    """

    accepted: bool
    state: dict[str, Any]
    budget: "StateBudget"
    refusal: OverBudget | None


@dataclass
class StateBudget:
    """A hard byte cap on agent state, checked at every transition.

    ``max_state_size`` is the declared cap in bytes and must be a positive
    int -- a budget without a cap is not a budget, so construction fails
    closed.  ``current_size`` is the measured size of the state this budget
    last accepted; :meth:`transition` updates it, and a refused transition
    leaves it exactly where it was.
    """

    max_state_size: int
    current_size: int = 0
    unit: str = UNIT

    def __post_init__(self) -> None:
        if isinstance(self.max_state_size, bool) or not isinstance(
            self.max_state_size, int
        ):
            raise ValueError("max_state_size must be an int")
        if self.max_state_size <= 0:
            raise ValueError("max_state_size must be positive")
        if isinstance(self.current_size, bool) or not isinstance(self.current_size, int):
            raise ValueError("current_size must be an int")
        if self.current_size < 0:
            raise ValueError("current_size must be non-negative")
        if self.unit != UNIT:
            raise ValueError(f"unit must be {UNIT!r}")

    # -- measurement -----------------------------------------------------

    def size_of(self, state: Any) -> int:
        """Measured size of ``state`` in bytes (canonical JSON)."""
        return measure_state(state)

    # -- checks ----------------------------------------------------------

    def check(self, state: Any) -> bool:
        """True when ``state`` fits inside the budget.

        A state that cannot be measured is *not* within budget.
        """
        try:
            size = self.size_of(state)
        except StateBudgetError:
            return False
        return size <= self.max_state_size

    def check_or_raise(self, state: Any) -> None:
        """Raise :class:`OverBudget` when ``state`` does not fit.

        The mirror of Jido's ``StateBudget.check!/1``.  Silent when the state
        is within budget.
        """
        size = self.size_of(state)
        if size > self.max_state_size:
            raise OverBudget(
                current_size=size,
                max_state_size=self.max_state_size,
                delta_bytes=0,
                projected_size=size,
            )

    # -- the enforced path ------------------------------------------------

    def transition(
        self, state: Mapping[str, Any], delta: Mapping[str, Any]
    ) -> "TransitionResult":
        """Apply ``delta`` to ``state`` and return the accepted result.

        The new size is measured, then checked -- **every** call, with no
        "accumulate now, reconcile at the checkpoint" path.  When the new
        state does not fit, :class:`OverBudget` is raised and this budget is
        left untouched: the delta is not applied and ``current_size`` does
        not move.  Nothing is silently truncated and nothing is dropped.
        """
        state = _check_mapping(state, "state")
        delta = _check_mapping(delta, "delta")
        current = self.size_of(state)
        projected_state = _apply_delta(state, delta)
        projected = self.size_of(projected_state)
        if not self.check(projected_state):
            raise OverBudget(
                current_size=current,
                max_state_size=self.max_state_size,
                delta_bytes=projected - current,
                projected_size=projected,
            )
        self.current_size = projected
        return TransitionResult(
            state=projected_state,
            budget=self,
            current_size=projected,
        )

    def try_transition(
        self, state: Mapping[str, Any], delta: Mapping[str, Any]
    ) -> "TransitionOutcome":
        """Like :meth:`transition`, but a refusal is a returned value.

        Same enforcement -- the check still happens at the transition, not
        at some later reconciliation -- but the caller gets an explicit
        ``accepted`` flag and the :class:`OverBudget` detail instead of an
        exception.  A refusal leaves the budget untouched, exactly as in
        :meth:`transition`.
        """
        try:
            result = self.transition(state, delta)
        except OverBudget as exc:
            return TransitionOutcome(
                accepted=False,
                state=dict(_check_mapping(state, "state")),
                budget=self,
                refusal=exc,
            )
        return TransitionOutcome(
            accepted=True,
            state=result.state,
            budget=result.budget,
            refusal=None,
        )

    # -- caller-side planning ---------------------------------------------

    def would_fit(self, state: Mapping[str, Any], delta: Mapping[str, Any]) -> bool:
        """Whether ``delta`` applied to ``state`` would fit the budget.

        Same measurement, same rule as :meth:`transition` -- a caller can
        ask before committing and get the same answer the transition would.
        """
        state = _check_mapping(state, "state")
        delta = _check_mapping(delta, "delta")
        projected = self.size_of(_apply_delta(state, delta))
        return projected <= self.max_state_size

    def bytes_over_budget(self, state: Any) -> int:
        """How many bytes ``state`` exceeds the budget by (0 when it fits).

        This is the caller's signal for how much to compact away.  This
        module does not compact; it only measures the shortfall.
        """
        size = self.size_of(state)
        over = size - self.max_state_size
        return over if over > 0 else 0
