"""Differential privacy budget accounting for training pipelines.

DP-SGD (and any differentially private mechanism) spends a privacy budget:
each training step consumes some (epsilon, delta), and the composition of
all steps must stay under the declared budget. Spending beyond the budget
is not an accounting nicety — it is a privacy violation, because the
published (epsilon, delta) guarantee no longer holds.

This module is the accountant half of that guarantee. The *mechanism* half
(noise calibration, clipping, sampling) is the trainer's job; this module
records spends, enforces the ceiling fail-closed, and converts RDP moments
to (epsilon, delta) so the declared guarantee stays honest.

Two accountants:

* :class:`PrivacyAccountant` — basic (linear) composition. Each ``spend()``
  adds (epsilon, delta) to the ledger; a spend that would push cumulative
  (epsilon, delta) past the budget raises :class:`PrivacyBudgetExhausted`
  and is *not* recorded. Append-only, deterministic, no wall-clock.
* :class:`RDPAccountant` — Renyi differential privacy moments accounting.
  Each step records ``rdp_alpha`` costs per order; ``to_epsilon_delta()``
  applies the RDP-to-DP conversion (epsilon = min_alpha rdp + log(1/delta) /
  (alpha - 1)) and checks against the declared budget.

Honest scope: this is a ledger and a gate, not a privacy proof. It cannot
verify that the trainer's noise actually matched the spent epsilon — the
mechanism calibration is upstream and out of scope. A clean accountant says
"the ledger never exceeded the declared budget", never "the training was
differentially private". Budgets must be positive; zero-epsilon spends are
rejected as meaningless (epsilon = 0 with delta > 0 is not a valid DP
statement for this accountant); bool-typed numerics are rejected as
programming errors.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Optional

#: Module version pin. Bump on any semantic change.
DP_ACCOUNTANT_VERSION = "dp-accountant.v1"

#: Schema pin for audit records.
DP_ACCOUNTANT_SCHEMA = "northstar.dp-accountant.v1"


class PrivacyBudgetExhausted(Exception):
    """Raised when a spend would exceed the declared privacy budget.

    The refused spend is not recorded. The accountant's ledger is unchanged,
    so the caller can decide whether to stop training, increase noise, or
    (explicitly, as a policy decision) raise the budget.

    Attributes:
        epsilon: the refused spend's epsilon.
        delta: the refused spend's delta.
        budget_epsilon: the declared epsilon budget.
        budget_delta: the declared delta budget.
    """

    def __init__(
        self,
        epsilon: float,
        delta: float,
        budget_epsilon: float,
        budget_delta: float,
    ) -> None:
        self.epsilon = epsilon
        self.delta = delta
        self.budget_epsilon = budget_epsilon
        self.budget_delta = budget_delta
        super().__init__(
            f"privacy budget exhausted: spend ({epsilon}, {delta}) exceeds "
            f"budget ({budget_epsilon}, {budget_delta})"
        )


def _check_non_negative_number(value: Any, name: str) -> float:
    """Validate a budget/spend numeric; fail closed on bad input."""
    if isinstance(value, bool):
        raise TypeError(f"{name} must be a number, not bool")
    if not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be a number, got {type(value).__name__}")
    value = float(value)
    if not math.isfinite(value):
        raise ValueError(f"{name} must be finite, got {value}")
    if value < 0:
        raise ValueError(f"{name} must be non-negative, got {value}")
    return value


@dataclass(frozen=True)
class SpendRecord:
    """One recorded privacy spend (append-only ledger entry).

    Attributes:
        seq: caller-supplied monotonically increasing sequence number —
            the training step. No wall-clock is used anywhere in this
            module; the caller owns time.
        epsilon: epsilon consumed by this step.
        delta: delta consumed by this step.
        label: optional human-readable label (e.g. "epoch-3-step-120").
    """

    seq: int
    epsilon: float
    delta: float
    label: str = ""

    def __post_init__(self) -> None:
        if isinstance(self.seq, bool) or not isinstance(self.seq, int):
            raise TypeError("seq must be an int")
        if self.seq < 0:
            raise ValueError("seq must be non-negative")
        if not isinstance(self.label, str):
            raise TypeError("label must be a string")
        _check_non_negative_number(self.epsilon, "epsilon")
        _check_non_negative_number(self.delta, "delta")
        if self.epsilon == 0.0 and self.delta > 0.0:
            raise ValueError("epsilon=0 with delta>0 is not a valid DP spend")


class PrivacyAccountant:
    """Basic-composition (epsilon, delta) privacy budget accountant.

    Constructor args:
        budget_epsilon: total epsilon the training run may spend (> 0).
        budget_delta: total delta the training run may spend (>= 0; a
            pure-epsilon guarantee uses 0.0).

    The ledger is append-only: spends are recorded with caller-supplied
    ``seq`` numbers, and composition is linear (basic composition theorem).
    A spend that would exceed either ceiling raises
    :class:`PrivacyBudgetExhausted` and leaves the ledger unchanged.
    """

    def __init__(self, budget_epsilon: float, budget_delta: float = 0.0) -> None:
        budget_epsilon = _check_non_negative_number(budget_epsilon, "budget_epsilon")
        if budget_epsilon <= 0.0:
            raise ValueError("budget_epsilon must be positive")
        budget_delta = _check_non_negative_number(budget_delta, "budget_delta")
        self._budget_epsilon = budget_epsilon
        self._budget_delta = budget_delta
        self._ledger: list[SpendRecord] = []
        self._last_seq: Optional[int] = None

    @property
    def budget_epsilon(self) -> float:
        return self._budget_epsilon

    @property
    def budget_delta(self) -> float:
        return self._budget_delta

    def spend(
        self,
        epsilon_delta: tuple[float, float],
        seq: int,
        label: str = "",
    ) -> SpendRecord:
        """Record one training step's privacy spend.

        Args:
            epsilon_delta: ``(epsilon, delta)`` consumed by this step.
            seq: caller-supplied step sequence number; must be strictly
                greater than the previous spend's seq (out-of-order spends
                are rejected — the ledger is a training-order record).
            label: optional label for the spend.

        Returns:
            The recorded :class:`SpendRecord`.

        Raises:
            PrivacyBudgetExhausted: if the spend would push cumulative
                (epsilon, delta) over budget. Nothing is recorded.
            TypeError / ValueError: on malformed input (fail-closed).
        """
        if not isinstance(epsilon_delta, tuple) or len(epsilon_delta) != 2:
            raise TypeError("epsilon_delta must be a (epsilon, delta) tuple")
        epsilon = _check_non_negative_number(epsilon_delta[0], "epsilon")
        delta = _check_non_negative_number(epsilon_delta[1], "delta")
        if epsilon == 0.0 and delta > 0.0:
            raise ValueError("epsilon=0 with delta>0 is not a valid DP spend")
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise TypeError("seq must be an int")
        if seq < 0:
            raise ValueError("seq must be non-negative")
        if not isinstance(label, str):
            raise TypeError("label must be a string")
        if self._last_seq is not None and seq <= self._last_seq:
            raise ValueError(
                f"seq must be strictly increasing (last={self._last_seq}, got={seq})"
            )
        spent_epsilon, spent_delta = self.get_privacy_spent()
        if spent_epsilon + epsilon > self._budget_epsilon:
            raise PrivacyBudgetExhausted(
                epsilon, delta, self._budget_epsilon, self._budget_delta
            )
        if spent_delta + delta > self._budget_delta:
            raise PrivacyBudgetExhausted(
                epsilon, delta, self._budget_epsilon, self._budget_delta
            )
        record = SpendRecord(seq=seq, epsilon=epsilon, delta=delta, label=label)
        self._ledger.append(record)
        self._last_seq = seq
        return record

    def get_privacy_spent(self) -> tuple[float, float]:
        """Return cumulative ``(epsilon, delta)`` spent so far."""
        epsilon = sum(r.epsilon for r in self._ledger)
        delta = sum(r.delta for r in self._ledger)
        return (epsilon, delta)

    def remaining(self) -> tuple[float, float]:
        """Return remaining ``(epsilon, delta)`` budget."""
        spent_epsilon, spent_delta = self.get_privacy_spent()
        return (
            self._budget_epsilon - spent_epsilon,
            self._budget_delta - spent_delta,
        )

    def can_spend(self, epsilon_delta: tuple[float, float]) -> bool:
        """Return True iff this spend would fit the remaining budget."""
        try:
            epsilon = _check_non_negative_number(epsilon_delta[0], "epsilon")
            delta = _check_non_negative_number(epsilon_delta[1], "delta")
        except (TypeError, ValueError):
            return False
        spent_epsilon, spent_delta = self.get_privacy_spent()
        return (
            spent_epsilon + epsilon <= self._budget_epsilon
            and spent_delta + delta <= self._budget_delta
        )

    def ledger(self) -> tuple[SpendRecord, ...]:
        """Return the append-only spend ledger (oldest first)."""
        return tuple(self._ledger)

    def compose(self, other: "PrivacyAccountant") -> "PrivacyAccountant":
        """Return a new accountant covering this ledger plus ``other``'s.

        Both ledgers must be combinable: the result's budget is the sum of
        the two budgets, and the result's ledger concatenates both ledgers
        in seq order (raises ValueError if seq ranges overlap — the two
        accountants must cover disjoint training runs).
        """
        if not isinstance(other, PrivacyAccountant):
            raise TypeError("can only compose with another PrivacyAccountant")
        my_spent_epsilon, my_spent_delta = self.get_privacy_spent()
        ot_spent_epsilon, ot_spent_delta = other.get_privacy_spent()
        merged = PrivacyAccountant(
            self._budget_epsilon + other._budget_epsilon,
            self._budget_delta + other._budget_delta,
        )
        combined = self._ledger + other._ledger
        combined.sort(key=lambda r: r.seq)
        for i in range(1, len(combined)):
            if combined[i].seq == combined[i - 1].seq:
                raise ValueError(
                    f"overlapping seq {combined[i].seq}: ledgers must cover "
                    "disjoint training runs"
                )
        # Bypass per-spend ceiling checks — the merged ledger already fit
        # each accountant's own budget, and the merged budget is the sum.
        for record in combined:
            merged._ledger.append(record)
            merged._last_seq = record.seq
        assert math.isclose(
            merged.get_privacy_spent()[0], my_spent_epsilon + ot_spent_epsilon
        )
        assert math.isclose(
            merged.get_privacy_spent()[1], my_spent_delta + ot_spent_delta
        )
        return merged

    def audit_event(self, seq: int) -> dict[str, Any]:
        """Return an audit-log-shaped record of current budget state."""
        spent_epsilon, spent_delta = self.get_privacy_spent()
        return {
            "schema": "audit.ndjson/1",
            "module": "dp_accountant",
            "module_version": DP_ACCOUNTANT_VERSION,
            "seq": seq,
            "event": "privacy-budget-state",
            "budget_epsilon": self._budget_epsilon,
            "budget_delta": self._budget_delta,
            "spent_epsilon": spent_epsilon,
            "spent_delta": spent_delta,
            "spend_count": len(self._ledger),
        }

    def __repr__(self) -> str:
        spent_epsilon, spent_delta = self.get_privacy_spent()
        return (
            f"PrivacyAccountant(budget=({self._budget_epsilon}, "
            f"{self._budget_delta}), spent=({spent_epsilon}, {spent_delta}), "
            f"records={len(self._ledger)})"
        )


@dataclass(frozen=True)
class RDPStep:
    """One RDP step: per-order Renyi costs at this training step.

    Attributes:
        seq: caller-supplied step sequence number.
        orders: tuple of Renyi orders (alpha > 1), strictly increasing.
        costs: tuple of rdp_alpha costs, parallel to ``orders``.
    """

    seq: int
    orders: tuple[float, ...]
    costs: tuple[float, ...]

    def __post_init__(self) -> None:
        if isinstance(self.seq, bool) or not isinstance(self.seq, int):
            raise TypeError("seq must be an int")
        if self.seq < 0:
            raise ValueError("seq must be non-negative")
        if not self.orders:
            raise ValueError("orders must be non-empty")
        if len(self.orders) != len(self.costs):
            raise ValueError("orders and costs must have the same length")
        for alpha in self.orders:
            if isinstance(alpha, bool) or not isinstance(alpha, (int, float)):
                raise TypeError("orders must be numbers")
            if alpha <= 1.0:
                raise ValueError(f"Renyi order must be > 1, got {alpha}")
        for i in range(1, len(self.orders)):
            if self.orders[i] <= self.orders[i - 1]:
                raise ValueError("orders must be strictly increasing")
        for cost in self.costs:
            _check_non_negative_number(cost, "rdp cost")


class RDPAccountant:
    """Renyi DP moments accountant with (epsilon, delta) conversion.

    Constructor args:
        orders: Renyi orders (alpha > 1) to track.
        budget_epsilon: epsilon ceiling for converted guarantees (> 0).
        target_delta: delta at which converted epsilon is evaluated
            (must be in (0, 1)).

    Conversion theorem: a mechanism that is (alpha, rdp)-RDP is also
    (rdp + log(1/delta)/(alpha-1), delta)-DP for any alpha > 1 and
    delta in (0, 1). This accountant takes the minimum over tracked
    orders.
    """

    def __init__(
        self,
        orders: tuple[float, ...],
        budget_epsilon: float,
        target_delta: float,
    ) -> None:
        if not orders:
            raise ValueError("orders must be non-empty")
        self._orders = tuple(float(a) for a in orders)
        for alpha in self._orders:
            if alpha <= 1.0:
                raise ValueError(f"Renyi order must be > 1, got {alpha}")
        if list(self._orders) != sorted(self._orders) or len(set(self._orders)) != len(
            self._orders
        ):
            raise ValueError("orders must be strictly increasing")
        budget_epsilon = _check_non_negative_number(budget_epsilon, "budget_epsilon")
        if budget_epsilon <= 0.0:
            raise ValueError("budget_epsilon must be positive")
        if isinstance(target_delta, bool) or not isinstance(target_delta, (int, float)):
            raise TypeError("target_delta must be a number")
        target_delta = float(target_delta)
        if not (0.0 < target_delta < 1.0):
            raise ValueError("target_delta must be in (0, 1)")
        self._budget_epsilon = budget_epsilon
        self._target_delta = target_delta
        self._totals = [0.0] * len(self._orders)
        self._steps: list[RDPStep] = []
        self._last_seq: Optional[int] = None

    @property
    def orders(self) -> tuple[float, ...]:
        return self._orders

    @property
    def budget_epsilon(self) -> float:
        return self._budget_epsilon

    @property
    def target_delta(self) -> float:
        return self._target_delta

    def spend(self, step: RDPStep) -> RDPStep:
        """Record one RDP step's per-order costs.

        Raises :class:`PrivacyBudgetExhausted` if the converted epsilon
        would exceed the budget; the step is then not recorded.
        """
        if not isinstance(step, RDPStep):
            raise TypeError("step must be an RDPStep")
        if tuple(step.orders) != self._orders:
            raise ValueError(
                f"step orders {step.orders} do not match accountant orders {self._orders}"
            )
        if self._last_seq is not None and step.seq <= self._last_seq:
            raise ValueError(
                f"seq must be strictly increasing (last={self._last_seq}, got={step.seq})"
            )
        trial = [t + c for t, c in zip(self._totals, step.costs)]
        epsilon = self._convert(trial)
        if epsilon > self._budget_epsilon:
            raise PrivacyBudgetExhausted(
                epsilon, self._target_delta, self._budget_epsilon, self._target_delta
            )
        self._totals = trial
        self._steps.append(step)
        self._last_seq = step.seq
        return step

    def _convert(self, totals: list[float]) -> float:
        """RDP-to-DP conversion: min over orders of the epsilon bound."""
        log_term = math.log(1.0 / self._target_delta)
        best = math.inf
        for alpha, total in zip(self._orders, totals):
            epsilon = total + log_term / (alpha - 1.0)
            if epsilon < best:
                best = epsilon
        return best

    def to_epsilon_delta(self) -> tuple[float, float]:
        """Return the converted ``(epsilon, target_delta)`` guarantee."""
        return (self._convert(list(self._totals)), self._target_delta)

    def can_spend(self, costs: tuple[float, ...]) -> bool:
        """Return True iff a step with these costs would fit the budget."""
        if len(costs) != len(self._orders):
            return False
        try:
            for cost in costs:
                _check_non_negative_number(cost, "rdp cost")
        except (TypeError, ValueError):
            return False
        trial = [t + c for t, c in zip(self._totals, costs)]
        return self._convert(trial) <= self._budget_epsilon

    def step_count(self) -> int:
        return len(self._steps)

    def audit_event(self, seq: int) -> dict[str, Any]:
        epsilon, delta = self.to_epsilon_delta()
        return {
            "schema": "audit.ndjson/1",
            "module": "dp_accountant",
            "module_version": DP_ACCOUNTANT_VERSION,
            "seq": seq,
            "event": "rdp-budget-state",
            "budget_epsilon": self._budget_epsilon,
            "target_delta": self._target_delta,
            "converted_epsilon": epsilon,
            "step_count": len(self._steps),
        }

    def __repr__(self) -> str:
        epsilon, delta = self.to_epsilon_delta()
        return (
            f"RDPAccountant(orders={self._orders}, budget_epsilon="
            f"{self._budget_epsilon}, target_delta={self._target_delta}, "
            f"converted=({epsilon}, {delta}), steps={len(self._steps)})"
        )


def main() -> None:
    """Self-check: spend within budget, refuse over budget, RDP converts."""
    acc = PrivacyAccountant(1.0, 1e-5)
    acc.spend((0.1, 1e-6), seq=0, label="step-0")
    acc.spend((0.1, 1e-6), seq=1, label="step-1")
    spent = acc.get_privacy_spent()
    assert spent == (0.2, 2e-6), spent
    try:
        acc.spend((0.9, 0.0), seq=2)
    except PrivacyBudgetExhausted:
        pass
    else:
        raise AssertionError("over-budget spend should raise")
    assert acc.get_privacy_spent() == (0.2, 2e-6)  # refused spend not recorded

    rdp = RDPAccountant((2.0, 4.0, 8.0), budget_epsilon=5.0, target_delta=1e-5)
    rdp.spend(RDPStep(seq=0, orders=(2.0, 4.0, 8.0), costs=(0.05, 0.02, 0.01)))
    epsilon, delta = rdp.to_epsilon_delta()
    assert delta == 1e-5
    assert 0.0 < epsilon <= 5.0, epsilon
    print(
        f"dp-accountant OK: basic spent={acc.get_privacy_spent()}, "
        f"rdp converted epsilon={epsilon:.4f}"
    )


if __name__ == "__main__":
    main()
