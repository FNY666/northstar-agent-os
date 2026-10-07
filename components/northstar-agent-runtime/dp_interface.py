"""Differential-privacy mechanisms: Laplace and Gaussian noise, with composition.

Research basis (second-hand):
- Dwork / Roth "The Algorithmic Foundations of Differential Privacy": the
  Laplace mechanism (scale = sensitivity/epsilon) is pure epsilon-DP;
  the Gaussian mechanism with sigma = sensitivity*sqrt(2*ln(1.25/delta))/epsilon
  is (epsilon, delta)-DP for 0 < epsilon < 1.
- Kairouz, Oh, Viswanath composition bounds: naive sequential composition
  adds (epsilon, delta) across mechanisms.

This module is the *mechanism* half. The *ledger* half lives in
``dp_accountant`` (PrivacyAccountant / RDPAccountant): this module calibrates
noise and draws it, and offers :class:`DPComposer` as a lightweight
sequential-composition budget tracker for mechanism call sites. The caller is
responsible for recording spends in the accountant if it wants the durable
budget ceiling; DPComposer.fail-closed refuses a spend that would exceed the
declared budget.

Noise sourcing (load-bearing design decision):
- Production draws come from :mod:`secrets` (``SystemRandom``), not the
  global :mod:`random` state. Deterministic noise is NOT private noise, so
  determinism is never the default.
- For tests / audit replay, pass ``noise_seed=b"..."``: noise is then derived
  by SHA-256 expansion of (seed, per-mechanism counter), bit-for-bit
  replayable. The counter advances per call, so two calls never reuse a draw.

Calibration formulas (pinned, tested):
- Laplace: scale = sensitivity / epsilon; noise = Lap(0, scale).
- Gaussian: sigma = sensitivity * sqrt(2 * ln(1.25 / delta)) / epsilon.
  Caller may override sigma explicitly, but the (epsilon, delta) spend must
  still be declared - an explicit sigma does not waive accounting.

Composition:
- :meth:`DPComposer.spend` records one mechanism's (epsilon, delta) cost;
  exceeding the budget raises :class:`DPBudgetExhausted` and records nothing.
- :meth:`DPComposer.compose` merges two composers over the same declared
  budget (sequential composition: spends add). Budgets that disagree raise.

Honest scope: this is calibrated noise plus bookkeeping, not a privacy
proof. It cannot check that the sensitivity you passed is the true global
sensitivity of your query - a wrong sensitivity silently breaks the DP claim
while every function returns normally. Deterministic-seed noise is provided
for replayability and must never be used for production data. The Gaussian
calibration used here is the classic 0 < epsilon < 1 regime; out-of-regime
epsilons are rejected fail-closed rather than silently miscalibrated.
``NoisyResult`` records the true value for testability - production callers
should drop it (it is a privacy leak by construction).
"""

from __future__ import annotations

import hashlib
import math
import secrets
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

#: Module version pin. Bump on any semantic change.
DP_INTERFACE_VERSION = "dp-interface.v1"

#: Schema pin for audit records.
DP_INTERFACE_SCHEMA = "northstar.dp-interface.v1"

#: Deterministic-noise domain separation prefix.
_NOISE_DOMAIN = b"northstar.dp-interface.v1/noise"

#: Classic Gaussian calibration regime: 0 < epsilon < 1.
_GAUSSIAN_MAX_EPSILON = 1.0


class DPError(Exception):
    """Base error for differential-privacy mechanism failures."""


class DPBudgetExhausted(DPError):
    """A spend would exceed the declared privacy budget; nothing recorded."""

    def __init__(self, epsilon: float, delta: float,
                 budget_epsilon: float, budget_delta: float) -> None:
        super().__init__(
            f"spend ({epsilon}, {delta}) exceeds budget "
            f"({budget_epsilon}, {budget_delta})"
        )
        self.epsilon = epsilon
        self.delta = delta
        self.budget_epsilon = budget_epsilon
        self.budget_delta = budget_delta


class DPCalibrationError(DPError):
    """Mechanism parameters are outside the supported calibration regime."""


def _reject_bool(name: str, value: Any) -> None:
    if isinstance(value, bool):
        raise DPError(f"{name} must not be a bool")


def _check_finite_real(name: str, value: float) -> float:
    _reject_bool(name, value)
    if not isinstance(value, (int, float)):
        raise DPError(f"{name} must be a real number, got {type(value).__name__}")
    value = float(value)
    if not math.isfinite(value):
        raise DPError(f"{name} must be finite")
    return value


def _check_positive(name: str, value: float) -> float:
    value = _check_finite_real(name, value)
    if value <= 0.0:
        raise DPCalibrationError(f"{name} must be > 0")
    return value


def _check_delta(name: str, value: float) -> float:
    value = _check_finite_real(name, value)
    if not 0.0 < value < 1.0:
        raise DPCalibrationError(f"{name} must be in (0, 1)")
    return value


def laplace_scale(sensitivity: float, epsilon: float) -> float:
    """Return the Laplace scale b = sensitivity / epsilon (pure function)."""
    sensitivity = _check_positive("sensitivity", sensitivity)
    epsilon = _check_positive("epsilon", epsilon)
    return sensitivity / epsilon


def gaussian_sigma(sensitivity: float, epsilon: float, delta: float) -> float:
    """Calibrated sigma for the (epsilon, delta)-DP Gaussian mechanism.

    Classic calibration: sigma = sensitivity * sqrt(2 * ln(1.25 / delta)) / epsilon,
    valid for 0 < epsilon < 1.
    """
    sensitivity = _check_positive("sensitivity", sensitivity)
    epsilon = _check_positive("epsilon", epsilon)
    if epsilon >= _GAUSSIAN_MAX_EPSILON:
        raise DPCalibrationError(
            f"epsilon must be < {_GAUSSIAN_MAX_EPSILON} for the classic "
            "Gaussian calibration; use an explicit sigma instead"
        )
    delta = _check_delta("delta", delta)
    return sensitivity * math.sqrt(2.0 * math.log(1.25 / delta)) / epsilon


def _uniform53(seed: bytes, counter: int, stream: int) -> float:
    """Deterministic uniform draw in [2**-53, 1 - 2**-53] via SHA-256 expansion."""
    digest = hashlib.sha256(
        _NOISE_DOMAIN
        + seed
        + counter.to_bytes(8, "big")
        + stream.to_bytes(1, "big")
    ).digest()
    mantissa = int.from_bytes(digest[:7], "big") >> 3  # 53 bits
    # Clamp away from the endpoints so log() never sees 0.
    mantissa = min(max(mantissa, 1), 2**53 - 1)
    return mantissa / 2**53


def _laplace_draw(scale: float, seed: Optional[bytes], counter: int) -> float:
    if seed is not None:
        u = _uniform53(seed, counter, 0)
    else:
        u = secrets.SystemRandom().random()
        u = min(max(u, 2**-53), 1.0 - 2**-53)
    # Inverse CDF of Laplace(0, scale): -sign(u-1/2) * scale * ln(1 - 2|u-1/2|)
    return -math.copysign(1.0, u - 0.5) * scale * math.log(1.0 - 2.0 * abs(u - 0.5))


def _gaussian_draw(sigma: float, seed: Optional[bytes], counter: int) -> float:
    if seed is not None:
        u1 = _uniform53(seed, counter, 0)
        u2 = _uniform53(seed, counter, 1)
    else:
        rng = secrets.SystemRandom()
        u1 = min(max(rng.random(), 2**-53), 1.0 - 2**-53)
        u2 = rng.random()
    # Box-Muller.
    z = math.sqrt(-2.0 * math.log(u1)) * math.cos(2.0 * math.pi * u2)
    return sigma * z


@dataclass(frozen=True)
class NoisyResult:
    """One mechanism invocation: noisy answer plus the declared privacy cost.

    ``true_value`` is recorded for testability only - it is a privacy leak by
    construction and production callers must drop the record or strip it.
    """

    value: float
    true_value: float
    mechanism: str
    sensitivity: float
    epsilon: float
    delta: float
    noise: float
    schema: str = DP_INTERFACE_SCHEMA

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "mechanism": self.mechanism,
            "value": self.value,
            "true_value": self.true_value,
            "sensitivity": self.sensitivity,
            "epsilon": self.epsilon,
            "delta": self.delta,
            "noise": self.noise,
            "module_version": DP_INTERFACE_VERSION,
        }


@dataclass(frozen=True)
class SpendRecord:
    """One recorded privacy spend."""

    epsilon: float
    delta: float
    mechanism: str
    seq: int

    def as_dict(self) -> Dict[str, Any]:
        return {
            "epsilon": self.epsilon,
            "delta": self.delta,
            "mechanism": self.mechanism,
            "seq": self.seq,
        }


class DPMechanism:
    """Laplace / Gaussian mechanisms with replayable-or-real noise.

    Args:
        noise_seed: optional bytes enabling deterministic noise (tests/audit
            replay). ``None`` (default) draws from :mod:`secrets` - the only
            setting suitable for production data.
    """

    def __init__(self, noise_seed: Optional[bytes] = None) -> None:
        if noise_seed is not None:
            if not isinstance(noise_seed, (bytes, bytearray)) or not noise_seed:
                raise DPError("noise_seed must be non-empty bytes or None")
            noise_seed = bytes(noise_seed)
        self._seed = noise_seed
        self._counter = 0

    def _next_counter(self) -> int:
        self._counter += 1
        return self._counter

    def laplace(self, value: float, sensitivity: float, epsilon: float,
                *, noise_seed: Optional[bytes] = None) -> NoisyResult:
        """Release ``value`` with Laplace noise; pure epsilon-DP."""
        value = _check_finite_real("value", value)
        scale = laplace_scale(sensitivity, epsilon)
        seed = bytes(noise_seed) if noise_seed is not None else self._seed
        noise = _laplace_draw(scale, seed, self._next_counter())
        return NoisyResult(
            value=value + noise,
            true_value=value,
            mechanism="laplace",
            sensitivity=float(sensitivity),
            epsilon=float(epsilon),
            delta=0.0,
            noise=noise,
        )

    def gaussian(self, value: float, sensitivity: float, epsilon: float,
                 delta: float = 0.0, sigma: Optional[float] = None,
                 *, noise_seed: Optional[bytes] = None) -> NoisyResult:
        """Release ``value`` with Gaussian noise; (epsilon, delta)-DP.

        If ``sigma`` is omitted it is calibrated from (sensitivity, epsilon,
        delta). An explicit ``sigma`` overrides calibration but the
        (epsilon, delta) spend must still be declared - sigma never waives
        accounting.
        """
        value = _check_finite_real("value", value)
        sensitivity = _check_positive("sensitivity", sensitivity)
        epsilon = _check_positive("epsilon", epsilon)
        delta = _check_delta("delta", delta) if delta else 0.0
        if delta == 0.0:
            raise DPCalibrationError(
                "gaussian requires 0 < delta < 1 (pure epsilon-DP is not "
                "supported by the Gaussian mechanism)"
            )
        if sigma is None:
            sigma = gaussian_sigma(sensitivity, epsilon, delta)
        else:
            sigma = _check_positive("sigma", sigma)
        seed = bytes(noise_seed) if noise_seed is not None else self._seed
        noise = _gaussian_draw(sigma, seed, self._next_counter())
        return NoisyResult(
            value=value + noise,
            true_value=value,
            mechanism="gaussian",
            sensitivity=sensitivity,
            epsilon=epsilon,
            delta=delta,
            noise=noise,
        )


class DPComposer:
    """Sequential-composition budget tracker for mechanism call sites.

    Spends add up (basic composition). A spend that would exceed the declared
    budget raises :class:`DPBudgetExhausted` and is not recorded.
    """

    def __init__(self, budget_epsilon: float, budget_delta: float) -> None:
        self._budget_epsilon = _check_positive("budget_epsilon", budget_epsilon)
        self._budget_delta = _check_finite_real("budget_delta", budget_delta)
        if self._budget_delta < 0.0:
            raise DPCalibrationError("budget_delta must be >= 0")
        self._spends: List[SpendRecord] = []
        self._seq = 0

    def spend(self, epsilon: float, delta: float = 0.0,
              mechanism: str = "unknown") -> SpendRecord:
        """Record one mechanism's cost; fail-closed on budget exhaustion."""
        epsilon = _check_finite_real("epsilon", epsilon)
        delta = _check_finite_real("delta", delta)
        if epsilon < 0.0 or delta < 0.0:
            raise DPCalibrationError("spend (epsilon, delta) must be non-negative")
        if not isinstance(mechanism, str) or not mechanism:
            raise DPError("mechanism must be a non-empty string")
        spent_eps = sum(s.epsilon for s in self._spends)
        spent_del = sum(s.delta for s in self._spends)
        if (spent_eps + epsilon > self._budget_epsilon
                or spent_del + delta > self._budget_delta):
            raise DPBudgetExhausted(epsilon, delta,
                                    self._budget_epsilon, self._budget_delta)
        self._seq += 1
        record = SpendRecord(epsilon=epsilon, delta=delta,
                             mechanism=mechanism, seq=self._seq)
        self._spends.append(record)
        return record

    def spend_result(self, result: NoisyResult) -> SpendRecord:
        """Record the declared cost of a :class:`NoisyResult`."""
        if not isinstance(result, NoisyResult):
            raise DPError("spend_result expects a NoisyResult")
        return self.spend(result.epsilon, result.delta,
                          mechanism=result.mechanism)

    def spent(self) -> Tuple[float, float]:
        """Cumulative (epsilon, delta) spent so far."""
        return (sum(s.epsilon for s in self._spends),
                sum(s.delta for s in self._spends))

    def remaining(self) -> Tuple[float, float]:
        """Remaining (epsilon, delta) budget."""
        spent_eps, spent_del = self.spent()
        return (self._budget_epsilon - spent_eps,
                self._budget_delta - spent_del)

    def compose(self, other: "DPComposer") -> "DPComposer":
        """Sequentially compose two composers over the same declared budget.

        Returns a new composer whose spends are the union of both ledgers.
        Disagreeing budgets raise - composing ledgers declared under different
        budgets is meaningless.
        """
        if not isinstance(other, DPComposer):
            raise DPError("compose expects a DPComposer")
        if (other._budget_epsilon != self._budget_epsilon
                or other._budget_delta != self._budget_delta):
            raise DPCalibrationError(
                "compose requires identical declared budgets"
            )
        merged = DPComposer(self._budget_epsilon, self._budget_delta)
        for record in self._spends + other._spends:
            merged.spend(record.epsilon, record.delta,
                         mechanism=record.mechanism)
        return merged

    def ledger(self) -> Tuple[SpendRecord, ...]:
        """Immutable view of recorded spends."""
        return tuple(self._spends)

    def audit_event(self, seq: int) -> Dict[str, Any]:
        """Audit-log-shaped record of current budget state."""
        _reject_bool("seq", seq)
        if not isinstance(seq, int) or seq < 0:
            raise DPError("seq must be a non-negative int")
        spent_eps, spent_del = self.spent()
        return {
            "schema": "audit.ndjson/1",
            "module": "dp_interface",
            "module_version": DP_INTERFACE_VERSION,
            "seq": seq,
            "event": "dp-composition-state",
            "budget_epsilon": self._budget_epsilon,
            "budget_delta": self._budget_delta,
            "spent_epsilon": spent_eps,
            "spent_delta": spent_del,
            "spend_count": len(self._spends),
        }


def main() -> None:
    mech = DPMechanism(noise_seed=b"self-check")
    lap = mech.laplace(100.0, 1.0, 1.0)
    assert lap.mechanism == "laplace" and lap.delta == 0.0
    assert abs(lap.value - 100.0 - lap.noise) < 1e-12
    # Deterministic seed replays bit-identically.
    mech2 = DPMechanism(noise_seed=b"self-check")
    assert mech2.laplace(100.0, 1.0, 1.0).noise == lap.noise
    gauss = mech.gaussian(50.0, 1.0, 0.5, delta=1e-5)
    assert gauss.mechanism == "gaussian" and gauss.delta == 1e-5
    # Calibration pins.
    assert laplace_scale(2.0, 0.5) == 4.0
    assert abs(gaussian_sigma(1.0, 0.5, 1e-5)
               - math.sqrt(2.0 * math.log(1.25 / 1e-5)) / 0.5) < 1e-12
    # Composer: spends, budget ceiling, composition.
    comp = DPComposer(2.0, 1e-5)
    comp.spend_result(lap)
    comp.spend_result(gauss)
    assert comp.spent() == (1.5, 1e-5)
    assert comp.remaining() == (0.5, 0.0)
    try:
        comp.spend(1.0, 0.0)
        raise AssertionError("expected DPBudgetExhausted")
    except DPBudgetExhausted:
        pass
    other = DPComposer(2.0, 1e-5)
    other.spend(0.25, 0.0, mechanism="laplace")
    merged = comp.compose(other)
    assert merged.spent() == (1.75, 1e-5)
    print("dp-interface OK: laplace, gaussian, calibration, composition")


if __name__ == "__main__":
    main()
