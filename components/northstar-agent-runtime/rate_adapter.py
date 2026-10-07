"""Rate adapter: AIMD (Additive Increase / Multiplicative Decrease) adaptation.

Classic congestion-style adaptation used to throttle the rate at which the
agent performs an operation (e.g. tool calls, probes, network requests)
based on observed success/loss feedback.

Successes grow the rate additively; losses cut it multiplicatively (with a
floor), so the adapter converges to the sustainable rate of the resource.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional


@dataclass
class RateAdapter:
    """AIMD rate controller.

    - ``on_success()``: increase current rate additively by ``alpha``
      (capped at ``max_rate``).
    - ``on_loss()``: decrease current rate multiplicatively by ``beta``
      (floored at ``min_rate``).
    - ``current_rate()``: current adapted rate.
    """

    initial_rate: float = 10.0
    min_rate: float = 1.0
    max_rate: float = 100.0
    alpha: float = 1.0
    beta: float = 0.5
    clock: Callable[[], float] = field(default=time.monotonic, repr=False)

    def __post_init__(self) -> None:
        if self.min_rate <= 0:
            raise ValueError("min_rate must be > 0")
        if self.max_rate < self.min_rate:
            raise ValueError("max_rate must be >= min_rate")
        if not 0.0 < self.beta < 1.0:
            raise ValueError("beta must be in (0, 1)")
        if self.alpha <= 0:
            raise ValueError("alpha must be > 0")
        self._rate: float = max(
            self.min_rate, min(self.max_rate, self.initial_rate)
        )
        self._successes: int = 0
        self._losses: int = 0
        self._consecutive_losses: int = 0
        self._history: List[tuple] = []
        self._record(self._rate)

    # -- feedback -----------------------------------------------------
    def on_success(self) -> float:
        """Record a success; additive increase. Returns the new rate."""
        self._rate = min(self.max_rate, self._rate + self.alpha)
        self._successes += 1
        self._consecutive_losses = 0
        self._record(self._rate)
        return self._rate

    def on_loss(self) -> float:
        """Record a loss; multiplicative decrease. Returns the new rate."""
        self._rate = max(self.min_rate, self._rate * self.beta)
        self._losses += 1
        self._consecutive_losses += 1
        self._record(self._rate)
        return self._rate

    # -- introspection ------------------------------------------------
    def current_rate(self) -> float:
        """Return the current adapted rate."""
        return self._rate

    @property
    def successes(self) -> int:
        return self._successes

    @property
    def losses(self) -> int:
        return self._losses

    @property
    def consecutive_losses(self) -> int:
        return self._consecutive_losses

    @property
    def loss_rate(self) -> float:
        """Fraction of recorded events that were losses (0.0 if none)."""
        total = self._successes + self._losses
        if total == 0:
            return 0.0
        return self._losses / total

    @property
    def history(self) -> List[tuple]:
        """Snapshot of (timestamp, rate) after each adaptation event."""
        return list(self._history)

    # -- helpers ------------------------------------------------------
    def _record(self, rate: float) -> None:
        self._history.append((self.clock(), rate))

    def reset(self, rate: Optional[float] = None) -> float:
        """Reset counters and optionally re-seed the rate."""
        self._successes = 0
        self._losses = 0
        self._consecutive_losses = 0
        if rate is not None:
            self._rate = max(self.min_rate, min(self.max_rate, rate))
        self._record(self._rate)
        return self._rate
