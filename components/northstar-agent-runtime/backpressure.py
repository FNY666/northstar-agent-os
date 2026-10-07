"""Backpressure: reactive-streams demand signaling for a bounded agent pipeline.

Research note: *backpressure* is the demand-driven flow-control contract of
the Reactive Streams spec (Bonér et al., 2014; adopted by RxJava 2, Akka
Streams, Project Reactor, java.util.concurrent.Flow). In a push-based
publisher/subscriber system, an unbounded producer can overwhelm a slow
consumer — overflowing buffers, spiking latency, or OOM-killing the host.
The spec fixes the direction of control: the *subscriber* signals how many
items it is ready to receive (``request(n)``), the *publisher* must not emit
more than the outstanding demand (spec rule 1.1: "the total number of
``onNext`` signals ... must be less than or equal to the ... outstanding
demand"), and either side may ``cancel()`` to terminate the flow.

* **Demand signaling** — ``request(n)`` adds *n* to the outstanding demand.
  A producer calls ``on_next()`` before emitting each item; ``on_next()``
  consumes one unit of demand and reports the remainder, so a correct
  producer checks demand before emitting and never emits blind.
* **Fail-closed request** — spec rule 3.9: a non-positive ``request``
  must signal an error. Here that is :class:`BackpressureError`: a
  non-positive or non-int demand is a programming error, not silent
  zero-demand.
* **Overflow is an error** — spec rule 1.1: a producer calling
  ``on_next()`` with zero outstanding demand violates the contract and
  raises :class:`BackpressureOverflowError` instead of silently growing
  an unbounded buffer. The violation is *prevented*, not absorbed.
* **Demand arithmetic caps** — spec rule 3.17: cumulative demand must
  saturate at ``MAX_DEMAND`` (2**63 - 1) rather than wrapping or raising.
  An unbounded consumer requests ``Backpressure.UNBOUNDED``.
* **Cancel** — ``cancel()`` marks the subscription terminated and clears
  outstanding demand; it is idempotent. Any ``request``/``on_next`` after
  cancel is a programming error and raises ``BackpressureError``
  fail-closed (a producer that keeps emitting after cancel is leaking).

Honest scope: this is the *demand accounting* side of the contract, not a
scheduler — it cannot see a producer that ignores it and emits directly to
the consumer, and it cannot detect demand signaled through a side channel
(a raw integer shared outside this object). ``demand > 0`` means "the
producer is *allowed* to emit that many", never "the consumer will keep
up". A quiet controller means "no known contract violation", never "no
overload".

Version pin: backpressure.v1
Schema pin: northstar.backpressure.v1
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

#: Module version.
BACKPRESSURE_VERSION = "backpressure.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.backpressure.v1"


class BackpressureError(Exception):
    """Malformed use of the backpressure contract (programming error)."""


class BackpressureOverflowError(BackpressureError):
    """Producer emitted with zero outstanding demand (contract violation)."""


def _check_demand(value: Any, name: str = "n") -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BackpressureError(f"{name} must be an int, got {type(value).__name__}")
    if value <= 0:
        raise BackpressureError(f"{name} must be positive, got {value}")
    return value


@dataclass(frozen=True)
class BackpressureRecord:
    """One demand-state snapshot (frozen record)."""

    version: str
    demand: int
    delivered: int
    cancelled: bool
    overflows: int

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "version": self.version,
            "demand": self.demand,
            "delivered": self.delivered,
            "cancelled": self.cancelled,
            "overflows": self.overflows,
        }


class Backpressure:
    """Reactive-streams demand controller for one subscriber.

    The subscriber (slow consumer) owns demand via :meth:`request`; the
    producer checks it by calling :meth:`on_next` before each emission.
    Either side may :meth:`cancel` to terminate.
    """

    #: Demand value meaning "no bound" (saturates at the cap).
    UNBOUNDED = 2**63 - 1

    #: Arithmetic saturation point (Reactive Streams spec rule 3.17).
    MAX_DEMAND = 2**63 - 1

    def __init__(self) -> None:
        self._demand = 0
        self._delivered = 0
        self._cancelled = False
        self._overflows = 0

    @property
    def demand(self) -> int:
        """Outstanding demand (items the producer is allowed to emit)."""
        return self._demand

    @property
    def delivered(self) -> int:
        """Items consumed via ``on_next`` since construction."""
        return self._delivered

    @property
    def cancelled(self) -> bool:
        """True after :meth:`cancel` (terminal)."""
        return self._cancelled

    @property
    def overflows(self) -> int:
        """Times a producer attempted emission with zero demand."""
        return self._overflows

    def request(self, n: int) -> int:
        """Add *n* to outstanding demand; returns the new demand.

        ``request`` after ``cancel`` raises ``BackpressureError``: the
        subscription is terminated, so new demand is a programming error.
        Cumulative demand saturates at :attr:`MAX_DEMAND`.
        """
        _check_demand(n)
        if self._cancelled:
            raise BackpressureError("request after cancel: subscription is terminated")
        self._demand = min(self.MAX_DEMAND, self._demand + n)
        return self._demand

    def cancel(self) -> None:
        """Terminate the subscription (idempotent); clears demand."""
        if not self._cancelled:
            self._cancelled = True
            self._demand = 0

    def on_next(self) -> int:
        """Consume one unit of demand before emitting; returns remaining.

        Raises ``BackpressureOverflowError`` when outstanding demand is
        zero (producer emitting without demand), and
        ``BackpressureError`` when called after ``cancel``.
        """
        if self._cancelled:
            raise BackpressureError("on_next after cancel: subscription is terminated")
        if self._demand <= 0:
            self._overflows += 1
            raise BackpressureOverflowError(
                "producer emitted with zero outstanding demand"
            )
        self._demand -= 1
        self._delivered += 1
        return self._demand

    def snapshot(self) -> BackpressureRecord:
        """Frozen snapshot of the controller state."""
        return BackpressureRecord(
            version=BACKPRESSURE_VERSION,
            demand=self._demand,
            delivered=self._delivered,
            cancelled=self._cancelled,
            overflows=self._overflows,
        )


def backpressure_audit_event(seq: int, record: BackpressureRecord) -> dict:
    """Wrap a snapshot record as an audit event dict."""
    event = record.as_dict()
    event["audit_seq"] = seq
    event["event"] = "backpressure"
    return event


def main() -> None:
    """Self-check: demand flow, overflow prevention, cancel semantics."""
    bp = Backpressure()
    assert bp.demand == 0 and not bp.cancelled

    assert bp.request(3) == 3
    assert bp.on_next() == 2
    assert bp.on_next() == 1
    assert bp.on_next() == 0
    assert bp.delivered == 3

    try:
        bp.on_next()
    except BackpressureOverflowError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected BackpressureOverflowError")
    assert bp.overflows == 1

    assert bp.request(Backpressure.UNBOUNDED) == Backpressure.MAX_DEMAND
    assert bp.request(Backpressure.UNBOUNDED) == Backpressure.MAX_DEMAND  # saturates

    bp.cancel()
    assert bp.cancelled and bp.demand == 0
    bp.cancel()  # idempotent
    try:
        bp.request(1)
    except BackpressureError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected BackpressureError after cancel")
    try:
        bp.on_next()
    except BackpressureError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected BackpressureError after cancel")

    print("backpressure OK: demand accounting, overflow prevention, cancel semantics")


if __name__ == "__main__":
    main()
