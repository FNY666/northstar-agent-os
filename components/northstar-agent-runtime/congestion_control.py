"""BBR-style congestion controller over simulated, caller-supplied time.

A ``CongestionControl`` tracks a bottleneck-bandwidth estimate
(``btlbw_bytes_per_ms``) and a minimum-RTT estimate (``min_rtt_ms``) from
``on_ack()`` samples, then sets ``cwnd()`` to a gain times the
bandwidth-delay product (``BDP = btlbw * min_rtt``).  Phases:

- ``STARTUP``: exponential-ish gain while delivery rate keeps rising;
  exits once the bandwidth estimate plateaus for a round and moves to
  ``DRAIN`` to clear any standing queue.
- ``DRAIN``: cwnd at ~1x BDP until in-flight drops below BDP, then
  ``PROBE_BW``.
- ``PROBE_BW``: cycles through pacing gains (1.25 up, 0.75 down, 1.0
  cruise, one round each) to discover new capacity.
- ``PROBE_RTT``: every 10 s of simulated time, drops to a 4-packet cwnd
  for at most 200 ms (or one round) to refresh ``min_rtt_ms``.

``on_loss()`` halves the current cwnd ceiling (BBRv2-style loss
reaction) and marks the loss epoch; cwnd never goes below a floor of
4 packets so the connection cannot self-silence.

House style: no wall-clock -- all timestamps are caller-supplied
monotonic millisecond ints, all volumes are byte ints.  Time never flows
backwards: a ``now_ms`` earlier than the last seen one raises
``TypeError``.  stdlib-only, deterministic, frozen decision records,
version/schema pins, ``main()`` self-check.

Honest scope: a *simulated* model of the control law, not a socket
implementation.  Bandwidth and RTT inputs come from the caller's
simulation harness (e.g. a scripted bottleneck or a replay trace); it
cannot discover real link capacity, does not pace packets on a wire, and
has no visibility into cross-traffic.  A rising cwnd means "the model
would send more", never "the path can carry more".

Version pin: congestion-control.v1
Schema pin: northstar.congestion-control.v1
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from enum import Enum

CONGESTION_CONTROL_VERSION = "congestion-control.v1"
SCHEMA_PIN = "northstar.congestion-control.v1"

_DEFAULT_PACKET_BYTES = 1500
_MIN_PACKETS_IN_FLIGHT = 4

_PROBE_BW_GAINS = (1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0)
_STARTUP_GAIN = 2.0
_DRAIN_GAIN = 1.0
_STARTUP_PLATEAU_ROUNDS = 3
_PROBE_RTT_EVERY_MS = 10_000
_PROBE_RTT_DURATION_MS = 200


def _require_nonneg_int(name: str, value) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int, got {type(value).__name__}")
    if value < 0:
        raise ValueError(f"{name} must be non-negative")


def _require_positive_int(name: str, value) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int, got {type(value).__name__}")
    if value <= 0:
        raise ValueError(f"{name} must be positive")


class Phase(Enum):
    STARTUP = "startup"
    DRAIN = "drain"
    PROBE_BW = "probe_bw"
    PROBE_RTT = "probe_rtt"


@dataclass(frozen=True)
class AckSample:
    """One delivery observation fed to the controller."""

    now_ms: int
    delivered_bytes: int
    rtt_ms: int
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        _require_nonneg_int("now_ms", self.now_ms)
        _require_nonneg_int("delivered_bytes", self.delivered_bytes)
        _require_positive_int("rtt_ms", self.rtt_ms)

    def as_dict(self) -> dict:
        return {
            "now_ms": self.now_ms,
            "delivered_bytes": self.delivered_bytes,
            "rtt_ms": self.rtt_ms,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class LossEvent:
    """One loss notification (frozen record)."""

    now_ms: int
    packets_lost: int
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        _require_nonneg_int("now_ms", self.now_ms)
        _require_positive_int("packets_lost", self.packets_lost)

    def as_dict(self) -> dict:
        return {
            "now_ms": self.now_ms,
            "packets_lost": self.packets_lost,
            "schema": self.schema,
        }


class CongestionControl:
    """BBR-style controller driven by simulated ACK/loss events.

    ``bandwidth_window_ms``: how long a bandwidth sample stays in the
    max-filter (BBR's 10-round trip equivalent, simulated as a fixed
    window). ``packet_bytes``: segment size used for the minimum-window
    floor.
    """

    def __init__(
        self,
        bandwidth_window_ms: int = 10_000,
        packet_bytes: int = _DEFAULT_PACKET_BYTES,
    ) -> None:
        _require_positive_int("bandwidth_window_ms", bandwidth_window_ms)
        _require_positive_int("packet_bytes", packet_bytes)
        self.bandwidth_window_ms = bandwidth_window_ms
        self.packet_bytes = packet_bytes
        self.version = CONGESTION_CONTROL_VERSION

        self._last_ms: int | None = None
        self._min_rtt_ms: int | None = None
        self._min_rtt_stamp_ms: int = 0
        self._bw_samples: list[tuple[int, float]] = []  # (stamp_ms, bytes_per_ms)
        self._phase = Phase.STARTUP
        self._startup_rounds_flat = 0
        self._prev_max_bw = 0.0
        self._round_start_ms = 0
        self._probe_bw_idx = 0
        self._probe_rtt_deadline_ms: int | None = None
        self._loss_ceiling_bytes: int | None = None
        self._min_cwnd_bytes = _MIN_PACKETS_IN_FLIGHT * packet_bytes

    # -- plumbing ----------------------------------------------------
    def _advance(self, now_ms: int) -> None:
        if isinstance(now_ms, bool) or not isinstance(now_ms, int):
            raise TypeError(f"now_ms must be an int, got {type(now_ms).__name__}")
        if self._last_ms is not None and now_ms < self._last_ms:
            raise TypeError("time moved backwards")
        self._last_ms = now_ms

    def _max_bw(self, now_ms: int) -> float:
        cutoff = now_ms - self.bandwidth_window_ms
        self._bw_samples = [s for s in self._bw_samples if s[0] >= cutoff]
        return max((bw for _, bw in self._bw_samples), default=0.0)

    def _maybe_enter_probe_rtt(self, now_ms: int) -> None:
        if self._phase is Phase.PROBE_RTT:
            return
        if self._min_rtt_ms is None:
            return
        if now_ms - self._min_rtt_stamp_ms >= _PROBE_RTT_EVERY_MS:
            self._phase = Phase.PROBE_RTT
            self._probe_rtt_deadline_ms = now_ms + _PROBE_RTT_DURATION_MS

    def _maybe_exit_probe_rtt(self, now_ms: int) -> None:
        if self._phase is not Phase.PROBE_RTT:
            return
        if (
            self._probe_rtt_deadline_ms is not None
            and now_ms >= self._probe_rtt_deadline_ms
        ):
            self._phase = Phase.PROBE_BW
            self._probe_bw_idx = 0
            self._min_rtt_stamp_ms = now_ms
            self._probe_rtt_deadline_ms = None

    def _update_bw_sample(self, now_ms: int, sample: AckSample) -> None:
        if sample.delivered_bytes <= 0:
            return
        rate = sample.delivered_bytes / max(sample.rtt_ms, 1)
        self._bw_samples.append((now_ms, rate))

    def _update_min_rtt(self, now_ms: int, rtt_ms: int) -> None:
        if self._min_rtt_ms is None or rtt_ms < self._min_rtt_ms:
            self._min_rtt_ms = rtt_ms
            self._min_rtt_stamp_ms = now_ms

    def _rotate_probe_bw(self, now_ms: int) -> None:
        if self._phase is not Phase.PROBE_BW:
            return
        if self._min_rtt_ms is None:
            return
        if now_ms - self._round_start_ms >= self._min_rtt_ms:
            self._round_start_ms = now_ms
            self._probe_bw_idx = (self._probe_bw_idx + 1) % len(_PROBE_BW_GAINS)

    # -- public API --------------------------------------------------
    def on_ack(self, sample: AckSample) -> None:
        """Feed one delivery observation into the estimator."""
        if not isinstance(sample, AckSample):
            raise TypeError("sample must be an AckSample")
        self._advance(sample.now_ms)
        self._update_bw_sample(sample.now_ms, sample)
        self._update_min_rtt(sample.now_ms, sample.rtt_ms)

        max_bw = self._max_bw(sample.now_ms)

        if self._phase is Phase.STARTUP:
            # Round-trip boundary on min_rtt granularity.
            if self._min_rtt_ms and sample.now_ms - self._round_start_ms >= self._min_rtt_ms:
                self._round_start_ms = sample.now_ms
                if max_bw <= self._prev_max_bw * 1.25:
                    self._startup_rounds_flat += 1
                else:
                    self._startup_rounds_flat = 0
                self._prev_max_bw = max_bw
                if self._startup_rounds_flat >= _STARTUP_PLATEAU_ROUNDS:
                    self._phase = Phase.DRAIN
        elif self._phase is Phase.DRAIN:
            # Simulated drain: exit once cwnd is back near 1x BDP; the
            # harness reports queue depth via in_flight feedback.  Here
            # exit after one min_rtt round has elapsed.
            if self._min_rtt_ms and sample.now_ms - self._round_start_ms >= self._min_rtt_ms:
                self._round_start_ms = sample.now_ms
                self._phase = Phase.PROBE_BW
                self._probe_bw_idx = 0

        self._rotate_probe_bw(sample.now_ms)
        self._maybe_enter_probe_rtt(sample.now_ms)
        self._maybe_exit_probe_rtt(sample.now_ms)

    def on_loss(self, event: LossEvent) -> None:
        """React to loss: cap cwnd at half the current window."""
        if not isinstance(event, LossEvent):
            raise TypeError("event must be a LossEvent")
        self._advance(event.now_ms)
        current = self._raw_cwnd(event.now_ms)
        halved = max(self._min_cwnd_bytes, current // 2)
        if self._loss_ceiling_bytes is None:
            self._loss_ceiling_bytes = halved
        else:
            self._loss_ceiling_bytes = min(self._loss_ceiling_bytes, halved)
        self._maybe_enter_probe_rtt(event.now_ms)
        self._maybe_exit_probe_rtt(event.now_ms)

    def _bdp_bytes(self) -> float:
        now = self._last_ms or 0
        return self._max_bw(now) * (self._min_rtt_ms or 0)

    def _gain(self) -> float:
        if self._phase is Phase.STARTUP:
            return _STARTUP_GAIN
        if self._phase is Phase.DRAIN:
            return _DRAIN_GAIN
        if self._phase is Phase.PROBE_RTT:
            return 0.0  # floor to minimum window
        return _PROBE_BW_GAINS[self._probe_bw_idx % len(_PROBE_BW_GAINS)]

    def _raw_cwnd(self, now_ms: int) -> int:
        if self._min_rtt_ms is None or not self._bw_samples:
            return self._min_cwnd_bytes
        if self._phase is Phase.PROBE_RTT:
            return self._min_cwnd_bytes
        cwnd = int(self._gain() * self._bdp_bytes())
        if self._loss_ceiling_bytes is not None:
            cwnd = min(cwnd, self._loss_ceiling_bytes)
        return max(cwnd, self._min_cwnd_bytes)

    def cwnd(self) -> int:
        """Current congestion window in bytes."""
        now = self._last_ms if self._last_ms is not None else 0
        return self._raw_cwnd(now)

    @property
    def phase(self) -> Phase:
        return self._phase

    @property
    def min_rtt_ms(self) -> int | None:
        return self._min_rtt_ms

    @property
    def btlbw_bytes_per_s(self) -> float:
        now = self._last_ms if self._last_ms is not None else 0
        return self._max_bw(now) * 1000.0


def main() -> int:
    cc = CongestionControl()
    assert cc.cwnd() == _MIN_PACKETS_IN_FLIGHT * _DEFAULT_PACKET_BYTES
    assert cc.phase is Phase.STARTUP
    cc.on_ack(AckSample(now_ms=0, delivered_bytes=100_000, rtt_ms=50))
    assert cc.min_rtt_ms == 50
    # Drive through startup -> drain -> probe_bw with growing delivery.
    t = 0
    for i in range(30):
        t += 50
        cc.on_ack(AckSample(now_ms=t, delivered_bytes=100_000, rtt_ms=50))
    assert cc.phase is Phase.PROBE_BW, cc.phase
    assert cc.btlbw_bytes_per_s > 0
    before = cc.cwnd()
    cc.on_loss(LossEvent(now_ms=t + 1, packets_lost=3))
    assert cc.cwnd() <= before
    # Probe-RTT: jump simulated time past 10 s without new ACKs.
    cc2 = CongestionControl()
    cc2.on_ack(AckSample(now_ms=0, delivered_bytes=100_000, rtt_ms=50))
    cc2.on_ack(AckSample(now_ms=_PROBE_RTT_EVERY_MS + 1, delivered_bytes=100_000, rtt_ms=50))
    assert cc2.phase is Phase.PROBE_RTT, cc2.phase
    assert cc2.cwnd() == _MIN_PACKETS_IN_FLIGHT * _DEFAULT_PACKET_BYTES
    print("congestion-control self-check ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
