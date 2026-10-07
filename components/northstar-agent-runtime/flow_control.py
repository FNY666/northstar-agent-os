"""TCP-style flow control: sliding-window send/ack bookkeeping.

A ``FlowControl`` mirrors TCP's sender-side window: ``send(n_bytes)`` may
proceed only while the unacknowledged in-flight volume stays under the
advertised receiver window; ``ack(seq_no)`` is cumulative and frees every
segment up to and including ``seq_no``. ``window_size()`` reports the currently
available window.

House style: no wall-clock — no timestamps at all in this module; the caller
decides *when* to call. stdlib-only, deterministic, frozen decision records,
version/schema pins, ``main()`` self-check.

Honest scope: pure bookkeeping over host-reported events. Cannot verify the
peer actually received anything, cannot detect a peer that lies about acks,
and does not model congestion control (no slow-start, no AIMD) — that is a
separate concern. A quiet window means "no known over-window shape", never
"no pressure".

Version pin: flow-control.v1
Schema pin: northstar.flow-control.v1
"""

from __future__ import annotations

import sys
from dataclasses import dataclass

FLOW_CONTROL_VERSION = "flow-control.v1"
SCHEMA_PIN = "northstar.flow-control.v1"


def _require_positive_int(name: str, value) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int, got {type(value).__name__}")
    if value <= 0:
        raise ValueError(f"{name} must be positive")


def _require_nonneg_int(name: str, value) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int, got {type(value).__name__}")
    if value < 0:
        raise ValueError(f"{name} must be non-negative")


@dataclass(frozen=True)
class SendDecision:
    """One send verdict (frozen record)."""

    accepted: bool
    seq_no: int  # first sequence number assigned to this segment (0 when rejected)
    window_after: int  # available window after this decision
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        if not isinstance(self.accepted, bool):
            raise TypeError("accepted must be a bool")
        _require_nonneg_int("seq_no", self.seq_no)
        _require_nonneg_int("window_after", self.window_after)


@dataclass(frozen=True)
class AckDecision:
    """One ack verdict (frozen record)."""

    accepted: bool  # False for duplicates / out-of-range; state untouched
    bytes_acked: int  # newly freed bytes (0 when not accepted)
    window_after: int
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        if not isinstance(self.accepted, bool):
            raise TypeError("accepted must be a bool")
        _require_nonneg_int("bytes_acked", self.bytes_acked)
        _require_nonneg_int("window_after", self.window_after)


@dataclass(frozen=True)
class WindowSnapshot:
    """Point-in-time window state (frozen record)."""

    window_bytes: int  # advertised receiver window
    in_flight_bytes: int  # sent but not yet acked
    available: int  # window_bytes - in_flight_bytes
    next_seq: int  # sequence number the next send would use
    segments_in_flight: int
    duplicate_acks: int
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        _require_nonneg_int("window_bytes", self.window_bytes)
        _require_nonneg_int("in_flight_bytes", self.in_flight_bytes)
        _require_nonneg_int("available", self.available)
        _require_nonneg_int("next_seq", self.next_seq)
        _require_nonneg_int("segments_in_flight", self.segments_in_flight)
        _require_nonneg_int("duplicate_acks", self.duplicate_acks)


class FlowControl:
    """Sliding-window flow control with cumulative acks."""

    def __init__(self, window_bytes: int) -> None:
        _require_positive_int("window_bytes", window_bytes)
        self._window_bytes = window_bytes
        self._next_seq = 0
        # seq_no -> size of each unacknowledged segment, insertion ordered
        self._in_flight: dict[int, int] = {}
        # last cumulative ack accepted (init -1: "ack(0)" means first segment)
        self._last_ack = -1
        self._duplicate_acks = 0

    @property
    def window_bytes(self) -> int:
        return self._window_bytes

    @property
    def duplicate_acks(self) -> int:
        return self._duplicate_acks

    def _in_flight_bytes(self) -> int:
        return sum(self._in_flight.values())

    def send(self, n_bytes: int) -> SendDecision:
        """Try to send ``n_bytes``. Accepts only if it fits in the window."""
        _require_positive_int("n_bytes", n_bytes)
        if n_bytes <= self._window_bytes - self._in_flight_bytes():
            seq = self._next_seq
            self._in_flight[seq] = n_bytes
            self._next_seq += n_bytes
            return SendDecision(
                accepted=True,
                seq_no=seq,
                window_after=self._window_bytes - self._in_flight_bytes(),
            )
        return SendDecision(
            accepted=False,
            seq_no=0,
            window_after=self._window_bytes - self._in_flight_bytes(),
        )

    def ack(self, seq_no: int) -> AckDecision:
        """Cumulative ack: frees every segment with seq < = ``seq_no``.

        Rejects (accepted=False, state untouched): non-int seqs, seqs beyond
        ``next_seq - 1``, and acks that free nothing (duplicates).
        """
        if isinstance(seq_no, bool) or not isinstance(seq_no, int):
            raise TypeError(f"seq_no must be an int, got {type(seq_no).__name__}")
        if seq_no < -1:
            raise ValueError("seq_no must be >= -1")
        if seq_no >= self._next_seq:
            return AckDecision(
                accepted=False,
                bytes_acked=0,
                window_after=self._window_bytes - self._in_flight_bytes(),
            )
        freed = 0
        for seq in list(self._in_flight):
            if seq <= seq_no:
                freed += self._in_flight.pop(seq)
        if freed == 0:
            self._duplicate_acks += 1
            return AckDecision(
                accepted=False,
                bytes_acked=0,
                window_after=self._window_bytes - self._in_flight_bytes(),
            )
        self._last_ack = max(self._last_ack, seq_no)
        return AckDecision(
            accepted=True,
            bytes_acked=freed,
            window_after=self._window_bytes - self._in_flight_bytes(),
        )

    def window_size(self) -> int:
        """Currently available window (bytes)."""
        return self._window_bytes - self._in_flight_bytes()

    def snapshot(self) -> WindowSnapshot:
        return WindowSnapshot(
            window_bytes=self._window_bytes,
            in_flight_bytes=self._in_flight_bytes(),
            available=self._window_bytes - self._in_flight_bytes(),
            next_seq=self._next_seq,
            segments_in_flight=len(self._in_flight),
            duplicate_acks=self._duplicate_acks,
        )

    def resize(self, window_bytes: int) -> int:
        """Advertise a new receiver window; returns the new available size."""
        _require_positive_int("window_bytes", window_bytes)
        self._window_bytes = window_bytes
        return self.window_size()


def main() -> int:
    fc = FlowControl(window_bytes=100)
    assert fc.window_size() == 100
    d = fc.send(60)
    assert d.accepted and d.seq_no == 0 and fc.window_size() == 40
    d2 = fc.send(50)
    assert not d2.accepted and fc.window_size() == 40
    a = fc.ack(59)
    assert a.accepted and a.bytes_acked == 60 and fc.window_size() == 100
    dup = fc.ack(59)
    assert not dup.accepted and fc.duplicate_acks == 1
    print("flow-control.v1 self-check OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
