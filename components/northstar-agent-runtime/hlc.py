"""Hybrid Logical Clock (HLC) for audit event timestamps.

Absorbs the Hybrid Logical Clock of Kulkarni et al. ("Logical Physical
Clocks and Consistent Snapshots in Globally Distributed Databases",
SSS 2014, building on Lamport 1978): a 64-bit timestamp ``(l, c)`` where
``l`` tracks the maximum physical time seen and ``c`` is a bounded counter
that breaks ties. The guarantee: if event *a* causally precedes event *b*
(``a -> b``), then ``hlc(a) < hlc(b)`` in lexicographic order — even when
the two events were produced by different writers whose wall clocks
disagree.

Why the audit feed needs it: audit records carry a wall-clock ``ts``
(RFC 3339 UTC, millisecond precision). With more than one writer —
parallel tool workers, multi-process runs, merged transcripts — two
causally-ordered events can receive ``ts`` values that disagree with
causality: clock skew inverts the order, millisecond granularity flattens
it. ``verify --strict`` tolerates this with a clock-skew allowance, which
papers over the problem instead of fixing it. HLC stamps fix it
structurally: a writer merges (receive rule) every stamp it has observed
before ticking its own, so timestamps agree with causality by
construction, while ``l`` stays within a bounded drift of physical time.

Wire format: the optional top-level audit envelope field ``"hlc"`` holds
the canonical string ``"<l>:<c>"`` (e.g. ``"1727865600000:3"``), ``l`` in
milliseconds since the Unix epoch (48 bits), ``c`` the tie-break counter
(16 bits). Records written before HLC simply lack the field — the schema
stays ``audit.ndjson/1`` and verifiers skip the causality check for any
pair that does not both carry a parseable stamp.

Everything here is pure and deterministic: the physical clock is an
explicit parameter (``pt_ms``), never read implicitly, so tests pin exact
behavior. The one documented deviation from the paper: the 16-bit counter
cannot overflow in this implementation — when ``c`` would exceed its
maximum, ``l`` advances by one millisecond and ``c`` resets to zero, which
preserves the causality guarantee (the new stamp is strictly greater than
the old one).
"""
from __future__ import annotations

import re
import time
from typing import Optional

#: Bits for the physical-time component (milliseconds since Unix epoch;
#: 48 bits cover dates far beyond any audit feed's lifetime).
L_BITS = 48
#: Bits for the tie-break counter.
C_BITS = 16

L_MAX = (1 << L_BITS) - 1
C_MAX = (1 << C_BITS) - 1

#: Canonical wire shape: "<l>:<c>", both non-negative integers.
_HLC_RE = re.compile(r"^(\d+):(\d+)$")


def now_ms() -> int:
    """Current physical time in whole milliseconds (the default clock)."""
    return int(time.time() * 1000)


def pack(l: int, c: int) -> str:
    """Canonical wire string for an ``(l, c)`` stamp.

    Raises ``ValueError`` when either component is out of range, so a bad
    stamp can never be silently emitted.
    """
    if not (0 <= l <= L_MAX):
        raise ValueError(f"hlc l={l} out of 48-bit range")
    if not (0 <= c <= C_MAX):
        raise ValueError(f"hlc c={c} out of 16-bit range")
    return f"{l}:{c}"


def unpack(stamp: object) -> Optional[tuple[int, int]]:
    """Parse a wire stamp; ``None`` when malformed or out of range.

    Never raises: verifiers use this to decide whether the causality check
    applies to a record pair, and an unparseable stamp is treated as
    "no HLC information", not as a forgery signal.
    """
    if not isinstance(stamp, str):
        return None
    match = _HLC_RE.fullmatch(stamp)
    if match is None:
        return None
    l, c = int(match.group(1)), int(match.group(2))
    if l > L_MAX or c > C_MAX:
        return None
    return (l, c)


def _bump(l: int, c: int) -> tuple[int, int]:
    """Increment the counter, advancing ``l`` instead of overflowing ``c``."""
    if c < C_MAX:
        return (l, c + 1)
    # Documented deviation (see module docstring): keep the stamp strictly
    # greater without breaking the 64-bit packing.
    return (l + 1, 0)


def tick(state: tuple[int, int], pt_ms: int | None = None) -> tuple[int, int]:
    """Stamp a new local event (the paper's send/local rule).

    ``state`` is the writer's current ``(l, c)``; returns the new state.
    ``l' = max(l, pt)``; the counter advances only when ``l`` did not move,
    so the stamp stays close to physical time while remaining strictly
    greater than every stamp this writer has issued before.
    """
    l, c = state
    pt = now_ms() if pt_ms is None else pt_ms
    new_l = l if l > pt else pt
    if new_l == l:
        return _bump(l, c)
    return (new_l, 0)


def receive(
    state: tuple[int, int],
    msg_l: int,
    msg_c: int,
    pt_ms: int | None = None,
) -> tuple[int, int]:
    """Merge an observed stamp and stamp a new event (the paper's receive rule).

    ``l' = max(l, l_msg, pt)``; the counter is ``max(c, c_msg) + 1`` when
    the merged ``l'`` ties both inputs, ``c + 1`` / ``c_msg + 1`` when it
    ties one of them, else ``0``. This is the rule that makes causality
    visible in the timestamps: after receiving ``a``'s stamp, every stamp
    this writer issues is strictly greater than ``hlc(a)``.
    """
    l, c = state
    pt = now_ms() if pt_ms is None else pt_ms
    new_l = max(l, msg_l, pt)
    if new_l == l == msg_l:
        return _bump(l, c if c > msg_c else msg_c)
    if new_l == l:
        return _bump(l, c)
    if new_l == msg_l:
        return _bump(msg_l, msg_c)
    return (new_l, 0)


class HLCClock:
    """Mutable per-writer HLC state; the convenient producer interface."""

    def __init__(self) -> None:
        self._state: tuple[int, int] = (0, 0)

    @property
    def state(self) -> tuple[int, int]:
        """Current ``(l, c)`` (for persistence or tests)."""
        return self._state

    def tick(self, pt_ms: int | None = None) -> str:
        """Stamp a new local event; returns the packed wire string."""
        self._state = tick(self._state, pt_ms)
        return pack(*self._state)

    def receive(self, stamp: object, pt_ms: int | None = None) -> bool:
        """Merge an observed stamp; ``False`` (no state change) when the
        stamp is unparseable — a producer never lets a malformed input
        corrupt its clock."""
        parsed = unpack(stamp)
        if parsed is None:
            return False
        self._state = receive(self._state, parsed[0], parsed[1], pt_ms)
        return True
