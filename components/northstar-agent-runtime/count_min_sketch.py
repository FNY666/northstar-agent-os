"""Count-min sketch: compact frequency estimation for event streams.

A ``CountMinSketch`` estimates how often an item has appeared using a small
fixed table of counters, trading exactness for space. ``add(item)`` records
an occurrence; ``estimate(item)`` returns the estimated count. Estimates are
never below the true count (one-sided error): hash collisions only ever
inflate the estimate, bounded by ``epsilon * total_adds`` with probability
``1 - delta``.

Parameters map to the standard guarantee:

* ``width`` — columns per row; choose ``width = ceil(e / epsilon)``.
* ``depth`` — rows (hash functions); choose ``depth = ceil(ln(1 / delta))``.

House style: stdlib-only (``hashlib``), deterministic hashing with per-row
salts (no ``random`` module, no global-RNG coupling), no wall-clock,
fail-closed validation (bool/negative/non-str items and counts rejected),
frozen records with version/schema pins, ``main()`` self-check.

Honest scope: this bounds *reported* frequencies as the host reports them --
it cannot see events the host never adds, and an inflated estimate means
"at most this many, collisions included", never "exactly this many".
``estimate`` never under-counts; adversaries that know the salts can
manufacture collisions, so salts are a deployment secret, not a security
boundary. A low estimate on a busy key means the event is rare or unreported,
never proven absent.

Version pin: count-min-sketch.v1
Schema pin: northstar.count-min-sketch.v1
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass, field

#: Module version pin.
COUNT_MIN_SKETCH_VERSION = "count-min-sketch.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.count-min-sketch.v1"


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


def _item_bytes(item) -> bytes:
    """Encode an item for hashing (fail-closed on wrong type)."""
    if isinstance(item, bool):
        raise TypeError("item must be str or bytes, not bool")
    if isinstance(item, str):
        return item.encode("utf-8")
    if isinstance(item, (bytes, bytearray)):
        return bytes(item)
    raise TypeError(f"item must be str or bytes, got {type(item).__name__}")


def _params_for(epsilon: float, delta: float) -> tuple[int, int]:
    """Standard (width, depth) from the (epsilon, delta) guarantee."""
    if not isinstance(epsilon, (int, float)) or isinstance(epsilon, bool):
        raise TypeError("epsilon must be a number")
    if not isinstance(delta, (int, float)) or isinstance(delta, bool):
        raise TypeError("delta must be a number")
    if not (0 < epsilon < 1):
        raise ValueError("epsilon must be in (0, 1)")
    if not (0 < delta < 1):
        raise ValueError("delta must be in (0, 1)")
    width = math.ceil(math.e / epsilon)
    depth = math.ceil(math.log(1.0 / delta))
    return (max(1, width), max(1, depth))


@dataclass(frozen=True)
class SketchSummary:
    """Exportable snapshot of a sketch's shape (frozen record)."""

    width: int
    depth: int
    total_adds: int
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        _require_positive_int("width", self.width)
        _require_positive_int("depth", self.depth)
        _require_nonneg_int("total_adds", self.total_adds)

    def as_dict(self) -> dict:
        return {
            "width": self.width,
            "depth": self.depth,
            "total_adds": self.total_adds,
            "schema": self.schema,
        }


class CountMinSketch:
    """Count-min sketch over caller-supplied items.

    ``width`` columns x ``depth`` rows of counters. ``add(item, count=1)``
    increments the ``depth`` hashed positions; ``estimate(item)`` returns the
    minimum of the hashed positions (never below the true count).
    ``merge(other)`` unions two sketches with identical shape and salt.
    """

    def __init__(self, width: int, depth: int, salt: bytes = b"northstar-count-min.v1") -> None:
        _require_positive_int("width", width)
        _require_positive_int("depth", depth)
        if isinstance(salt, bool) or not isinstance(salt, (bytes, bytearray)):
            raise TypeError("salt must be bytes")
        if len(salt) == 0:
            raise ValueError("salt must be non-empty")
        self._width = width
        self._depth = depth
        self._salt = bytes(salt)
        self._table: list[list[int]] = [[0] * width for _ in range(depth)]
        self._total_adds = 0

    @classmethod
    def with_guarantee(cls, epsilon: float, delta: float, salt: bytes = b"northstar-count-min.v1") -> "CountMinSketch":
        """Build a sketch sized for the (epsilon, delta) error guarantee."""
        width, depth = _params_for(epsilon, delta)
        return cls(width, depth, salt=salt)

    @property
    def width(self) -> int:
        return self._width

    @property
    def depth(self) -> int:
        return self._depth

    @property
    def total_adds(self) -> int:
        return self._total_adds

    def _columns(self, item) -> tuple[int, ...]:
        data = _item_bytes(item)
        cols = []
        for row in range(self._depth):
            digest = hashlib.sha256(self._salt + row.to_bytes(8, "big") + data).digest()
            cols.append(int.from_bytes(digest[:8], "big") % self._width)
        return tuple(cols)

    def add(self, item, count: int = 1) -> None:
        """Record ``count`` occurrences of ``item``."""
        _require_positive_int("count", count)
        for row, col in enumerate(self._columns(item)):
            self._table[row][col] += count
        self._total_adds += count

    def estimate(self, item) -> int:
        """Estimated count for ``item`` (>= true count, never below)."""
        return min(self._table[row][col] for row, col in enumerate(self._columns(item)))

    def merge(self, other: "CountMinSketch") -> None:
        """Union ``other`` into this sketch (same width/depth/salt required)."""
        if not isinstance(other, CountMinSketch):
            raise TypeError(f"other must be a CountMinSketch, got {type(other).__name__}")
        if (other._width, other._depth, other._salt) != (self._width, self._depth, self._salt):
            raise ValueError("sketches must share width, depth, and salt to merge")
        for row in range(self._depth):
            for col in range(self._width):
                self._table[row][col] += other._table[row][col]
        self._total_adds += other._total_adds

    def summary(self) -> SketchSummary:
        """Frozen exportable snapshot of the sketch's shape."""
        return SketchSummary(width=self._width, depth=self._depth, total_adds=self._total_adds)

    def error_bound(self, epsilon: float, delta: float) -> bool:
        """True when this sketch's shape meets the (epsilon, delta) guarantee."""
        need_w, need_d = _params_for(epsilon, delta)
        return self._width >= need_w and self._depth >= need_d


def countmin_audit_event(action: str, item_hash: str, estimate: int, seq: int) -> dict:
    """Build an ``audit.ndjson/1``-shaped record for a sketch event.

    ``action`` is one of ``add`` / ``estimate`` / ``merge``. ``item_hash`` is
    the caller's ``sha256:`` hex digest of the item -- the raw item is never
    emitted. ``seq`` is caller-supplied.
    """
    if action not in ("add", "estimate", "merge"):
        raise ValueError(f"action must be add/estimate/merge, got {action!r}")
    if not isinstance(item_hash, str) or not item_hash.startswith("sha256:"):
        raise ValueError("item_hash must be a 'sha256:' hex digest")
    _require_nonneg_int("estimate", estimate)
    _require_nonneg_int("seq", seq)
    return {
        "kind": "count-min-sketch",
        "action": action,
        "item_hash": item_hash,
        "estimate": estimate,
        "audit_seq": seq,
        "schema": SCHEMA_PIN,
    }


def main() -> None:
    sketch = CountMinSketch.with_guarantee(epsilon=0.01, delta=0.01)
    for _ in range(100):
        sketch.add("event-a")
    for _ in range(5):
        sketch.add("event-b")
    assert sketch.estimate("event-a") >= 100, "never under-counts"
    assert sketch.estimate("event-c") >= 0, "unseen item has non-negative estimate"
    other = CountMinSketch(sketch.width, sketch.depth)
    other.add("event-a", count=10)
    sketch.merge(other)
    assert sketch.estimate("event-a") >= 110, "merge unions counts"
    print("count-min-sketch OK: add, estimate, merge, guarantee sizing")


if __name__ == "__main__":
    main()
