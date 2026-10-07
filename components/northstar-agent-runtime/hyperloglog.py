"""HyperLogLog cardinality estimation: distinct-count sketch over hash digests.

Estimates how many *distinct* items were seen without storing them
(Flajolet, Fusy, Gandouillet & Meunier, 2007). ``HyperLogLog.add(item)``
folds one item into the sketch; ``count()`` returns the current estimate.

* **Precision** — ``precision`` (4..16) sets the register count ``m = 2**p``.
  Relative standard error is ``1.04 / sqrt(m)``; higher precision costs more
  memory (m bytes, registers are one byte each) but is more accurate.
* **Deterministic** — items hash with SHA-256 (truncated to 64 bits); the
  same item set always yields the same estimate, regardless of insertion
  order or restarts.
* **Mergeable** — ``merge(other)`` takes register-wise maxima, so sketches
  built on different hosts fold into one cardinality estimate (union).
* **Small-range correction** — linear counting when the raw estimate is
  small and registers are empty; large-range correction against the 64-bit
  hash space when the estimate nears it.
* **Fail-closed** — precision outside 4..16 rejected at construction;
  non-str/non-bytes items rejected by ``add`` (never silently coerced);
  ``merge`` rejects sketches of a different precision.

House style: frozen records, no wall-clock, stdlib-only, deterministic,
version/schema pins, ``main()`` self-check.

Honest scope: ``count()`` is an *estimate* with a documented error band,
never an exact distinct count. Hash collisions in the 64-bit space are
negligible but nonzero; a wildly wrong estimate on adversarial inputs
(e.g. a broken hash or pre-imaged digests) is outside what the sketch can
detect. A quiet sketch means "no items seen", never "no duplicates".

Version pin: hyperloglog.v1
Schema pin: northstar.hyperloglog.v1
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass

HYPERLOGLOG_VERSION = "hyperloglog.v1"
SCHEMA_PIN = "northstar.hyperloglog.v1"

_HASH_BITS = 64
_MIN_PRECISION = 4
_MAX_PRECISION = 16

# alpha_m bias-correction constants (Flajolet et al.); m >= 128 uses the
# closed form 0.7213 / (1 + 1.079 / m).
_ALPHA_SMALL = {4: 0.673, 5: 0.697, 6: 0.709}


def _alpha(m: int) -> float:
    p = m.bit_length() - 1
    if p in _ALPHA_SMALL:
        return _ALPHA_SMALL[p]
    return 0.7213 / (1 + 1.079 / m)


def _require_precision(value) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"precision must be an int, got {type(value).__name__}")
    if not (_MIN_PRECISION <= value <= _MAX_PRECISION):
        raise ValueError(
            f"precision must be {_MIN_PRECISION}..{_MAX_PRECISION}, got {value}"
        )
    return value


def _digest64(item: str | bytes) -> int:
    if isinstance(item, str):
        data = item.encode("utf-8")
    elif isinstance(item, bytes):
        data = item
    else:
        raise TypeError(f"item must be str or bytes, got {type(item).__name__}")
    return int.from_bytes(hashlib.sha256(data).digest()[:8], "big")


@dataclass(frozen=True)
class CardinalityReport:
    """One cardinality estimate (frozen record)."""

    estimate: float
    precision: int
    registers_used: int
    registers_total: int
    relative_error: float
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        if isinstance(self.estimate, bool) or not isinstance(
            self.estimate, (int, float)
        ):
            raise TypeError("estimate must be a number")
        if not math.isfinite(float(self.estimate)) or float(self.estimate) < 0:
            raise ValueError("estimate must be finite and non-negative")
        _require_precision(self.precision)
        m = 1 << self.precision
        if m != self.registers_total:
            raise ValueError("registers_total must equal 2**precision")
        if (
            isinstance(self.registers_used, bool)
            or not isinstance(self.registers_used, int)
            or not (0 <= self.registers_used <= self.registers_total)
        ):
            raise ValueError("registers_used must be an int in [0, registers_total]")
        if not (isinstance(self.relative_error, float) and self.relative_error > 0):
            raise ValueError("relative_error must be a positive float")

    def as_dict(self) -> dict:
        return {
            "estimate": float(self.estimate),
            "precision": self.precision,
            "registers_used": self.registers_used,
            "registers_total": self.registers_total,
            "relative_error": self.relative_error,
            "schema": self.schema,
        }


class HyperLogLog:
    """Distinct-count sketch. ``add(item)`` folds items in; ``count()`` estimates."""

    def __init__(self, precision: int = 10) -> None:
        _require_precision(precision)
        self._precision = precision
        self._m = 1 << precision
        self._registers = bytearray(self._m)

    @property
    def precision(self) -> int:
        return self._precision

    @property
    def register_count(self) -> int:
        return self._m

    def add(self, item: str | bytes) -> None:
        """Fold one item into the sketch (idempotent for repeats)."""
        h = _digest64(item)
        index = h >> (_HASH_BITS - self._precision)
        w = h & ((1 << (_HASH_BITS - self._precision)) - 1)
        rho = (_HASH_BITS - self._precision) - w.bit_length() + 1
        if rho > self._registers[index]:
            self._registers[index] = rho

    def merge(self, other: "HyperLogLog") -> None:
        """Fold another sketch into this one (union of item sets)."""
        if not isinstance(other, HyperLogLog):
            raise TypeError(
                f"other must be a HyperLogLog, got {type(other).__name__}"
            )
        if other._precision != self._precision:
            raise ValueError(
                f"precision mismatch: {self._precision} vs {other._precision}"
            )
        for i in range(self._m):
            if other._registers[i] > self._registers[i]:
                self._registers[i] = other._registers[i]

    def count(self) -> float:
        """Estimate the number of distinct items seen."""
        regs = self._registers
        inv_sum = sum(2.0 ** -r for r in regs)
        estimate = _alpha(self._m) * self._m * self._m / inv_sum
        zeros = regs.count(0)
        if estimate <= 2.5 * self._m and zeros > 0:
            # Small-range correction: linear counting.
            estimate = self._m * math.log(self._m / zeros)
        elif estimate > (1.0 / 30.0) * float(1 << _HASH_BITS):
            # Large-range correction against the 64-bit hash space.
            estimate = -float(1 << _HASH_BITS) * math.log(
                1.0 - estimate / float(1 << _HASH_BITS)
            )
        return estimate

    def report(self) -> CardinalityReport:
        """Frozen snapshot of the current estimate and its error band."""
        used = sum(1 for r in self._registers if r > 0)
        return CardinalityReport(
            estimate=self.count(),
            precision=self._precision,
            registers_used=used,
            registers_total=self._m,
            relative_error=1.04 / math.sqrt(self._m),
        )


def hyperloglog_audit_event(
    report: CardinalityReport, *, audit_seq: int
) -> dict:
    """Shape a cardinality report as an ``audit.ndjson/1`` record."""
    if not isinstance(report, CardinalityReport):
        raise TypeError("report must be a CardinalityReport")
    if isinstance(audit_seq, bool) or not isinstance(audit_seq, int):
        raise TypeError("audit_seq must be an int")
    if audit_seq < 0:
        raise ValueError("audit_seq must be >= 0")
    record = report.as_dict()
    record["audit_seq"] = audit_seq
    return record


def main() -> None:
    hll = HyperLogLog(precision=10)
    for i in range(1000):
        hll.add(f"user-{i}")
    est = hll.count()
    assert 800.0 <= est <= 1200.0, f"estimate {est} out of band"
    # Idempotent for repeats and order-independent.
    hll2 = HyperLogLog(precision=10)
    for i in reversed(range(1000)):
        hll2.add(f"user-{i}")
        hll2.add(f"user-{i}")
    assert hll2.count() == est
    # Merge == union.
    a = HyperLogLog(precision=10)
    b = HyperLogLog(precision=10)
    for i in range(500):
        a.add(f"user-{i}")
    for i in range(500, 1000):
        b.add(f"user-{i}")
    a.merge(b)
    merged = a.count()
    assert 800.0 <= merged <= 1200.0, f"merged estimate {merged} out of band"
    rep = hll.report()
    assert rep.registers_used > 0
    assert 0.0 < rep.relative_error < 1.0
    evt = hyperloglog_audit_event(rep, audit_seq=0)
    assert evt["audit_seq"] == 0
    print("hyperloglog OK: estimate, idempotent, merge, audit")
    return None


if __name__ == "__main__":
    main()
