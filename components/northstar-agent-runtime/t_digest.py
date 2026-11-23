"""T-digest: mergeable quantile estimation over streaming values.

A ``TDigest`` compresses a value stream into a small set of weighted centroids
so that ``quantile(q)`` and ``cdf(x)`` stay accurate — especially in the tails,
where the k1 scale function forces clusters to stay small.

* ``add(value)`` — ingest one finite float (bool/NaN/inf rejected fail-closed).
  Values buffer up and are merged + compressed when the buffer fills.
* ``quantile(q)`` — estimated value at quantile ``q`` in [0, 1]; piecewise-linear
  interpolation between centroid half-mass points (monotone, exact when the
  digest holds every value).
* ``cdf(x)`` — estimated fraction of values <= ``x``; the inverse of the
  quantile map over the same knots.
* ``merge(other)`` — combine two digests (same compression) without re-reading
  the stream; merge is associative, so fleet-wide aggregation is safe.

House style: no wall-clock, fail-closed, stdlib-only, deterministic, frozen
records, version/schema pins, ``main()`` self-check.

Honest scope: a *sketch*, not the data — quantile/cdf are estimates whose
error shrinks with compression and grows adversarially against clustered
streams; ``quantile`` on an empty digest raises rather than guessing. Merge
only sees centroid summaries, never raw values, so a merged digest cannot be
more accurate than the union of its inputs.

Version pin: t-digest.v1
Schema pin: northstar.t-digest.v1
"""

from __future__ import annotations

import math
from dataclasses import dataclass

TDIGEST_VERSION = "t-digest.v1"
SCHEMA_PIN = "northstar.t-digest.v1"

#: Default compression (delta). Higher = more centroids, lower error.
DEFAULT_COMPRESSION = 100.0

#: Buffer size before a merge+compress cycle runs.
DEFAULT_BUFFER_SIZE = 512


class TDigestError(Exception):
    """Raised for structural misuse (empty digest, mismatched merge)."""


def _require_finite_float(name: str, value) -> float:
    if isinstance(value, bool):
        raise TypeError(f"{name} must be a float, got bool")
    if not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be a number, got {type(value).__name__}")
    f = float(value)
    if math.isnan(f) or math.isinf(f):
        raise ValueError(f"{name} must be finite")
    return f


def _require_compression(value) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("compression must be a number")
    f = float(value)
    if not math.isfinite(f) or f <= 0:
        raise ValueError("compression must be positive and finite")
    return f


def _k1(q: float, compression: float) -> float:
    """k1 scale function: k(q) = delta * (asin(2q-1)/pi + 1/2)."""
    q = min(1.0, max(0.0, q))
    return compression * (math.asin(2.0 * q - 1.0) / math.pi + 0.5)


@dataclass(frozen=True)
class Centroid:
    """One digest cluster: mean of its values, and how many it holds."""

    mean: float
    count: int

    def as_dict(self) -> dict:
        return {"mean": self.mean, "count": self.count, "schema": SCHEMA_PIN}


@dataclass(frozen=True)
class DigestSummary:
    """Frozen snapshot of a digest's shape (for audit, never the raw values)."""

    count: int
    min: float
    max: float
    centroid_count: int
    compression: float

    def as_dict(self) -> dict:
        return {
            "count": self.count,
            "min": self.min,
            "max": self.max,
            "centroid_count": self.centroid_count,
            "compression": self.compression,
            "schema": SCHEMA_PIN,
        }


class TDigest:
    """Streaming quantile sketch with k1-bounded clusters."""

    def __init__(
        self,
        compression: float = DEFAULT_COMPRESSION,
        buffer_size: int = DEFAULT_BUFFER_SIZE,
    ) -> None:
        self._compression = _require_compression(compression)
        if isinstance(buffer_size, bool) or not isinstance(buffer_size, int):
            raise TypeError("buffer_size must be an int")
        if buffer_size <= 0:
            raise ValueError("buffer_size must be positive")
        self._buffer_size = buffer_size
        self._centroids: list[tuple[float, int]] = []  # (mean, count), sorted
        self._buffer: list[float] = []
        self._total = 0
        self._min = math.inf
        self._max = -math.inf

    # ------------------------------------------------------------------ input

    def add(self, value) -> None:
        """Ingest one value; compresses when the buffer fills."""
        f = _require_finite_float("value", value)
        self._buffer.append(f)
        self._total += 1
        if f < self._min:
            self._min = f
        if f > self._max:
            self._max = f
        if len(self._buffer) >= self._buffer_size:
            self._compress()

    def merge(self, other: "TDigest") -> None:
        """Fold another digest in. Both must share the same compression."""
        if not isinstance(other, TDigest):
            raise TypeError("can only merge a TDigest")
        if other._compression != self._compression:
            raise TDigestError("compression mismatch")
        other._compress()
        for mean, count in other._centroids:
            self._buffer.extend([mean] * count)
        self._total += other._total
        if other._total:
            self._min = min(self._min, other._min)
            self._max = max(self._max, other._max)
        self._compress()

    # --------------------------------------------------------------- queries

    def count(self) -> int:
        self._compress()
        return self._total

    def summary(self) -> DigestSummary:
        self._compress()
        if self._total == 0:
            raise TDigestError("empty digest")
        return DigestSummary(
            count=self._total,
            min=self._min,
            max=self._max,
            centroid_count=len(self._centroids),
            compression=self._compression,
        )

    def centroids(self) -> tuple[Centroid, ...]:
        """Current clusters, sorted by mean (deterministic)."""
        self._compress()
        return tuple(Centroid(mean=m, count=c) for m, c in self._centroids)

    def quantile(self, q) -> float:
        """Estimated value at quantile q in [0, 1]."""
        if isinstance(q, bool) or not isinstance(q, (int, float)):
            raise TypeError("q must be a number")
        if math.isnan(q) or not 0.0 <= q <= 1.0:
            raise ValueError("q must be in [0, 1]")
        self._compress()
        if self._total == 0:
            raise TDigestError("empty digest")
        centroids = self._centroids
        if len(centroids) == 1:
            return centroids[0][0]
        # Half-mass knot positions: x_i = mass before centroid i + w_i/2.
        t = q * self._total
        xs: list[float] = []
        ys: list[float] = []
        cum = 0.0
        for mean, count in centroids:
            xs.append(cum + count / 2.0)
            ys.append(mean)
            cum += count
        if t <= xs[0]:
            return ys[0]
        if t >= xs[-1]:
            return ys[-1]
        for i in range(len(xs) - 1):
            if xs[i] <= t <= xs[i + 1]:
                if ys[i] == ys[i + 1]:
                    return ys[i]
                frac = (t - xs[i]) / (xs[i + 1] - xs[i])
                return ys[i] + frac * (ys[i + 1] - ys[i])
        return ys[-1]  # unreachable; kept fail-safe

    def cdf(self, x) -> float:
        """Estimated fraction of values <= x. Inverse of the quantile map."""
        f = _require_finite_float("x", x)
        self._compress()
        if self._total == 0:
            raise TDigestError("empty digest")
        centroids = self._centroids
        xs: list[float] = []
        ys: list[float] = []
        cum = 0.0
        for mean, count in centroids:
            xs.append(cum + count / 2.0)
            ys.append(mean)
            cum += count
        if f < ys[0]:
            return 0.0
        if f > ys[-1]:
            return 1.0
        for i in range(len(ys) - 1):
            lo, hi = ys[i], ys[i + 1]
            if lo == hi:
                if f == lo:
                    return (xs[i] + xs[i + 1]) / 2.0 / self._total
                continue
            if lo <= f <= hi:
                t = xs[i] + (xs[i + 1] - xs[i]) * (f - lo) / (hi - lo)
                return t / self._total
        return 1.0 if f >= ys[-1] else 0.0

    # ------------------------------------------------------------ internals

    def _compress(self) -> None:
        if not self._buffer:
            return
        points: list[tuple[float, int]] = list(self._centroids)
        points.extend((v, 1) for v in self._buffer)
        points.sort(key=lambda p: p[0])
        self._buffer = []
        total = self._total
        if total == 0:
            self._centroids = []
            return
        new: list[tuple[float, int]] = []
        cur_mean = 0.0
        cur_count = 0
        mass_before = 0.0  # mass of closed clusters
        for mean, count in points:
            if cur_count == 0:
                cur_mean, cur_count = mean, count
                continue
            q0 = mass_before / total
            q1 = (mass_before + cur_count + count) / total
            if _k1(q1, self._compression) - _k1(q0, self._compression) <= 1.0:
                merged = cur_count + count
                cur_mean = (cur_mean * cur_count + mean * count) / merged
                cur_count = merged
            else:
                new.append((cur_mean, cur_count))
                mass_before += cur_count
                cur_mean, cur_count = mean, count
        if cur_count:
            new.append((cur_mean, cur_count))
        self._centroids = new


def t_digest_audit_event(summary: DigestSummary, outcome: str, seq: int) -> dict:
    """Audit-shaped record for a digest observation."""
    if not isinstance(summary, DigestSummary):
        raise TypeError("summary must be a DigestSummary")
    if outcome not in ("observed", "merged", "queried"):
        raise ValueError("unknown outcome")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise ValueError("seq must be a non-negative int")
    return {
        "event": "t-digest",
        "outcome": outcome,
        "audit_seq": seq,
        "summary": summary.as_dict(),
        "schema": "audit.ndjson/1",
    }


def main() -> None:
    d = TDigest(compression=100.0)
    for v in range(1, 101):
        d.add(float(v))
    q50 = d.quantile(0.5)
    q99 = d.quantile(0.99)
    c = d.cdf(50.0)
    assert 45.0 <= q50 <= 56.0, q50
    assert 95.0 <= q99 <= 100.0, q99
    assert 0.45 <= c <= 0.56, c
    print(f"t-digest OK: q50={q50:.2f} q99={q99:.2f} cdf(50)={c:.3f}")


if __name__ == "__main__":
    main()
