"""Order statistics: quickselect and running median."""

from __future__ import annotations

import heapq
import random


def kth_smallest(xs, k: int, seed: int = 0):
    """0-indexed kth smallest via randomized quickselect."""
    xs = list(xs)
    if not xs:
        raise ValueError("empty input")
    if not 0 <= k < len(xs):
        raise IndexError("k out of range")
    rng = random.Random(seed)
    lo, hi = 0, len(xs)
    while True:
        if hi - lo == 1:
            return xs[lo]
        pivot = xs[rng.randrange(lo, hi)]
        i, lt, gt = lo, lo, hi
        while i < gt:
            if xs[i] < pivot:
                xs[lt], xs[i] = xs[i], xs[lt]
                lt += 1
                i += 1
            elif xs[i] > pivot:
                gt -= 1
                xs[i], xs[gt] = xs[gt], xs[i]
            else:
                i += 1
        if k < lt:
            hi = lt
        elif k >= gt:
            lo = gt
        else:
            return xs[k]


def running_median(xs):
    """Median after each prefix (two heaps)."""
    lo: list = []  # max-heap (negated)
    hi: list = []  # min-heap
    out = []
    for x in xs:
        if not lo or x <= -lo[0]:
            heapq.heappush(lo, -x)
        else:
            heapq.heappush(hi, x)
        if len(lo) > len(hi) + 1:
            heapq.heappush(hi, -heapq.heappop(lo))
        elif len(hi) > len(lo):
            heapq.heappush(lo, -heapq.heappop(hi))
        if len(lo) > len(hi):
            out.append(float(-lo[0]))
        else:
            out.append((-lo[0] + hi[0]) / 2.0)
    return out


def main() -> None:
    assert kth_smallest([3, 1, 2], 1) == 2
    assert kth_smallest([5, 4, 3, 2, 1], 0) == 1
    assert kth_smallest([5, 4, 3, 2, 1], 4) == 5
    assert running_median([1, 3, 2]) == [1.0, 2.0, 2.0]
    assert running_median([5, 15, 1, 3]) == [5.0, 10.0, 5.0, 4.0]
    print("math_40 OK")


if __name__ == "__main__":
    main()
