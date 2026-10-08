"""Monte Carlo estimation of pi (seeded, deterministic).

estimate_pi(n, seed): fraction of uniform [0,1)^2 points inside the
quarter circle, scaled by 4.
"""

from __future__ import annotations

import math
import random


def estimate_pi(n: int, seed: int = 0) -> float:
    if n < 1:
        raise ValueError("n must be >= 1")
    rng = random.Random(seed)
    inside = 0
    for _ in range(n):
        x, y = rng.random(), rng.random()
        if x * x + y * y <= 1.0:
            inside += 1
    return 4.0 * inside / n


def main() -> None:
    assert estimate_pi(1000, seed=0) == estimate_pi(1000, seed=0)
    assert abs(estimate_pi(200000, seed=42) - math.pi) < 0.02
    print("math_35 OK")


if __name__ == "__main__":
    main()
