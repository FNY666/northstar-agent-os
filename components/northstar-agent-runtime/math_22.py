"""Ordinary least-squares linear regression (1D).

linregress(xs, ys) -> dict(slope, intercept, r_squared, n).
"""

from __future__ import annotations


def linregress(xs, ys) -> dict:
    xs, ys = list(xs), list(ys)
    if len(xs) != len(ys):
        raise ValueError("xs and ys must have equal length")
    n = len(xs)
    if n < 2:
        raise ValueError("need at least 2 points")
    mx = sum(xs) / n
    my = sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    if sxx == 0:
        raise ValueError("xs are constant")
    sxy = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    slope = sxy / sxx
    intercept = my - slope * mx
    ss_res = sum((y - (slope * x + intercept)) ** 2 for x, y in zip(xs, ys))
    ss_tot = sum((y - my) ** 2 for y in ys)
    r_squared = 1.0 - ss_res / ss_tot if ss_tot != 0 else 0.0
    return {"slope": slope, "intercept": intercept,
            "r_squared": r_squared, "n": n}


def predict(model: dict, x: float) -> float:
    return model["slope"] * x + model["intercept"]


def main() -> None:
    model = linregress([1, 2, 3, 4], [2, 4, 6, 8])
    assert abs(model["slope"] - 2.0) < 1e-9
    assert abs(model["intercept"]) < 1e-9
    assert abs(model["r_squared"] - 1.0) < 1e-9
    assert predict(model, 5) == 10.0
    noisy = linregress([0, 1, 2, 3], [1, 3, 5, 7])  # y = 2x + 1
    assert abs(noisy["slope"] - 2.0) < 1e-9
    assert abs(noisy["intercept"] - 1.0) < 1e-9
    print("math_22 OK")


if __name__ == "__main__":
    main()
