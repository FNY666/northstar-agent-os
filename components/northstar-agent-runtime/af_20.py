"""AF-module: moving_average -- Sliding-window means of a numeric list."""
from __future__ import annotations
VERSION = "af_20"
def moving_average(xs: list, w: int) -> list:
    if w <= 0:
        raise ValueError('w must be positive')
    return [sum(xs[i:i + w]) / w for i in range(len(xs) - w + 1)]

def main() -> None:
    assert moving_average([1, 2, 3, 4], 2) == [1.5, 2.5, 3.5]
    assert moving_average([1, 2], 3) == []
    assert moving_average([5], 1) == [5.0]
    print("af_20 moving_average OK")
if __name__ == "__main__": main()
