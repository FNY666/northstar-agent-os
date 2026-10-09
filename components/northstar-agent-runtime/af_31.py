"""AF-module: sliding_window -- Sliding windows of size n over a list."""
from __future__ import annotations
VERSION = "af_31"
def sliding_window(xs: list, n: int) -> list:
    if n <= 0:
        raise ValueError('n must be positive')
    return [xs[i:i + n] for i in range(len(xs) - n + 1)]

def main() -> None:
    assert sliding_window([1, 2, 3, 4], 2) == [[1, 2], [2, 3], [3, 4]]
    assert sliding_window([1], 2) == []
    assert sliding_window([1, 2], 2) == [[1, 2]]
    print("af_31 sliding_window OK")
if __name__ == "__main__": main()
