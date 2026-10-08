"""X-module: chunk -- Split list into chunks of size n."""
from __future__ import annotations
VERSION = "x_09.v1"
def chunk(xs: list, n: int) -> list:
    if n <= 0: raise ValueError("n must be > 0")
    return [xs[i:i + n] for i in range(0, len(xs), n)]

def main() -> None:
    assert chunk([1, 2, 3, 4, 5], 2) == [[1, 2], [3, 4], [5]]
    assert chunk([], 3) == []
    print("x_09 chunk OK")
if __name__ == "__main__": main()
