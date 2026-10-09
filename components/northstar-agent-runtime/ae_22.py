"""AE-module: chunk -- Split list into chunks of size n."""
from __future__ import annotations
VERSION = "ae_22.v1"
def chunk(xs: list, n: int) -> list:
    return [xs[i:i + n] for i in range(0, len(xs), n)]

def main() -> None:
    assert chunk([1, 2, 3, 4, 5], 2) == [[1, 2], [3, 4], [5]]
    assert chunk([], 3) == []
    assert chunk([1], 5) == [[1]]
    print("ae_22 chunk OK")
if __name__ == "__main__": main()
