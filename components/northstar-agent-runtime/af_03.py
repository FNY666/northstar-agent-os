"""AF-module: chunk_list -- Split a list into chunks of size n (last may be shorter)."""
from __future__ import annotations
VERSION = "af_03"
def chunk_list(xs: list, n: int) -> list:
    if n <= 0:
        raise ValueError('n must be positive')
    return [xs[i:i + n] for i in range(0, len(xs), n)]

def main() -> None:
    assert chunk_list([1, 2, 3, 4, 5], 2) == [[1, 2], [3, 4], [5]]
    assert chunk_list([], 3) == []
    assert chunk_list([1, 2], 5) == [[1, 2]]
    print("af_03 chunk_list OK")
if __name__ == "__main__": main()
