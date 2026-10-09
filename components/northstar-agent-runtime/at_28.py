"""at_28: chunk -- Split xs into chunks of n."""
from __future__ import annotations
VERSION = "at_28.v1"
def chunk(xs, n):
    return [xs[i:i + n] for i in range(0, len(xs), n)]

def main() -> None:
    assert chunk([1, 2, 3, 4], 2) == [[1, 2], [3, 4]]
    assert chunk([], 3) == []
    print("at_28 chunk OK")
if __name__ == "__main__": main()
