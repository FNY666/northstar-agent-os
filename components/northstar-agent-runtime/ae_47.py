"""AE-module: zip_fill -- Pair two lists, padding the short one with fill."""
from __future__ import annotations
VERSION = "ae_47.v1"
def zip_fill(a: list, b: list, fill=None) -> list:
    n = max(len(a), len(b))
    return [(a[i] if i < len(a) else fill, b[i] if i < len(b) else fill) for i in range(n)]

def main() -> None:
    assert zip_fill([1, 2], [3]) == [(1, 3), (2, None)]
    assert zip_fill([], []) == []
    assert zip_fill([1], [2, 3], 0) == [(1, 2), (0, 3)]
    print("ae_47 zip_fill OK")
if __name__ == "__main__": main()
