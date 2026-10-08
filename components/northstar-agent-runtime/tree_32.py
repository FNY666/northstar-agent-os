"""UB-tree (mock): Z-order (Morton) curve linearization. Stdlib only."""
from __future__ import annotations
from typing import List, Tuple

def z_order(x: int, y: int, bits: int = 8) -> int:
    z = 0
    for i in range(bits):
        z |= ((x >> i) & 1) << (2 * i)
        z |= ((y >> i) & 1) << (2 * i + 1)
    return z

class UBTreeMock:
    def __init__(self, bits: int = 8) -> None:
        self.bits = bits
        self.entries: List[Tuple[int, Tuple[int, int], object]] = []
    def insert(self, x: int, y: int, payload: object) -> None:
        self.entries.append((z_order(x, y, self.bits), (x, y), payload))
        self.entries.sort(key=lambda e: e[0])
    def range_query(self, x0: int, y0: int, x1: int, y1: int) -> List[object]:
        # mock: filter by coordinates (real UB-tree scans Z-intervals)
        return [p for _, (x, y), p in self.entries
                if x0 <= x <= x1 and y0 <= y <= y1]

def main() -> None:
    assert z_order(0, 0) == 0
    assert z_order(1, 0) == 1 and z_order(0, 1) == 2 and z_order(1, 1) == 3
    ub = UBTreeMock()
    ub.insert(1, 1, "a"); ub.insert(5, 5, "b")
    assert ub.range_query(0, 0, 2, 2) == ["a"]
    assert ub.range_query(0, 0, 9, 9) == ["a", "b"]
    print("tree_32 UB-tree (mock) OK")

if __name__ == "__main__":
    main()
