"""Binary heap: array-based min-heap. Stdlib only."""
from __future__ import annotations
from typing import List

class BinaryHeap:
    def __init__(self) -> None:
        self.a: List[int] = []
    def __len__(self) -> int: return len(self.a)
    def push(self, x: int) -> None:
        a = self.a
        a.append(x)
        i = len(a) - 1
        while i > 0:
            p = (i - 1) // 2
            if a[p] <= a[i]: break
            a[p], a[i] = a[i], a[p]; i = p
    def peek(self) -> int:
        if not self.a: raise IndexError("empty")
        return self.a[0]
    def pop(self) -> int:
        a = self.a
        if not a: raise IndexError("empty")
        top = a[0]
        last = a.pop()
        if a:
            a[0] = last
            i = 0
            while True:
                l, r = 2 * i + 1, 2 * i + 2
                m = i
                if l < len(a) and a[l] < a[m]: m = l
                if r < len(a) and a[r] < a[m]: m = r
                if m == i: break
                a[i], a[m] = a[m], a[i]; i = m
        return top
    def is_heap(self) -> bool:
        a = self.a
        return all(a[(i - 1) // 2] <= a[i] for i in range(1, len(a)))

def main() -> None:
    h = BinaryHeap()
    for x in [5, 3, 8, 1, 4]: h.push(x)
    assert h.peek() == 1 and h.is_heap()
    assert [h.pop() for _ in range(5)] == [1, 3, 4, 5, 8]
    assert len(h) == 0
    print("tree_34 Binary heap OK")

if __name__ == "__main__":
    main()
