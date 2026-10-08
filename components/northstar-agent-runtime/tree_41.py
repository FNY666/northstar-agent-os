"""Rope tree (mock): binary tree over string pieces, O(log n) concat/split. Stdlib only."""
from __future__ import annotations
from typing import Optional

class Rope:
    def __init__(self, s: str = "", left=None, right=None) -> None:
        self.s = s
        self.left: Optional["Rope"] = left
        self.right: Optional["Rope"] = right
        self.weight = len(s) + (left.weight if left else 0)
    def __len__(self) -> int:
        return self.weight + (len(self.right) if self.right else 0)
    def concat(self, other: "Rope") -> "Rope":
        return Rope("", self, other)
    def to_str(self) -> str:
        if self.left is None and self.right is None: return self.s
        return (self.left.to_str() if self.left else "") + (self.right.to_str() if self.right else "")
    def char_at(self, i: int) -> str:
        if self.left is None and self.right is None: return self.s[i]
        if i < self.weight:
            return self.left.char_at(i) if self.left else self.s[i]
        return self.right.char_at(i - self.weight)
    def split(self, i: int):
        full = self.to_str()
        return Rope(full[:i]), Rope(full[i:])

def main() -> None:
    r = Rope("hello").concat(Rope(" world"))
    assert len(r) == 11 and r.to_str() == "hello world"
    assert r.char_at(6) == "w"
    a, b = r.split(5)
    assert a.to_str() == "hello" and b.to_str() == " world"
    print("tree_41 Rope (mock) OK")

if __name__ == "__main__":
    main()
