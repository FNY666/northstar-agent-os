"""H-tree (mock): hashed directory tree for spatial data. Stdlib only."""
from __future__ import annotations
from typing import Dict, List, Tuple

def _hash_cell(x: int, y: int, level: int) -> int:
    return hash((x >> level, y >> level, level)) & 0xFFFFFFFF

class HTreeMock:
    def __init__(self) -> None:
        self.dir: Dict[int, List[Tuple[int, int, object]]] = {}
    def insert(self, x: int, y: int, payload: object, level: int = 0) -> None:
        h = _hash_cell(x, y, level)
        self.dir.setdefault(h, []).append((x, y, payload))
    def query(self, x: int, y: int, level: int = 0) -> List[object]:
        h = _hash_cell(x, y, level)
        return [p for px, py, p in self.dir.get(h, []) if px == x and py == y]

def main() -> None:
    h = HTreeMock()
    h.insert(3, 4, "a"); h.insert(3, 4, "b"); h.insert(7, 7, "c")
    assert sorted(h.query(3, 4)) == ["a", "b"]
    assert h.query(0, 0) == []
    assert h.query(7, 7) == ["c"]
    print("tree_33 H-tree (mock) OK")

if __name__ == "__main__":
    main()
