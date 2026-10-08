"""Huffman tree: optimal prefix coding. Stdlib only."""
from __future__ import annotations
import heapq
from dataclasses import dataclass
from typing import Dict, Optional

@dataclass
class HNode:
    freq: int
    sym: Optional[str] = None
    left: Optional["HNode"] = None
    right: Optional["HNode"] = None
    def __lt__(self, other): return self.freq < other.freq

def build(freqs: Dict[str, int]) -> HNode:
    heap = [HNode(f, s) for s, f in freqs.items()]
    heapq.heapify(heap)
    while len(heap) > 1:
        a = heapq.heappop(heap); b = heapq.heappop(heap)
        heapq.heappush(heap, HNode(a.freq + b.freq, None, a, b))
    return heap[0]

def codes(root: HNode) -> Dict[str, str]:
    out: Dict[str, str] = {}
    def rec(n, cur):
        if n.sym is not None: out[n.sym] = cur or "0"
        else: rec(n.left, cur + "0"); rec(n.right, cur + "1")
    rec(root, "")
    return out

def encode(s: str, c: Dict[str, str]) -> str: return "".join(c[ch] for ch in s)
def decode(bits: str, root: HNode) -> str:
    if root.sym is not None: return root.sym * len(bits)
    out, n = [], root
    for b in bits:
        n = n.left if b == "0" else n.right
        if n.sym is not None: out.append(n.sym); n = root
    return "".join(out)

def main() -> None:
    root = build({"a": 5, "b": 2, "c": 1})
    c = codes(root)
    assert len(c["a"]) <= len(c["b"]) <= len(c["c"])
    enc = encode("aabac", c)
    assert decode(enc, root) == "aabac"
    print("tree_36 Huffman OK")

if __name__ == "__main__":
    main()
