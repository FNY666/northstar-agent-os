"""Merkle tree: SHA-256 hash tree with inclusion proofs. Stdlib only."""
from __future__ import annotations
import hashlib
from typing import List, Optional, Tuple

def _h(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

class MerkleTree:
    def __init__(self, leaves: List[bytes]) -> None:
        assert leaves
        self.levels: List[List[str]] = [[_h(l) for l in leaves]]
        cur = self.levels[0]
        while len(cur) > 1:
            nxt = []
            for i in range(0, len(cur), 2):
                r = cur[i + 1] if i + 1 < len(cur) else cur[i]
                nxt.append(_h((cur[i] + r).encode()))
            self.levels.append(nxt)
            cur = nxt
    @property
    def root(self) -> str: return self.levels[-1][0]
    def proof(self, idx: int) -> List[Tuple[str, bool]]:
        """Sibling hashes with is_left flag."""
        p = []
        i = idx
        for lvl in self.levels[:-1]:
            sib = i + 1 if i % 2 == 0 else i - 1
            sib = min(sib, len(lvl) - 1)
            p.append((lvl[sib], sib < i))
            i //= 2
        return p
    @staticmethod
    def verify(leaf: bytes, proof, root: str) -> bool:
        cur = _h(leaf)
        for sib, is_left in proof:
            cur = _h((sib + cur).encode()) if is_left else _h((cur + sib).encode())
        return cur == root

def main() -> None:
    mt = MerkleTree([b"a", b"b", b"c", b"d"])
    p = mt.proof(2)
    assert MerkleTree.verify(b"c", p, mt.root)
    assert not MerkleTree.verify(b"X", p, mt.root)
    mt1 = MerkleTree([b"solo"])
    assert MerkleTree.verify(b"solo", mt1.proof(0), mt1.root)
    print("tree_40 Merkle tree OK")

if __name__ == "__main__":
    main()
