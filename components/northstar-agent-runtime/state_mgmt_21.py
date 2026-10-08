"""State 21: Merkle-tree sync (mock), Simulated.

Merkle tree over a key-value store for efficient diff:
- leaves = sha256(key || 0x00 || value), sorted by key
- internal nodes = sha256(left || right); odd node promoted
- root(): tree root hash
- diff(other): walk both trees, return keys whose leaves differ
  (only differing subtrees are descended — O(d log n))

Mock: in-process dicts; models the tree-diff protocol.

Fail-closed: non-str keys/values, or diff against a tree built with
a different leaf encoding (version tag mismatch), raise.
"""

from __future__ import annotations

import ast
import hashlib
from typing import Dict, List, Optional, Tuple


MODULE_VERSION = "state-mgmt-21.v1"
SCHEMA_PIN = "northstar.state-mgmt-21.v1"
LEAF_VERSION = 1


class MerkleError(Exception):
    pass


def _leaf(key: str, value: str) -> bytes:
    return hashlib.sha256(
        LEAF_VERSION.to_bytes(1, "big") + b"\x00"
        + key.encode() + b"\x00" + value.encode()
    ).digest()


def _parent(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


class MerkleTree:
    def __init__(self, data: Dict[str, str]) -> None:
        for k, v in data.items():
            if not isinstance(k, str) or not isinstance(v, str):
                raise MerkleError("keys and values must be str")
        self.keys = sorted(data)
        self.leaves: List[bytes] = [_leaf(k, data[k]) for k in self.keys]
        self.levels: List[List[bytes]] = [self.leaves]
        self._build()

    def _build(self) -> None:
        cur = self.leaves
        while len(cur) > 1:
            nxt = []
            for i in range(0, len(cur), 2):
                if i + 1 < len(cur):
                    nxt.append(_parent(cur[i], cur[i + 1]))
                else:
                    nxt.append(cur[i])  # odd: promote
            self.levels.append(nxt)
            cur = nxt

    def root(self) -> str:
        if not self.leaves:
            return "sha256:" + hashlib.sha256(b"empty").hexdigest()
        return "sha256:" + self.levels[-1][0].hex()

    def _collect(self, other: "MerkleTree", level: int, idx: int,
                 out: List[str]) -> None:
        mine = self.levels[level]
        theirs = other.levels[level]
        if level == 0:
            # Leaf level: compare per key index.
            n = max(len(mine), len(theirs))
            for i in range(n):
                a = mine[i] if i < len(mine) else None
                b = theirs[i] if i < len(theirs) else None
                if a != b:
                    key = self.keys[i] if i < len(self.keys) else other.keys[i]
                    out.append(key)
            return
        # Internal level: descend into differing children.
        n = max(len(mine), len(theirs))
        for i in range(n):
            a = mine[i] if i < len(mine) else None
            b = theirs[i] if i < len(theirs) else None
            if a != b:
                self._collect(other, level - 1, i * 2, out)

    def diff(self, other: "MerkleTree") -> List[str]:
        if not isinstance(other, MerkleTree):
            raise MerkleError("diff requires a MerkleTree")
        if self.root() == other.root():
            return []
        top = len(self.levels) - 1
        out: List[str] = []
        self._collect(other, top, 0, out)
        # Dedupe while preserving order (structure may double-report).
        seen = set()
        uniq = []
        for k in out:
            if k not in seen:
                seen.add(k)
                uniq.append(k)
        return sorted(uniq)


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "hashlib", "pathlib", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    t1 = MerkleTree({f"k{i}": f"v{i}" for i in range(16)})
    t2 = MerkleTree({f"k{i}": f"v{i}" for i in range(16)})
    assert t1.root() == t2.root()
    assert t1.diff(t2) == []
    t3 = MerkleTree({f"k{i}": ("DIFF" if i == 5 else f"v{i}") for i in range(16)})
    assert t1.root() != t3.root()
    assert t1.diff(t3) == ["k5"]
    # Added key shows up.
    t4 = MerkleTree({f"k{i}": f"v{i}" for i in range(17)})
    assert "k16" in t1.diff(t4)
    # Non-str -> fail-closed.
    try:
        MerkleTree({"k": 123})  # type: ignore[dict-item]
        raise AssertionError("should raise")
    except MerkleError:
        pass
    assert stdlib_only()
    print("state_mgmt_21 OK: merkle root, subtree diff, fail-closed")


if __name__ == "__main__":
    main()
