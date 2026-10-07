"""B-tree: deterministic ordered key-value index for the runtime's own state.

Research note: B-trees (Bayer & McCreight, 1972) keep key/value pairs
sorted in a balanced multiway tree with ``O(log n)`` insert/search/delete
and ordered scans. Here the tree indexes host-owned runtime state that
must be *ordered* rather than merely addressed — pending request queues
by sequence number, audit offsets, compaction cursors, budget ledger
entries — where a hash map loses the ordering the host's logic depends
on.

* **Balanced by construction** — every node holds ``t-1`` to ``2t-1``
  keys (``t`` = ``min_degree``); splits propagate up on insert, merges
  and borrows rebalance on delete, so the height stays logarithmic no
  matter the insertion order. No pathological degenerate case.
* **Map semantics** — inserting an existing key *replaces* its value
  (last-write-wins for the index entry, not a multiset). Replacement is
  found and performed in-place; the tree shape is untouched.
* **Type-homogeneous keys** — keys are ``int`` or ``str`` and every key
  in one tree shares one type. Mixed-type comparison would fail inside
  a comparison anyway; the tree rejects it loudly at the API boundary
  instead of raising ``TypeError`` mid-traversal. ``bool`` is rejected
  (``True == 1`` would silently alias keys).
* **Fail-closed** — malformed inputs raise ``BTreeError``/``TypeError``
  rather than corrupting the tree; an empty tree answers every query
  with emptiness (``None`` / ``False`` / ``()``), never a guess.
* **Deterministic** — pure structural operations, no randomness, no
  wall-clock, no hashing of keys (ordering is the comparison itself).

Honest scope: this is an *in-memory ordered index*, not a database —
no persistence, no transactions, no crash recovery (snapshot/persist
is the host's job via ``items()``); ``range_query`` walks the tree in
order (``O(n)`` for the covered range, not a cursor); ``search`` returns
the stored value, which the tree never inspects. A clean result means
"the index holds no such key", never "the world holds no such record".
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, List, Optional, Tuple

#: Module version.
BTREE_INDEX_VERSION = "btree-index.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.btree-index.v1"

#: Fixed vocabulary for audit events.
AUDIT_KINDS = ("insert", "delete", "search", "range-query")


class BTreeError(Exception):
    """Base error for B-tree misuse (fail-closed, never silent corruption)."""


class _Node:
    """Internal B-tree node. Mutable container; the tree owns all mutation."""

    __slots__ = ("keys", "values", "children", "leaf")

    def __init__(self, leaf: bool):
        self.keys: List[Any] = []
        self.values: List[Any] = []
        self.children: List[_Node] = []
        self.leaf = leaf


def _validate_min_degree(min_degree: Any) -> int:
    if isinstance(min_degree, bool) or not isinstance(min_degree, int):
        raise BTreeError(f"min_degree must be an int >= 2, got {min_degree!r}")
    if min_degree < 2:
        raise BTreeError(f"min_degree must be >= 2, got {min_degree}")
    return min_degree


def _validate_key(key: Any) -> Any:
    """Keys are int or str; bool is rejected (True == 1 would alias keys)."""
    if isinstance(key, bool) or not isinstance(key, (int, str)):
        raise BTreeError(f"key must be int or str (not bool), got {type(key).__name__}")
    return key


@dataclass(frozen=True)
class BTreeEntry:
    """Immutable key/value record, e.g. one range-query hit."""

    key: Any
    value: Any

    def as_dict(self) -> dict:
        return {"schema": SCHEMA_PIN, "key": self.key, "value": self.value}


class BTree:
    """Ordered key-value index with B-tree (CLRS) structure."""

    def __init__(self, min_degree: int = 2):
        self._t = _validate_min_degree(min_degree)
        self._root = _Node(leaf=True)
        self._key_type: Optional[type] = None
        self._size = 0

    # -- key discipline -------------------------------------------------

    def _require_key(self, key: Any, *, allow_first: bool) -> Any:
        """Validate a key; enforce type homogeneity within the tree."""
        _validate_key(key)
        if self._key_type is None:
            if allow_first:
                self._key_type = type(key)
            return key
        if type(key) is not self._key_type:
            raise BTreeError(
                f"key type {type(key).__name__} does not match tree key type "
                f"{self._key_type.__name__}"
            )
        return key

    # -- core operations ------------------------------------------------

    def insert(self, key: Any, value: Any) -> None:
        """Insert or replace (map semantics): existing keys keep their slot."""
        self._require_key(key, allow_first=True)
        if self._replace(self._root, key, value):
            return
        root = self._root
        if len(root.keys) == 2 * self._t - 1:
            new_root = _Node(leaf=False)
            new_root.children.append(root)
            self._split_child(new_root, 0)
            self._root = new_root
            self._insert_nonfull(new_root, key, value)
        else:
            self._insert_nonfull(root, key, value)
        self._size += 1

    def search(self, key: Any) -> Optional[Any]:
        """Return the value for ``key``, or ``None`` when absent."""
        self._require_key(key, allow_first=False)
        node, idx = self._find(self._root, key)
        if node is not None:
            return node.values[idx]
        return None

    def contains(self, key: Any) -> bool:
        """True iff ``key`` is present."""
        return self.search(key) is not None

    def delete(self, key: Any) -> bool:
        """Remove ``key``; True if it was present, False otherwise."""
        self._require_key(key, allow_first=False)
        if not self._delete(self._root, key):
            return False
        self._size -= 1
        if not self._root.leaf and len(self._root.keys) == 0:
            self._root = self._root.children[0]
        return True

    def range_query(self, start: Any, end: Any) -> Tuple[BTreeEntry, ...]:
        """All entries with ``start <= key <= end``, in ascending key order."""
        _validate_key(start)
        _validate_key(end)
        if type(start) is not type(end):
            raise BTreeError(
                f"range bounds must share a type, got "
                f"{type(start).__name__} and {type(end).__name__}"
            )
        if start > end:
            raise BTreeError(f"range start {start!r} is greater than end {end!r}")
        if self._key_type is not None and type(start) is not self._key_type:
            raise BTreeError(
                f"range bound type {type(start).__name__} does not match "
                f"tree key type {self._key_type.__name__}"
            )
        out: List[BTreeEntry] = []
        self._collect_range(self._root, start, end, out)
        return tuple(out)

    # -- views ----------------------------------------------------------

    def keys(self) -> Tuple[Any, ...]:
        """All keys in ascending order."""
        return tuple(entry.key for entry in self.items())

    def items(self) -> Tuple[BTreeEntry, ...]:
        """All (key, value) pairs in ascending key order."""
        out: List[BTreeEntry] = []
        self._collect_all(self._root, out)
        return tuple(out)

    def height(self) -> int:
        """Number of levels (empty tree has height 0)."""
        if self._size == 0:
            return 0
        h = 1
        node = self._root
        while not node.leaf:
            node = node.children[0]
            h += 1
        return h

    def __len__(self) -> int:
        return self._size

    def __contains__(self, key: Any) -> bool:
        return self.contains(key)

    # -- insertion internals (CLRS) -------------------------------------

    def _replace(self, node: _Node, key: Any, value: Any) -> bool:
        """Replace value in place if key exists; True when found."""
        i = 0
        while i < len(node.keys) and node.keys[i] < key:
            i += 1
        if i < len(node.keys) and node.keys[i] == key:
            node.values[i] = value
            return True
        if node.leaf:
            return False
        return self._replace(node.children[i], key, value)

    def _split_child(self, parent: _Node, i: int) -> None:
        t = self._t
        full = parent.children[i]
        sibling = _Node(leaf=full.leaf)
        sibling.keys = full.keys[t:]
        sibling.values = full.values[t:]
        if not full.leaf:
            sibling.children = full.children[t:]
        mid_key = full.keys[t - 1]
        mid_value = full.values[t - 1]
        full.keys = full.keys[: t - 1]
        full.values = full.values[: t - 1]
        if not full.leaf:
            full.children = full.children[:t]
        parent.children.insert(i + 1, sibling)
        parent.keys.insert(i, mid_key)
        parent.values.insert(i, mid_value)

    def _insert_nonfull(self, node: _Node, key: Any, value: Any) -> None:
        t = self._t
        if node.leaf:
            i = len(node.keys) - 1
            node.keys.append(None)  # type: ignore[arg-type]
            node.values.append(None)
            while i >= 0 and key < node.keys[i]:
                node.keys[i + 1] = node.keys[i]
                node.values[i + 1] = node.values[i]
                i -= 1
            node.keys[i + 1] = key
            node.values[i + 1] = value
            return
        i = len(node.keys) - 1
        while i >= 0 and key < node.keys[i]:
            i -= 1
        i += 1
        if len(node.children[i].keys) == 2 * t - 1:
            self._split_child(node, i)
            if key > node.keys[i]:
                i += 1
        self._insert_nonfull(node.children[i], key, value)

    def _find(self, node: _Node, key: Any) -> Tuple[Optional[_Node], int]:
        i = 0
        while i < len(node.keys) and node.keys[i] < key:
            i += 1
        if i < len(node.keys) and node.keys[i] == key:
            return node, i
        if node.leaf:
            return None, -1
        return self._find(node.children[i], key)

    # -- deletion internals (CLRS) --------------------------------------

    def _delete(self, node: _Node, key: Any) -> bool:
        t = self._t
        i = 0
        while i < len(node.keys) and node.keys[i] < key:
            i += 1
        if node.leaf:
            if i < len(node.keys) and node.keys[i] == key:
                del node.keys[i]
                del node.values[i]
                return True
            return False
        if i < len(node.keys) and node.keys[i] == key:
            return self._delete_from_internal(node, i)
        # Key is not in this node; descend into child i.
        if len(node.children[i].keys) < t:
            i = self._fill(node, i)
        return self._delete(node.children[i], key)

    def _delete_from_internal(self, node: _Node, i: int) -> bool:
        t = self._t
        if len(node.children[i].keys) >= t:
            pred = self._predecessor(node.children[i])
            node.keys[i] = pred[0]
            node.values[i] = pred[1]
            return self._delete(node.children[i], pred[0])
        if len(node.children[i + 1].keys) >= t:
            succ = self._successor(node.children[i + 1])
            node.keys[i] = succ[0]
            node.values[i] = succ[1]
            return self._delete(node.children[i + 1], succ[0])
        key = node.keys[i]
        self._merge(node, i)
        return self._delete(node.children[i], key)

    def _predecessor(self, node: _Node) -> Tuple[Any, Any]:
        while not node.leaf:
            node = node.children[-1]
        return node.keys[-1], node.values[-1]

    def _successor(self, node: _Node) -> Tuple[Any, Any]:
        while not node.leaf:
            node = node.children[0]
        return node.keys[0], node.values[0]

    def _fill(self, node: _Node, i: int) -> int:
        """Ensure child i has >= t keys before descending; return child index."""
        t = self._t
        if i > 0 and len(node.children[i - 1].keys) >= t:
            self._borrow_from_prev(node, i)
            return i
        if i < len(node.children) - 1 and len(node.children[i + 1].keys) >= t:
            self._borrow_from_next(node, i)
            return i
        if i == len(node.children) - 1:
            self._merge(node, i - 1)
            return i - 1
        self._merge(node, i)
        return i

    def _borrow_from_prev(self, node: _Node, i: int) -> None:
        child = node.children[i]
        sibling = node.children[i - 1]
        child.keys.insert(0, node.keys[i - 1])
        child.values.insert(0, node.values[i - 1])
        if not child.leaf:
            child.children.insert(0, sibling.children.pop())
        node.keys[i - 1] = sibling.keys.pop()
        node.values[i - 1] = sibling.values.pop()

    def _borrow_from_next(self, node: _Node, i: int) -> None:
        child = node.children[i]
        sibling = node.children[i + 1]
        child.keys.append(node.keys[i])
        child.values.append(node.values[i])
        if not child.leaf:
            child.children.append(sibling.children.pop(0))
        node.keys[i] = sibling.keys.pop(0)
        node.values[i] = sibling.values.pop(0)

    def _merge(self, node: _Node, i: int) -> None:
        t = self._t
        left = node.children[i]
        right = node.children[i + 1]
        left.keys.append(node.keys.pop(i))
        left.values.append(node.values.pop(i))
        left.keys.extend(right.keys)
        left.values.extend(right.values)
        if not left.leaf:
            left.children.extend(right.children)
        del node.children[i + 1]
        assert len(left.keys) == 2 * t - 1

    # -- ordered traversal ----------------------------------------------

    def _collect_range(
        self, node: _Node, start: Any, end: Any, out: List[BTreeEntry]
    ) -> None:
        i = 0
        n = len(node.keys)
        while i < n and node.keys[i] < start:
            i += 1
        if not node.leaf:
            self._collect_range(node.children[i], start, end, out)
        while i < n and node.keys[i] <= end:
            out.append(BTreeEntry(node.keys[i], node.values[i]))
            if not node.leaf:
                self._collect_range(node.children[i + 1], start, end, out)
            i += 1

    def _collect_all(self, node: _Node, out: List[BTreeEntry]) -> None:
        for i, key in enumerate(node.keys):
            if not node.leaf:
                self._collect_all(node.children[i], out)
            out.append(BTreeEntry(key, node.values[i]))
        if not node.leaf:
            self._collect_all(node.children[len(node.keys)], out)


def btree_audit_event(kind: str, key: Any, seq: int) -> dict:
    """Audit-shaped record for one B-tree operation (caller-supplied seq)."""
    if kind not in AUDIT_KINDS:
        raise BTreeError(f"unknown audit kind {kind!r}; expected one of {AUDIT_KINDS}")
    _validate_key(key)
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise BTreeError(f"seq must be a non-negative int, got {seq!r}")
    return {
        "schema": "audit.ndjson/1",
        "module": SCHEMA_PIN,
        "kind": kind,
        "key": key,
        "audit_seq": seq,
    }


def main() -> None:
    tree = BTree(min_degree=2)
    for k in (5, 3, 8, 1, 9, 4):
        tree.insert(k, f"v{k}")
    assert tree.search(8) == "v8"
    assert tree.search(7) is None
    assert [e.key for e in tree.range_query(3, 8)] == [3, 4, 5, 8]
    assert tree.delete(5) is True
    assert tree.search(5) is None
    assert tree.keys() == (1, 3, 4, 8, 9)
    print("btree-index OK: insert/search/delete/range all ordered")


if __name__ == "__main__":
    main()
