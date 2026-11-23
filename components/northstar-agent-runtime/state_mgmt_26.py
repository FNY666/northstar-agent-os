"""State 26: OR-set (observed-remove set) CRDT.

Add-wins semantics via unique tags:
- add(elem): generates a fresh tag (node, counter), stores tag -> elem
- remove(elem): moves all currently-observed tags for elem to tombstones
- merge(other): union of adds and tombstones; an element is present
  iff it has at least one add tag not in tombstones

Concurrent add + remove -> add wins (the remove only saw the old tags).

Fail-closed: empty elements, merging with mismatched replica config
is allowed (tags are globally unique), but malformed tags raise.
"""

from __future__ import annotations

import ast
from typing import Dict, Set, Tuple


MODULE_VERSION = "state-mgmt-26.v1"
SCHEMA_PIN = "northstar.state-mgmt-26.v1"


class ORSetError(Exception):
    pass


Tag = Tuple[str, int]  # (node, counter)


class ORSet:
    def __init__(self, node_id: str) -> None:
        if not node_id:
            raise ORSetError("node_id required")
        self.node_id = node_id
        self._counter = 0
        self.adds: Dict[Tag, str] = {}
        self.tombstones: Set[Tag] = set()

    def _next_tag(self) -> Tag:
        self._counter += 1
        return (self.node_id, self._counter)

    def add(self, elem: str) -> Tag:
        if not isinstance(elem, str) or not elem:
            raise ORSetError("element must be non-empty str")
        tag = self._next_tag()
        self.adds[tag] = elem
        return tag

    def remove(self, elem: str) -> int:
        """Tombstone all observed tags for elem.  Returns count removed."""
        if not isinstance(elem, str) or not elem:
            raise ORSetError("element must be non-empty str")
        doomed = [t for t, e in self.adds.items()
                  if e == elem and t not in self.tombstones]
        self.tombstones.update(doomed)
        return len(doomed)

    def __contains__(self, elem: object) -> bool:
        return any(e == elem and t not in self.tombstones
                   for t, e in self.adds.items())

    def elements(self) -> Set[str]:
        return {e for t, e in self.adds.items() if t not in self.tombstones}

    def merge(self, other: "ORSet") -> None:
        if not isinstance(other, ORSet):
            raise ORSetError("merge requires an ORSet")
        for tag, elem in other.adds.items():
            if (not isinstance(tag, tuple) or len(tag) != 2
                    or not isinstance(elem, str)):
                raise ORSetError("malformed add entry")
            self.adds.setdefault(tag, elem)
        self.tombstones |= other.tombstones
        # Keep counter ahead of any seen tag from this node.
        for tag in other.adds:
            if tag[0] == self.node_id and tag[1] > self._counter:
                self._counter = tag[1]


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for x in node.names:
                if x.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    a, b = ORSet("n1"), ORSet("n2")
    a.add("x"); b.add("y")
    a.merge(b); b.merge(a)
    assert a.elements() == b.elements() == {"x", "y"}
    # Remove wins over observed adds.
    a.remove("x")
    a.merge(b); b.merge(a)
    assert "x" not in a.elements() and "x" not in b.elements()
    # Concurrent add + remove -> add wins.
    c, d = ORSet("n1"), ORSet("n2")
    c.add("z")
    d.remove("z")  # d never saw the add: removes nothing
    c.merge(d); d.merge(c)
    assert "z" in c.elements()
    # Empty element -> fail-closed.
    try:
        a.add("")
        raise AssertionError("should raise")
    except ORSetError:
        pass
    assert stdlib_only()
    print("state_mgmt_26 OK: OR-set add-wins, merge, fail-closed")


if __name__ == "__main__":
    main()
