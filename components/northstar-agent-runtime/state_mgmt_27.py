"""State 27: 2P-set (two-phase set) CRDT.

Grow-only adds + grow-only tombstones:
- add(elem): inserts into the add-set (idempotent)
- remove(elem): inserts into the remove-set (tombstone); only takes
  effect if the element was added
- lookup(elem): in adds and not in removes
- merge(other): union of both sets

An element removed can NEVER be re-added (tombstone is permanent).
Simpler than OR-set, but no re-add.

Fail-closed: empty elements, non-set merge argument raise.
"""

from __future__ import annotations

import ast
from typing import Set


MODULE_VERSION = "state-mgmt-27.v1"
SCHEMA_PIN = "northstar.state-mgmt-27.v1"


class TwoPSetError(Exception):
    pass


class TwoPSet:
    def __init__(self) -> None:
        self.adds: Set[str] = set()
        self.removes: Set[str] = set()

    def add(self, elem: str) -> None:
        if not isinstance(elem, str) or not elem:
            raise TwoPSetError("element must be non-empty str")
        self.adds.add(elem)

    def remove(self, elem: str) -> None:
        if not isinstance(elem, str) or not elem:
            raise TwoPSetError("element must be non-empty str")
        if elem not in self.adds:
            raise TwoPSetError(f"cannot remove never-added {elem!r}")
        self.removes.add(elem)

    def __contains__(self, elem: object) -> bool:
        return elem in self.adds and elem not in self.removes

    def elements(self) -> Set[str]:
        return self.adds - self.removes

    def merge(self, other: "TwoPSet") -> None:
        if not isinstance(other, TwoPSet):
            raise TwoPSetError("merge requires a TwoPSet")
        self.adds |= other.adds
        self.removes |= other.removes


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
    a, b = TwoPSet(), TwoPSet()
    a.add("x"); a.add("y"); b.add("y"); b.add("z")
    a.remove("x")
    a.merge(b); b.merge(a)
    assert a.elements() == b.elements() == {"y", "z"}
    # Re-add after remove is impossible: tombstone wins.
    a.add("x")
    assert "x" not in a.elements()
    # Remove of never-added -> fail-closed.
    try:
        TwoPSet().remove("ghost")
        raise AssertionError("should raise")
    except TwoPSetError:
        pass
    assert stdlib_only()
    print("state_mgmt_27 OK: 2P-set tombstones, no re-add, fail-closed")


if __name__ == "__main__":
    main()
