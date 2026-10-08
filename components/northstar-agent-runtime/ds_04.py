"""DS: Circular Linked List (04/50). circular singly linked list"""
from __future__ import annotations

import ast

#: Module version.
DS_04_VERSION = "ds-04-circular-list.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ds-04.circular-list.v1"


class _CNode:
    __slots__ = ("val", "next")

    def __init__(self, val):
        self.val = val
        self.next = None


class CircularList:
    """Circular singly linked list; tail links back to head."""

    def __init__(self):
        self._head = None
        self._size = 0

    def append(self, value):
        node = _CNode(value)
        if self._head is None:
            node.next = node
            self._head = node
        else:
            tail = self._head
            while tail.next is not self._head:
                tail = tail.next
            tail.next = node
            node.next = self._head
        self._size += 1

    def remove(self, value):
        if self._head is None:
            raise ValueError("empty")
        cur = self._head
        prev = None
        for _ in range(self._size):
            if cur.val == value:
                if self._size == 1:
                    self._head = None
                elif prev is None:
                    tail = self._head
                    while tail.next is not self._head:
                        tail = tail.next
                    self._head = cur.next
                    tail.next = self._head
                else:
                    prev.next = cur.next
                self._size -= 1
                return True
            prev = cur
            cur = cur.next
        return False

    def iterate(self, steps):
        """Walk ``steps`` nodes starting at head (wraps around)."""
        out = []
        cur = self._head
        for _ in range(steps):
            if cur is None:
                break
            out.append(cur.val)
            cur = cur.next
        return out

    def __len__(self):
        return self._size

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    """Self-check."""
    cl = CircularList()
    cl.append(1); cl.append(2); cl.append(3)
    assert cl.iterate(5) == [1, 2, 3, 1, 2]
    assert cl.remove(1) is True
    assert cl.iterate(4) == [2, 3, 2, 3]
    assert cl.remove(9) is False
    assert len(cl) == 2
    assert stdlib_only()
    print("ds-04 OK: wrap-around iteration, head removal")


if __name__ == "__main__":
    main()
