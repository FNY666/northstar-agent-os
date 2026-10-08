"""DS: Doubly Linked List (03/50). doubly linked list"""
from __future__ import annotations

import ast

#: Module version.
DS_03_VERSION = "ds-03-doubly-linked-list.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ds-03.doubly-linked-list.v1"


class _DNode:
    __slots__ = ("val", "prev", "next")

    def __init__(self, val):
        self.val = val
        self.prev = None
        self.next = None


class DoublyLinkedList:
    """Doubly linked list with head and tail pointers."""

    def __init__(self):
        self._head = None
        self._tail = None
        self._size = 0

    def push_front(self, value):
        node = _DNode(value)
        node.next = self._head
        if self._head is not None:
            self._head.prev = node
        else:
            self._tail = node
        self._head = node
        self._size += 1

    def push_back(self, value):
        node = _DNode(value)
        node.prev = self._tail
        if self._tail is not None:
            self._tail.next = node
        else:
            self._head = node
        self._tail = node
        self._size += 1

    def pop_front(self):
        if self._head is None:
            raise IndexError("empty")
        value = self._head.val
        self._head = self._head.next
        if self._head is not None:
            self._head.prev = None
        else:
            self._tail = None
        self._size -= 1
        return value

    def pop_back(self):
        if self._tail is None:
            raise IndexError("empty")
        value = self._tail.val
        self._tail = self._tail.prev
        if self._tail is not None:
            self._tail.next = None
        else:
            self._head = None
        self._size -= 1
        return value

    def to_list(self):
        out = []
        cur = self._head
        while cur is not None:
            out.append(cur.val)
            cur = cur.next
        return out

    def to_list_rev(self):
        out = []
        cur = self._tail
        while cur is not None:
            out.append(cur.val)
            cur = cur.prev
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
    dl = DoublyLinkedList()
    dl.push_back(1); dl.push_back(2); dl.push_front(0)
    assert dl.to_list() == [0, 1, 2]
    assert dl.to_list_rev() == [2, 1, 0]
    assert dl.pop_back() == 2
    assert dl.pop_front() == 0
    assert len(dl) == 1
    assert stdlib_only()
    print("ds-03 OK: push/pop both ends, reverse walk")


if __name__ == "__main__":
    main()
