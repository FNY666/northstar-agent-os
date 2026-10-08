"""DS: Singly Linked List (02/50). singly linked list"""
from __future__ import annotations

import ast

#: Module version.
DS_02_VERSION = "ds-02-linked-list.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ds-02.linked-list.v1"


class _Node:
    __slots__ = ("val", "next")

    def __init__(self, val):
        self.val = val
        self.next = None


class LinkedList:
    """Singly linked list."""

    def __init__(self):
        self._head = None
        self._size = 0

    def push_front(self, value):
        node = _Node(value)
        node.next = self._head
        self._head = node
        self._size += 1

    def push_back(self, value):
        node = _Node(value)
        self._size += 1
        if self._head is None:
            self._head = node
            return
        cur = self._head
        while cur.next is not None:
            cur = cur.next
        cur.next = node

    def pop_front(self):
        if self._head is None:
            raise IndexError("empty")
        value = self._head.val
        self._head = self._head.next
        self._size -= 1
        return value

    def find(self, value):
        cur = self._head
        while cur is not None:
            if cur.val == value:
                return True
            cur = cur.next
        return False

    def to_list(self):
        out = []
        cur = self._head
        while cur is not None:
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
    ll = LinkedList()
    ll.push_back(1); ll.push_back(2); ll.push_front(0)
    assert ll.to_list() == [0, 1, 2]
    assert ll.find(1) is True
    assert ll.find(9) is False
    assert ll.pop_front() == 0
    assert len(ll) == 2
    assert stdlib_only()
    print("ds-02 OK: push_front/push_back/pop_front/find")


if __name__ == "__main__":
    main()
