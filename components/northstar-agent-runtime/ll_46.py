"""ll-46: Merge two lists alternating by node (in-place splice).

Weaves the nodes of the second list into the first by rewiring pointers.
No new nodes are allocated; when one list runs out, the rest of the other is kept.

What this IS: an in-place node-level splice alternating a, b, a, b, ...
What this IS NOT: a copy-based zip merge (see ll-28) or a sorted merge.
"""

from __future__ import annotations

import ast
import pathlib

LL_46_VERSION = "ll-46.v1"
SCHEMA_PIN = "northstar.ll-46.v1"


class LlError(Exception):
    """Fail-closed: raised on any invalid input or invariant violation."""


class Node:
    """Singly linked-list node; the value must never be None."""

    __slots__ = ("val", "next")

    def __init__(self, val):
        if val is None:
            raise LlError("node value must not be None")
        self.val = val
        self.next = None


def from_list(values):
    """Build a singly linked list from a sequence; fail-closed on bad input."""
    if values is None:
        raise LlError("values must not be None")
    head = None
    tail = None
    for v in values:
        node = Node(v)
        if head is None:
            head = node
        else:
            tail.next = node
        tail = node
    return head


def to_list(head):
    """Materialise a linked list as a Python list; fail-closed on cycles."""
    if head is not None and not isinstance(head, Node):
        raise LlError("head must be a Node or None")
    out = []
    seen = set()
    cur = head
    while cur is not None:
        if id(cur) in seen:
            raise LlError("cycle detected while traversing")
        seen.add(id(cur))
        out.append(cur.val)
        cur = cur.next
    return out


_ALLOWED_IMPORTS = {"__future__", "ast", "pathlib"}


def stdlib_only():
    """AST check: this module may only import whitelisted stdlib modules."""
    src = pathlib.Path(__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [a.name.split(".")[0] for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            names = [(node.module or "").split(".")[0]]
        else:
            continue
        for name in names:
            if name not in _ALLOWED_IMPORTS:
                raise LlError("disallowed import: %r" % (name,))
    return True


def _require_acyclic(head, name):
    if head is not None and not isinstance(head, Node):
        raise LlError(name + " must be a Node or None")
    seen = set()
    cur = head
    while cur is not None:
        if id(cur) in seen:
            raise LlError(name + " contains a cycle")
        seen.add(id(cur))
        cur = cur.next


def splice_alternate(a, b):
    """Weave the nodes of b into a in place; return the head of the result."""
    _require_acyclic(a, "a")
    _require_acyclic(b, "b")
    if a is None:
        return b
    if b is None:
        return a
    head = a
    pa = a
    pb = b
    while pa is not None and pb is not None:
        a_next = pa.next
        b_next = pb.next
        pa.next = pb
        if a_next is None:
            pb.next = b_next
            break
        pb.next = a_next
        pa = a_next
        pb = b_next
    return head

def test_splice_equal():
    assert to_list(splice_alternate(from_list([1, 3, 5]), from_list([2, 4, 6]))) == [1, 2, 3, 4, 5, 6]


def test_splice_b_longer():
    assert to_list(splice_alternate(from_list([1, 2]), from_list([3, 4, 5, 6]))) == [1, 3, 2, 4, 5, 6]


def test_splice_a_longer():
    assert to_list(splice_alternate(from_list([1, 2, 3]), from_list([4]))) == [1, 4, 2, 3]


def test_splice_a_empty():
    assert to_list(splice_alternate(None, from_list([1, 2]))) == [1, 2]


def test_splice_b_empty():
    assert to_list(splice_alternate(from_list([1, 2]), None)) == [1, 2]


def test_splice_both_empty():
    assert to_list(splice_alternate(None, None)) == []


def test_splice_reuses_nodes():
    a = from_list([1, 3])
    b = from_list([2, 4])
    na, nb = a.next, b.next
    out = splice_alternate(a, b)
    assert to_list(out) == [1, 2, 3, 4]
    assert out.next.next is na
    assert out.next.next.next is nb

def main():
    test_splice_equal()
    test_splice_b_longer()
    test_splice_a_longer()
    test_splice_a_empty()
    test_splice_b_empty()
    test_splice_both_empty()
    test_splice_reuses_nodes()
    assert stdlib_only()
    print("ll-46 OK")


if __name__ == "__main__":
    main()
