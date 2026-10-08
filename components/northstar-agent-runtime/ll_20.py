"""Delete node given only the node: remove a node without the head.

With no access to the predecessor, the node's value and link are copied
over from its successor, effectively deleting the successor instead.
Runs in O(1) time. Cannot delete the tail this way -- fails closed.

What this IS: a copy-the-successor trick for deleting a middle node.
What this IS NOT: a deletion that works on the tail or on a bad reference.
"""

from __future__ import annotations

import ast

#: Module version.
LL_20_VERSION = "ll-20.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ll-20.v1"


class LlError(Exception):
    """Fail-closed."""


class Node:
    def __init__(self, val):
        self.val = val
        self.next = None


def _check_head(head):
    if head is not None and not isinstance(head, Node):
        raise LlError("head must be a Node or None")


def from_list(vals):
    """Build a list from a Python list."""
    if not isinstance(vals, (list, tuple)):
        raise LlError("vals must be a list or tuple")
    head = None
    tail = None
    for v in vals:
        node = Node(v)
        if head is None:
            head = node
        else:
            tail.next = node
        tail = node
    return head


def to_list(head):
    """Convert back to a Python list."""
    _check_head(head)
    out = []
    seen = set()
    cur = head
    while cur is not None:
        if id(cur) in seen:
            raise LlError("cycle detected; cannot linearize")
        seen.add(id(cur))
        out.append(cur.val)
        cur = cur.next
    return out


def delete_node(node):
    """Delete a non-tail node when only its reference is available."""
    if not isinstance(node, Node):
        raise LlError("node must be a Node")
    if node.next is None:
        raise LlError("cannot delete the tail node with only its reference")
    node.val = node.next.val
    node.next = node.next.next


def test_delete_middle():
    head = from_list([1, 2, 3, 4])
    node = head.next.next  # value 3
    delete_node(node)
    assert to_list(head) == [1, 2, 4]


def test_delete_head_via_reference():
    head = from_list([1, 2, 3])
    delete_node(head)
    assert to_list(head) == [2, 3]


def test_delete_second_to_last():
    head = from_list([1, 2, 3])
    delete_node(head.next)
    assert to_list(head) == [1, 3]


def test_delete_tail_raises():
    head = from_list([1, 2])
    try:
        delete_node(head.next)
    except LlError:
        pass
    else:
        raise AssertionError("expected LlError when deleting the tail")


def test_delete_singleton_raises():
    try:
        delete_node(from_list([1]))
    except LlError:
        pass
    else:
        raise AssertionError("expected LlError for a single-node list")


def test_delete_bad_input():
    for bad in (None, "nope", 42):
        try:
            delete_node(bad)
        except LlError:
            pass
        else:
            raise AssertionError(f"expected LlError for {bad!r}")


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    test_delete_middle()
    test_delete_head_via_reference()
    test_delete_second_to_last()
    test_delete_tail_raises()
    test_delete_singleton_raises()
    test_delete_bad_input()
    assert stdlib_only()
    print("ll-20 OK")


if __name__ == "__main__":
    main()
