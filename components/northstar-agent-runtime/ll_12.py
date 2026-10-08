"""Add two numbers: sum digits stored in reverse order.

Each list holds one number least-significant digit first; a single pass
adds column by column with carry, emitting fresh digit nodes.
Runs in O(max(n, m)) time with O(max(n, m)) new nodes.

What this IS: a digit-wise adder returning a new reversed-digit list.
What this IS NOT: a converter that parses the numbers into Python ints.
"""

from __future__ import annotations

import ast

#: Module version.
LL_12_VERSION = "ll-12.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.ll-12.v1"


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


def _check_digits(h, name):
    cur = h
    while cur is not None:
        v = cur.val
        if isinstance(v, bool) or not isinstance(v, int) or v < 0 or v > 9:
            raise LlError(f"{name} must hold single digits 0-9")
        cur = cur.next


def add_two_numbers(a, b):
    """Add two reversed-digit numbers; return the sum as a new list."""
    _check_head(a)
    _check_head(b)
    _check_digits(a, "a")
    _check_digits(b, "b")
    dummy = Node(0)
    tail = dummy
    carry = 0
    while a is not None or b is not None or carry:
        s = carry
        if a is not None:
            s += a.val
            a = a.next
        if b is not None:
            s += b.val
            b = b.next
        carry, digit = divmod(s, 10)
        tail.next = Node(digit)
        tail = tail.next
    if dummy.next is None:
        return Node(0)
    return dummy.next


def test_add_basic():
    assert to_list(add_two_numbers(from_list([2, 4, 3]), from_list([5, 6, 4]))) == [7, 0, 8]


def test_add_carry_chain():
    assert to_list(add_two_numbers(from_list([9, 9]), from_list([1]))) == [0, 0, 1]


def test_add_edge_cases():
    assert to_list(add_two_numbers(from_list([0]), from_list([0]))) == [0]
    assert to_list(add_two_numbers(from_list([]), from_list([]))) == [0]
    assert to_list(add_two_numbers(from_list([5]), from_list([5]))) == [0, 1]
    assert to_list(add_two_numbers(from_list([1, 8]), from_list([0]))) == [1, 8]


def test_add_unequal_lengths():
    assert to_list(add_two_numbers(from_list([9, 9, 9]), from_list([1]))) == [0, 0, 0, 1]


def test_add_bad_digit():
    try:
        add_two_numbers(from_list([1, 10]), from_list([2]))
    except LlError:
        pass
    else:
        raise AssertionError("expected LlError for non-digit value")
    try:
        add_two_numbers(from_list(["a"]), from_list([2]))
    except LlError:
        pass
    else:
        raise AssertionError("expected LlError for non-digit value")


def test_add_bad_input():
    try:
        add_two_numbers(None, "nope")
    except LlError:
        pass
    else:
        raise AssertionError("expected LlError")


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
    test_add_basic()
    test_add_carry_chain()
    test_add_edge_cases()
    test_add_unequal_lengths()
    test_add_bad_digit()
    test_add_bad_input()
    assert stdlib_only()
    print("ll-12 OK")


if __name__ == "__main__":
    main()
