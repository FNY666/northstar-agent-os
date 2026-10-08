"""dac-39: Merge sort on a linked list.

Split the list with slow/fast pointers, sort halves, merge. O(n log n), O(log n) stack.
"""
import ast
import sys

DAC_39_VERSION = "dac-39.v1"

class Node:
    def __init__(self, val, nxt=None):
        self.val = val
        self.next = nxt


def from_list(vals):
    head = None
    for v in reversed(vals):
        head = Node(v, head)
    return head


def to_list(head):
    out = []
    while head:
        out.append(head.val)
        head = head.next
    return out


def _split_list(head):
    slow = head
    fast = head.next if head else None
    while fast and fast.next:
        slow = slow.next
        fast = fast.next.next
    mid = slow.next if slow else None
    if slow:
        slow.next = None
    return head, mid


def _merge_lists(l1, l2):
    dummy = Node(0)
    tail = dummy
    while l1 and l2:
        if l1.val <= l2.val:
            tail.next, l1 = l1, l1.next
        else:
            tail.next, l2 = l2, l2.next
        tail = tail.next
    tail.next = l1 or l2
    return dummy.next


def merge_sort_linked(head):
    """Merge sort on a singly linked list (divide and conquer)."""
    if not head or not head.next:
        return head
    left, right = _split_list(head)
    return _merge_lists(merge_sort_linked(left), merge_sort_linked(right))

def stdlib_only() -> bool:
    # Parse this file with ast; every import must be a used stdlib module.
    with open(__file__, encoding="utf-8") as f:
        source = f.read()
    tree = ast.parse(source)
    imported = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported[alias.asname or alias.name.split(".")[0]] = alias.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                imported[alias.asname or alias.name] = (node.module or "").split(".")[0]
    used = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            used.add(node.id)
    for alias, top in imported.items():
        assert top in sys.stdlib_module_names, "non-stdlib import: %s" % top
        assert alias in used, "imported but unused: %s" % alias
    return True


def main() -> None:
    assert to_list(merge_sort_linked(from_list([]))) == []
    assert to_list(merge_sort_linked(from_list([1]))) == [1]
    assert to_list(merge_sort_linked(from_list([4, 2, 1, 3]))) == [1, 2, 3, 4]
    assert to_list(merge_sort_linked(from_list([5, 5, 1, 5]))) == [1, 5, 5, 5]
    assert to_list(merge_sort_linked(None)) == []
    assert stdlib_only()
    print("dac-39 OK")


if __name__ == "__main__":
    main()
