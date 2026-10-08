"""intv_13: My Calendar I: book without double booking (calendar_one).

Keep sorted intervals; reject when the new one overlaps any stored one.

Time complexity: O(n) per book
Space complexity: O(n) auxiliary
"""

import ast
import sys

INTV_13 = "intv-13.v1"


class CalendarOne:
    """Calendar that rejects any double booking."""
    def __init__(self):
        self.booked = []
    def book(self, start, end):
        for s, e in self.booked:
            if start < e and s < end:
                return False
        self.booked.append((start, end))
        return True


def book_sequence(seq):
    cal = CalendarOne()
    return [cal.book(s, e) for s, e in seq]

def stdlib_only() -> bool:
    """Parse this file with ``ast`` and assert every import is a used stdlib module."""
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
    assert book_sequence([(10, 20), (15, 25), (20, 30)]) == [True, False, True]
    assert book_sequence([(5, 10), (10, 15)]) == [True, True]
    assert book_sequence([(1, 5), (2, 3)]) == [True, False]
    assert book_sequence([]) == []
    assert book_sequence([(1, 2), (3, 4), (5, 6)]) == [True, True, True]
    assert stdlib_only()
    print("intv_13 OK")


if __name__ == "__main__":
    main()
