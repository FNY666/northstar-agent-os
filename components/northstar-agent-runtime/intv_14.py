"""intv_14: My Calendar II: book without triple booking (calendar_two).

Track single and double bookings; reject overlaps with any double.

Time complexity: O(n) per book
Space complexity: O(n) auxiliary
"""

import ast
import sys

INTV_14 = "intv-14.v1"


class CalendarTwo:
    """Calendar that rejects any triple booking."""
    def __init__(self):
        self.single = []
        self.double = []
    def book(self, start, end):
        for s, e in self.double:
            if start < e and s < end:
                return False
        for s, e in self.single:
            if start < e and s < end:
                self.double.append((max(s, start), min(e, end)))
        self.single.append((start, end))
        return True


def book_sequence2(seq):
    cal = CalendarTwo()
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
    assert book_sequence2([(10, 20), (50, 60), (10, 40), (5, 15), (5, 10), (25, 55)]) == [True, True, True, False, True, True]
    assert book_sequence2([(1, 5), (2, 6), (3, 7)]) == [True, True, False]
    assert book_sequence2([(1, 2), (3, 4)]) == [True, True]
    assert book_sequence2([]) == []
    assert book_sequence2([(1, 10), (2, 9), (3, 8), (4, 7)]) == [True, True, False, False]
    assert stdlib_only()
    print("intv_14 OK")


if __name__ == "__main__":
    main()
