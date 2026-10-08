"""slide_45: Substrings of size three with distinct characters.

Fixed-size window of length 3: count positions where all three characters differ.

Time complexity: O(n) time
Space complexity: O(1) auxiliary
"""

import ast
import sys
SLIDE_45_VERSION = "slide-45.v1"


def count_good_substrings(s):
    """Count substrings of length 3 with all distinct characters."""
    count = 0
    for i in range(len(s) - 2):
        if len({s[i], s[i + 1], s[i + 2]}) == 3:
            count += 1
    return count

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
    assert count_good_substrings("xyzzaz") == 1
    assert count_good_substrings("aababcabc") == 4
    assert count_good_substrings("abc") == 1
    assert count_good_substrings("aaa") == 0
    assert count_good_substrings("ab") == 0
    assert stdlib_only()
    print("slide_45 OK")


if __name__ == "__main__":
    main()
