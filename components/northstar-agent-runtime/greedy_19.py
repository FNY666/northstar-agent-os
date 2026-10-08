"""greedy_19: Remove K digits.

Monotone stack: pop larger previous digits while removals remain, then strip leading zeros.

Time complexity: O(n) time
Space complexity: O(n) auxiliary
"""

import ast
import sys
GREEDY_19_VERSION = "greedy-19.v1"


def remove_k_digits(num, k):
    """Return the smallest possible number after removing k digits."""
    stack = []
    for d in num:
        while k and stack and stack[-1] > d:
            stack.pop()
            k -= 1
        stack.append(d)
    if k:
        stack = stack[:len(stack) - k]
    return "".join(stack).lstrip("0") or "0"

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
    assert remove_k_digits("1432219", 3) == "1219"
    assert remove_k_digits("10200", 1) == "200"
    assert remove_k_digits("10", 2) == "0"
    assert remove_k_digits("112", 1) == "11"
    assert stdlib_only()
    print("greedy_19 OK")


if __name__ == "__main__":
    main()
