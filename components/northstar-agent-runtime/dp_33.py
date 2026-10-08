"""dp-33: Decode ways.

Count ways to decode a digit string with A=1..Z=26. A '0' can only pair with a preceding 1 or 2.

Time complexity: O(n) time
Space complexity: O(1) auxiliary
"""

import ast
import sys

DP_33_VERSION = "dp-33.v1"


def decode_ways(s: str) -> int:
    """Return the number of ways to decode the digit string s."""
    if not s or s[0] == "0":
        return 0
    prev2, prev1 = 1, 1
    for i in range(1, len(s)):
        cur = 0
        if s[i] != "0":
            cur += prev1
        if s[i - 1] != "0" and int(s[i - 1:i + 1]) <= 26:
            cur += prev2
        prev2, prev1 = prev1, cur
    return prev1


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
    assert decode_ways("12") == 2
    assert decode_ways("226") == 3
    assert decode_ways("06") == 0
    assert decode_ways("10") == 1
    assert decode_ways("0") == 0
    assert decode_ways("") == 0
    assert decode_ways("27") == 1
    assert decode_ways("11106") == 2
    assert stdlib_only()
    print("dp-33 OK")


if __name__ == "__main__":
    main()
