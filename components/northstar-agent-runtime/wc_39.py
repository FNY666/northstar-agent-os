"""wc_39: Find-all-spans glob

IS: non-overlapping (start, end) spans where the glob fully matches.
IS NOT: overlapping match enumeration.
"""
import ast
import sys
WC_39_VERSION = "wc-39.v1"

def _ends(pattern, text, start):
    ends = set()

    def rec(p, t):
        if p == len(pattern):
            ends.add(t)
            return
        if pattern[p] == "*":
            rec(p + 1, t)
            if t < len(text):
                rec(p, t + 1)
        elif t < len(text) and (pattern[p] == "?" or pattern[p] == text[t]):
            rec(p + 1, t + 1)

    rec(0, start)
    return ends


def find_all(pattern, text):
    """List of non-overlapping (start, end) full-match spans, greedy."""
    if not isinstance(pattern, str) or not isinstance(text, str):
        return []
    spans = []
    i, n = 0, len(text)
    while i <= n:
        ends = _ends(pattern, text, i)
        if ends:
            j = max(ends)
            spans.append((i, j))
            i = j if j > i else i + 1
        else:
            i += 1
    return spans


def match(pattern, text):
    """True when the pattern matches at least one span."""
    return bool(find_all(pattern, text))

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
    assert find_all("ab", "ab ab") == [(0, 2), (3, 5)]
    assert find_all("a*b", "aXb aYYb") == [(0, 8)]
    assert find_all("z*", "abc") == []
    assert find_all("a", 1) == []
    assert match("a*b", "xxaxxbxx".replace("xx", ""))
    assert stdlib_only()
    print("wc_39 OK")


if __name__ == "__main__":
    main()
