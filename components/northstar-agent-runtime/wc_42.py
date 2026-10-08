"""wc_42: Fuzzy glob (k mismatches)

IS: literal mismatches cost 1 up to max_errors; '?'/'*' unchanged.
IS NOT: insertions/deletions (substitutions only).
"""
import ast
import sys
WC_42_VERSION = "wc-42.v1"

def match_fuzzy(pattern, text, max_errors=1):
    """True when the whole text matches with <= max_errors substitutions."""
    if not isinstance(pattern, str) or not isinstance(text, str):
        return False
    if not isinstance(max_errors, int) or max_errors < 0:
        return False

    def rec(p, t, e):
        if e > max_errors:
            return False
        if p == len(pattern):
            return t == len(text)
        if pattern[p] == "*":
            return rec(p + 1, t, e) or (t < len(text) and rec(p, t + 1, e))
        if t < len(text):
            if pattern[p] == "?":
                return rec(p + 1, t + 1, e)
            if pattern[p] == text[t]:
                return rec(p + 1, t + 1, e)
            return rec(p + 1, t + 1, e + 1)
        return False

    return rec(0, 0, 0)


def match(pattern, text):
    """Exact variant: zero mismatches allowed."""
    return match_fuzzy(pattern, text, 0)

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
    assert match("abc", "abc")
    assert not match("abc", "abd")
    assert match_fuzzy("abc", "abd", 1)
    assert not match_fuzzy("abc", "xyz", 1)
    assert match_fuzzy("a*c", "axyc", 0)
    assert not match_fuzzy("abc", "abc", -1)
    assert stdlib_only()
    print("wc_42 OK")


if __name__ == "__main__":
    main()
