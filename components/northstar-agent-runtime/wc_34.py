"""wc_34: Compiled Pattern class

IS: Pattern objects with .match() (anchored) and .search().
IS NOT: regex syntax.
"""
import ast
import sys
WC_34_VERSION = "wc-34.v1"

class Pattern:
    """A compiled '?'/'*' glob with match and search methods."""

    def __init__(self, pattern):
        if not isinstance(pattern, str):
            raise TypeError("pattern must be str")
        self.pattern = pattern

    def match(self, text):
        """True when the whole text matches."""
        if not isinstance(text, str):
            return False
        pat = self.pattern

        def rec(p, t):
            if p == len(pat):
                return t == len(text)
            if pat[p] == "*":
                return rec(p + 1, t) or (t < len(text) and rec(p, t + 1))
            return t < len(text) and (pat[p] == "?" or pat[p] == text[t]) and rec(p + 1, t + 1)

        return rec(0, 0)

    def search(self, text):
        """True when the pattern matches a substring of text."""
        if not isinstance(text, str):
            return False
        pat = self.pattern
        for i in range(len(text) + 1):
            if self._match_prefix(pat, text, i):
                return True
        return False

    @staticmethod
    def _match_prefix(pat, text, start):
        """True when pat fully matches text[start:j] for some j."""

        def rec(p, t):
            if p == len(pat):
                return True
            if t >= len(text):
                return all(ch == "*" for ch in pat[p:])
            if pat[p] == "*":
                return rec(p + 1, t) or rec(p, t + 1)
            return (pat[p] == "?" or pat[p] == text[t]) and rec(p + 1, t + 1)

        return rec(0, start)


def match(pattern, text):
    """True when the whole text matches the pattern."""
    return Pattern(pattern).match(text) if isinstance(pattern, str) else False

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
    p = Pattern("a?c")
    assert p.match("abc")
    assert not p.match("abbc")
    assert Pattern("ab").search("xabx")
    assert not Pattern("ab").search("xaxb")
    try:
        Pattern(123)
        raised = False
    except TypeError:
        raised = True
    assert raised
    assert not Pattern("a").match(123)
    assert match("a*b", "axxb")
    assert stdlib_only()
    print("wc_34 OK")


if __name__ == "__main__":
    main()
