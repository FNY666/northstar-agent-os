"""wc_44: Multi-line glob

IS: '*' never crosses '\\n'; match_lines() returns matching lines.
IS NOT: '^'/'$' anchors.
"""
import ast
import sys
WC_44_VERSION = "wc-44.v1"

def _wild(pat, line):
    def rec(p, t):
        if p == len(pat):
            return t == len(line)
        if pat[p] == "*":
            if rec(p + 1, t):
                return True
            return t < len(line) and line[t] != "\n" and rec(p, t + 1)
        return t < len(line) and (pat[p] == "?" or pat[p] == line[t]) and rec(p + 1, t + 1)
    return rec(0, 0)


def match(pattern, text):
    """True when the single line fully matches ('*' skips '\\n')."""
    if not isinstance(pattern, str) or not isinstance(text, str):
        return False
    return _wild(pattern, text)


def match_lines(pattern, text):
    """List of lines fully matched by the pattern."""
    if not isinstance(pattern, str) or not isinstance(text, str):
        return []
    return [ln for ln in text.split("\n") if _wild(pattern, ln)]

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
    assert match_lines("a*", "ab\nac\nxb") == ["ab", "ac"]
    assert not match("a*b", "a\nb")
    assert match("a*b", "axb")
    assert match_lines("*", "x\ny") == ["x", "y"]
    assert match_lines("a", 1) == []
    assert stdlib_only()
    print("wc_44 OK")


if __name__ == "__main__":
    main()
