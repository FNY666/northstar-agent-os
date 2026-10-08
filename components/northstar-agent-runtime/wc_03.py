"""wc_03: Case-insensitive glob

IS: classic '?'/'*' matching with both sides case-folded.
IS NOT: locale-aware folding or path semantics.
"""
import ast
import sys
WC_03_VERSION = "wc-03.v1"

def match(pattern, text):
    """True when the whole text matches, ignoring ASCII case."""
    if not isinstance(pattern, str) or not isinstance(text, str):
        return False
    pat = pattern.lower()
    txt = text.lower()

    def rec(p, t):
        if p == len(pat):
            return t == len(txt)
        if pat[p] == "*":
            return rec(p + 1, t) or (t < len(txt) and rec(p, t + 1))
        if t < len(txt) and (pat[p] == "?" or pat[p] == txt[t]):
            return rec(p + 1, t + 1)
        return False

    return rec(0, 0)

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
    assert match("A*B", "axxb")
    assert match("HELLO", "hello")
    assert not match("a", "b")
    assert match("File?.TXT", "file1.txt")
    assert match("*", "MiXeD")
    assert stdlib_only()
    print("wc_03 OK")


if __name__ == "__main__":
    main()
