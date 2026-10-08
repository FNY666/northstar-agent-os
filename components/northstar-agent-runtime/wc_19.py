"""wc_19: Extglob '!(...)' (negation, whole-pattern)

IS: '!(a|b)' matches any string not exactly equal to an alternative.
IS NOT: infix negation or nested operators.
"""
import ast
import sys
WC_19_VERSION = "wc-19.v1"

def match(pattern, text):
    """True when text is not exactly one of the '!(...)' alternatives."""
    if not isinstance(pattern, str) or not isinstance(text, str):
        return False
    if not (pattern.startswith("!(") and pattern.endswith(")")):
        return False
    alts = pattern[2:-1].split("|")
    return text not in alts

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
    assert match("!(a|b)", "c")
    assert not match("!(a|b)", "a")
    assert not match("!(a|b)", "b")
    assert match("!(a|b)", "")
    assert not match("!(ab)", "ab")
    assert not match("abc", "abc")
    assert stdlib_only()
    print("wc_19 OK")


if __name__ == "__main__":
    main()
