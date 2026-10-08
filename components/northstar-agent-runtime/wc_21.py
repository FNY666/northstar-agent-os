"""wc_21: Suffix matcher ('*literal')

IS: '*literal' equals text.endswith(literal); fail-closed on other wildcards.
IS NOT: general glob or prefix matching.
"""
import ast
import sys
WC_21_VERSION = "wc-21.v1"

def match(pattern, text):
    """True when pattern is '*literal' and text ends with the literal."""
    if not isinstance(pattern, str) or not isinstance(text, str):
        return False
    if not pattern.startswith("*") or "?" in pattern or "[" in pattern:
        return False
    return text.endswith(pattern[1:])

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
    assert match("*bc", "abc")
    assert not match("*bc", "bca")
    assert match("*", "x")
    assert not match("*b?", "ab")
    assert not match("bc", "bc")
    assert match("*c", "c")
    assert stdlib_only()
    print("wc_21 OK")


if __name__ == "__main__":
    main()
