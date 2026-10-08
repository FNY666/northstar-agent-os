"""wc_20: Prefix matcher ('literal*')

IS: 'prefix*' equals text.startswith(prefix); fail-closed on other wildcards.
IS NOT: general glob or suffix matching.
"""
import ast
import sys
WC_20_VERSION = "wc-20.v1"

def match(pattern, text):
    """True when pattern is 'literal*' and text starts with the literal."""
    if not isinstance(pattern, str) or not isinstance(text, str):
        return False
    if not pattern.endswith("*") or "?" in pattern or "[" in pattern:
        return False
    return text.startswith(pattern[:-1])

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
    assert match("ab*", "abcde")
    assert not match("ab*", "xabc")
    assert match("*", "anything")
    assert not match("a?*", "abc")
    assert not match("ab", "ab")
    assert match("ab*", "ab")
    assert stdlib_only()
    print("wc_20 OK")


if __name__ == "__main__":
    main()
