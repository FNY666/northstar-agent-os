"""wc_47: Extension matcher ('*.ext')

IS: '*.ext' matches slash-free names ending in '.ext' (non-empty stem).
IS NOT: general glob.
"""
import ast
import sys
WC_47_VERSION = "wc-47.v1"

def match(pattern, text):
    """True for '*.ext' against a bare filename with that extension."""
    if not isinstance(pattern, str) or not isinstance(text, str):
        return False
    if "/" in text or "/" in pattern:
        return False
    if not pattern.startswith("*."):
        return False
    ext = pattern[1:]
    return text.endswith(ext) and len(text) > len(ext)

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
    assert match("*.py", "x.py")
    assert not match("*.py", ".py")
    assert not match("*.py", "x.pyc")
    assert not match("*.py", "d/x.py")
    assert match("*.tar.gz", "a.tar.gz")
    assert not match("*.py", "*.pyy")
    assert stdlib_only()
    print("wc_47 OK")


if __name__ == "__main__":
    main()
