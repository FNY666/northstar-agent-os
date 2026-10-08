"""wc_12: Glob via regex translation

IS: translates '?'/'*' to an anchored regex and matches with re.
IS NOT: classes or extglob.
"""
import ast
import sys
import re
WC_12_VERSION = "wc-12.v1"

def _translate(pattern):
    out = []
    for ch in pattern:
        if ch == "*":
            out.append(".*")
        elif ch == "?":
            out.append(".")
        else:
            out.append(re.escape(ch))
    return "".join(out)


def match(pattern, text):
    """True when the whole text matches the translated regex."""
    if not isinstance(pattern, str) or not isinstance(text, str):
        return False
    try:
        rx = re.compile(_translate(pattern) + "\\Z", re.DOTALL)
    except re.error:
        return False
    return rx.match(text) is not None

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
    assert match("a*b", "axxb")
    assert match("a?c", "axc")
    assert not match("a.c", "abc")
    assert match("a.c", "a.c")
    assert match("*", "a\nb")
    assert not match("a", 1)
    assert stdlib_only()
    print("wc_12 OK")


if __name__ == "__main__":
    main()
