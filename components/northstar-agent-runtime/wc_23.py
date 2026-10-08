"""wc_23: Ordered-segment matcher ('a*b*c')

IS: literal segments in order with prefix/suffix anchoring; no '?'.
IS NOT: single-char wildcards or classes.
"""
import ast
import sys
WC_23_VERSION = "wc-23.v1"

def match(pattern, text):
    """True when literal '*' segments appear in order (anchored as written)."""
    if not isinstance(pattern, str) or not isinstance(text, str):
        return False
    if "?" in pattern or "[" in pattern:
        return False
    if pattern == "":
        return text == ""
    parts = pattern.split("*")
    anchored_start = not pattern.startswith("*")
    anchored_end = not pattern.endswith("*")
    pos = 0
    for idx, part in enumerate(parts):
        if part == "":
            continue
        if idx == 0 and anchored_start:
            if not text.startswith(part):
                return False
            pos = len(part)
        else:
            found = text.find(part, pos)
            if found == -1:
                return False
            pos = found + len(part)
    if anchored_end and parts[-1] != "" and not text.endswith(parts[-1]):
        return False
    return True

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
    assert match("a*b*c", "aXXbYYc")
    assert match("*b*", "abc")
    assert not match("a*b", "ba")
    assert match("abc", "abc")
    assert not match("abc", "abcd")
    assert match("*", "xyz")
    assert match("", "")
    assert not match("", "a")
    assert stdlib_only()
    print("wc_23 OK")


if __name__ == "__main__":
    main()
