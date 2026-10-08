"""wc_35: Chunked/streaming glob

IS: matches the concatenation of an iterable of str chunks.
IS NOT: true streaming (input is joined first).
"""
import ast
import sys
WC_35_VERSION = "wc-35.v1"

def match(pattern, chunks):
    """True when the joined chunks fully match the pattern."""
    if not isinstance(pattern, str):
        return False
    parts = []
    try:
        iterator = iter(chunks)
    except TypeError:
        return False
    for ch in iterator:
        if not isinstance(ch, str):
            return False
        parts.append(ch)
    text = "".join(parts)

    def rec(p, t):
        if p == len(pattern):
            return t == len(text)
        if pattern[p] == "*":
            return rec(p + 1, t) or (t < len(text) and rec(p, t + 1))
        return t < len(text) and (pattern[p] == "?" or pattern[p] == text[t]) and rec(p + 1, t + 1)

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
    assert match("a*b", ["a", "x", "xb"])
    assert match("a?c", iter(["a", "bc"]))
    assert not match("a*b", ["a", 1])
    assert not match(123, ["a"])
    assert match("*", [])
    assert match("a*b", "axb")
    assert stdlib_only()
    print("wc_35 OK")


if __name__ == "__main__":
    main()
