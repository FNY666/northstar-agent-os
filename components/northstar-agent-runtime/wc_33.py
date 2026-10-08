"""wc_33: Glob with cached pattern compile

IS: lru_cache over the token tuple; classic matching afterwards.
IS NOT: a thread-safety guarantee.
"""
import ast
import sys
import functools
WC_33_VERSION = "wc-33.v1"

@functools.lru_cache(maxsize=512)
def _compile(pattern):
    return tuple(pattern)


def match(pattern, text):
    """True when the whole text matches the cached-token pattern."""
    if not isinstance(pattern, str) or not isinstance(text, str):
        return False
    toks = _compile(pattern)

    def rec(p, t):
        if p == len(toks):
            return t == len(text)
        if toks[p] == "*":
            return rec(p + 1, t) or (t < len(text) and rec(p, t + 1))
        return t < len(text) and (toks[p] == "?" or toks[p] == text[t]) and rec(p + 1, t + 1)

    return rec(0, 0)


def cache_info():
    """Expose the underlying cache statistics."""
    return _compile.cache_info()

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
    assert match("a*b", "axb")
    assert match("a*b", "ayb")
    assert cache_info().hits >= 1
    assert not match("a*b", "ba")
    assert match("?", "z")
    assert stdlib_only()
    print("wc_33 OK")


if __name__ == "__main__":
    main()
