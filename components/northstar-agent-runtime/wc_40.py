"""wc_40: Star-capture glob

IS: capture() returns the substring each '*' matched (shortest-first).
IS NOT: named or numbered regex groups.
"""
import ast
import sys
WC_40_VERSION = "wc-40.v1"

def capture(pattern, text):
    """Tuple of '*' captures, or None when there is no full match."""
    if not isinstance(pattern, str) or not isinstance(text, str):
        return None
    found = []

    def rec(p, t, cur):
        if p == len(pattern):
            if t == len(text):
                found.append(tuple(cur))
                return True
            return False
        if pattern[p] == "*":
            for end in range(t, len(text) + 1):
                if rec(p + 1, end, cur + [text[t:end]]):
                    return True
            return False
        if t < len(text) and (pattern[p] == "?" or pattern[p] == text[t]):
            return rec(p + 1, t + 1, cur)
        return False

    return found[0] if rec(0, 0, []) else None


def match(pattern, text):
    """True when the pattern fully matches."""
    return capture(pattern, text) is not None

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
    assert capture("a*b*c", "aXYbZc") == ("XY", "Z")
    assert capture("*@*", "u@h") == ("u", "h")
    assert capture("a*b", "ac") is None
    assert capture("a*b", 1) is None
    assert match("a*b", "axxb")
    assert capture("*", "hey") == ("hey",)
    assert stdlib_only()
    print("wc_40 OK")


if __name__ == "__main__":
    main()
