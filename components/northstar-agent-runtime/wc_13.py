"""wc_13: Class glob via iterative stack

IS: '[...]'/'[a-z]' classes (no negation) with explicit-stack search.
IS NOT: negated classes, escapes, or recursion.
"""
import ast
import sys
WC_13_VERSION = "wc-13.v1"

def _tokenize(pattern):
    toks = []
    i, n = 0, len(pattern)
    while i < n:
        c = pattern[i]
        if c == "*":
            toks.append(("star",))
            i += 1
        elif c == "?":
            toks.append(("any",))
            i += 1
        elif c == "[":
            j = pattern.find("]", i + 1)
            if j == -1:
                toks.append(("lit", c))
                i += 1
            else:
                body = pattern[i + 1:j]
                chars = set()
                k = 0
                while k < len(body):
                    if k + 2 < len(body) and body[k + 1] == "-":
                        for o in range(ord(body[k]), ord(body[k + 2]) + 1):
                            chars.add(chr(o))
                        k += 3
                    else:
                        chars.add(body[k])
                        k += 1
                toks.append(("class", frozenset(chars)))
                i = j + 1
        else:
            toks.append(("lit", c))
            i += 1
    return toks


def match(pattern, text):
    """True when the whole text matches, using an explicit stack."""
    if not isinstance(pattern, str) or not isinstance(text, str):
        return False
    toks = _tokenize(pattern)
    stack = [(0, 0)]
    seen = set()
    while stack:
        p, t = stack.pop()
        if (p, t) in seen:
            continue
        seen.add((p, t))
        if p == len(toks):
            if t == len(text):
                return True
            continue
        kind = toks[p][0]
        if kind == "star":
            stack.append((p + 1, t))
            if t < len(text):
                stack.append((p, t + 1))
        elif t < len(text):
            if kind == "any":
                stack.append((p + 1, t + 1))
            elif kind == "lit":
                if toks[p][1] == text[t]:
                    stack.append((p + 1, t + 1))
            elif text[t] in toks[p][1]:
                stack.append((p + 1, t + 1))
    return False

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
    assert match("a[bc]d", "abd")
    assert match("[a-z]*", "hello")
    assert not match("[a-z]", "A")
    assert match("file[0-9].txt", "file7.txt")
    assert match("a?c", "abc")
    assert not match("a[bc]d", "aed")
    assert stdlib_only()
    print("wc_13 OK")


if __name__ == "__main__":
    main()
