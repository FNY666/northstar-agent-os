"""wc_14: Glob with brace expansion

IS: '{a,b}' alternatives expanded before classic '?'/'*' matching.
IS NOT: nested extglob operators or character classes.
"""
import ast
import sys
WC_14_VERSION = "wc-14.v1"

def _expand(pattern):
    i = pattern.find("{")
    if i == -1:
        return [pattern]
    depth = 0
    for j in range(i, len(pattern)):
        if pattern[j] == "{":
            depth += 1
        elif pattern[j] == "}":
            depth -= 1
            if depth == 0:
                break
    else:
        return [pattern]
    body = pattern[i + 1:j]
    parts, depth, cur = [], 0, []
    for ch in body:
        if ch == "{":
            depth += 1
            cur.append(ch)
        elif ch == "}":
            depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur))
    out = []
    for part in parts:
        out.extend(_expand(pattern[:i] + part + pattern[j + 1:]))
    return out


def _wild(pat, text):
    def rec(p, t):
        if p == len(pat):
            return t == len(text)
        if pat[p] == "*":
            return rec(p + 1, t) or (t < len(text) and rec(p, t + 1))
        return t < len(text) and (pat[p] == "?" or pat[p] == text[t]) and rec(p + 1, t + 1)
    return rec(0, 0)


def match(pattern, text):
    """True when the whole text matches any brace expansion."""
    if not isinstance(pattern, str) or not isinstance(text, str):
        return False
    return any(_wild(p, text) for p in _expand(pattern))

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
    assert match("a{b,c}d", "abd")
    assert match("a{b,c}d", "acd")
    assert not match("a{b,c}d", "aed")
    assert match("*.{py,txt}", "x.txt")
    assert match("{a,b}{c,d}", "bd")
    assert not match("{a,b}", "c")
    assert stdlib_only()
    print("wc_14 OK")


if __name__ == "__main__":
    main()
