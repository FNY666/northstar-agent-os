"""wc_25: Unicode NFC-normalizing glob

IS: NFC-normalizes both sides, then classic '?'/'*' on code points.
IS NOT: grapheme-cluster matching.
"""
import ast
import sys
import unicodedata
WC_25_VERSION = "wc-25.v1"

def match(pattern, text):
    """True when the whole NFC-normalized text matches."""
    if not isinstance(pattern, str) or not isinstance(text, str):
        return False
    pat = unicodedata.normalize("NFC", pattern)
    txt = unicodedata.normalize("NFC", text)

    def rec(p, t):
        if p == len(pat):
            return t == len(txt)
        if pat[p] == "*":
            return rec(p + 1, t) or (t < len(txt) and rec(p, t + 1))
        if t < len(txt) and (pat[p] == "?" or pat[p] == txt[t]):
            return rec(p + 1, t + 1)
        return False

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
    assert match("caf\u00e9", "cafe\u0301")
    assert match("\U0001F600*", "\U0001F600\U0001F600")
    assert match("h?llo", "h\u00e9llo")
    assert not match("a", "b")
    assert match("*", "\u4e2d\u6587")
    assert stdlib_only()
    print("wc_25 OK")


if __name__ == "__main__":
    main()
