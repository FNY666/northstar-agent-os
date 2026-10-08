"""wc_50: Matcher-agreement harness

IS: checks recursive/DP/greedy implementations agree on a corpus.
IS NOT: a performance benchmark.
"""
import ast
import sys
WC_50_VERSION = "wc-50.v1"

def _recursive(pattern, text):
    def rec(p, t):
        if p == len(pattern):
            return t == len(text)
        if pattern[p] == "*":
            return rec(p + 1, t) or (t < len(text) and rec(p, t + 1))
        return t < len(text) and (pattern[p] == "?" or pattern[p] == text[t]) and rec(p + 1, t + 1)
    return rec(0, 0)


def _dp(pattern, text):
    m, n = len(pattern), len(text)
    dp = [[False] * (n + 1) for _ in range(m + 1)]
    dp[0][0] = True
    for i in range(1, m + 1):
        if pattern[i - 1] == "*":
            dp[i][0] = dp[i - 1][0]
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            c = pattern[i - 1]
            if c == "*":
                dp[i][j] = dp[i - 1][j] or dp[i][j - 1]
            elif c == "?" or c == text[j - 1]:
                dp[i][j] = dp[i - 1][j - 1]
    return dp[m][n]


def _greedy(pattern, text):
    px, tx = 0, 0
    star, ss = -1, 0
    while tx < len(text):
        if px < len(pattern) and (pattern[px] == "?" or pattern[px] == text[tx]):
            px += 1
            tx += 1
        elif px < len(pattern) and pattern[px] == "*":
            star, px, ss = px, px + 1, tx
        elif star != -1:
            px, ss, tx = star + 1, ss + 1, ss + 1
        else:
            return False
    while px < len(pattern) and pattern[px] == "*":
        px += 1
    return px == len(pattern)


CORPUS = [
    ("a*b", "axxb"), ("a?b", "axb"), ("a?b", "ab"), ("*", ""),
    ("", ""), ("a*b*c", "aXbYc"), ("***", "abc"), ("a*b", "abX"),
    ("?*?", "ab"), ("a*b", "a"), ("*a*", "baab"), ("a*a*a", "aaa"),
]


def check_agreement(cases=CORPUS):
    """Cases where the three engines disagree: empty means agreement."""
    bad = []
    for pattern, text in cases:
        rs = (_recursive(pattern, text), _dp(pattern, text), _greedy(pattern, text))
        if not (rs[0] == rs[1] == rs[2]):
            bad.append((pattern, text, rs))
    return bad


def match(pattern, text):
    """Greedy engine as the canonical matcher."""
    if not isinstance(pattern, str) or not isinstance(text, str):
        return False
    return _greedy(pattern, text)

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
    assert check_agreement() == []
    assert check_agreement([("a*", "abc")]) == []
    assert match("a*b", "axxb")
    assert not match("a*b", "ba")
    assert len(CORPUS) >= 10
    assert stdlib_only()
    print("wc_50 OK")


if __name__ == "__main__":
    main()
