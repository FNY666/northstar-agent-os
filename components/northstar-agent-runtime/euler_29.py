"""Word chain existence via Eulerian trail (EULER-029), Real."""
from __future__ import annotations
import ast

VERSION = "euler-29.v1"

def can_chain(words):
    """True iff words can be chained last->first letter (Eulerian trail)."""
    if not words:
        return True
    bal = {}
    adj = {}
    for w in words:
        u, v = w[0], w[-1]
        bal[u] = bal.get(u, 0) + 1
        bal[v] = bal.get(v, 0) - 1
        adj.setdefault(u, []).append(v)
        adj.setdefault(v, []).append(u)
    vals = sorted(bal.values())
    ok = all(x == 0 for x in vals) or (
        vals.count(1) == 1 and vals.count(-1) == 1
        and all(x in (-1, 0, 1) for x in vals))
    if not ok:
        return False
    start = next(iter(adj))
    seen = {start}
    stack = [start]
    while stack:
        u = stack.pop()
        for w in adj[u]:
            if w not in seen:
                seen.add(w)
                stack.append(w)
    return all(u in seen for u in bal)

def main() -> None:
    assert can_chain(["ab", "bc", "cd"])
    assert can_chain(["ab", "bc", "ca"])
    assert not can_chain(["ab", "cd"])
    assert can_chain([])
    assert can_chain(["aa"])
    assert not can_chain(["ab", "bc", "bd"])
    assert stdlib_only()
    print("euler-29.v1 OK")

def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing", "heapq", "collections", "math", "itertools", "functools", "dataclasses"}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(n, ast.ImportFrom):
            if n.module and n.module.split(".")[0] not in allowed:
                return False
    return True


if __name__ == "__main__":
    main()
