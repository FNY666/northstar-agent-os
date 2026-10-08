"""Word chain construction via Hierholzer (EULER-030), Real."""
from __future__ import annotations
import ast

VERSION = "euler-30.v1"

def build_chain(words):
    """Build a word chain using each word once. Returns list or []."""
    edges = [(w[0], w[-1], w) for w in words]
    adj = {}
    bal = {}
    for i, (u, v, w) in enumerate(edges):
        adj.setdefault(u, []).append((v, i))
        bal[u] = bal.get(u, 0) + 1
        bal[v] = bal.get(v, 0) - 1
    starts = [u for u, b in bal.items() if b == 1]
    if not ((len(starts) == 1) or all(b == 0 for b in bal.values())):
        return []
    start = starts[0] if starts else next((u for u in adj if adj[u]), None)
    if start is None:
        return []
    used = [False] * len(edges)
    stack = [start]
    epath = []
    vpath = []
    while stack:
        u = stack[-1]
        while u in adj and adj[u] and used[adj[u][-1][1]]:
            adj[u].pop()
        if u in adj and adj[u]:
            v, i = adj[u].pop()
            if used[i]:
                continue
            used[i] = True
            stack.append(v)
            epath.append(i)
        else:
            vpath.append(stack.pop())
    vpath.reverse()
    if not all(used):
        return []
    # recover edge order: edges were taken in DFS pre-order; rebuild via vertices
    emap = {}
    for i, (u, v, w) in enumerate(edges):
        emap.setdefault((u, v), []).append((i, w))
    out = []
    for a, b in zip(vpath, vpath[1:]):
        i, w = emap[(a, b)].pop(0)
        out.append(w)
    return out


def _valid_chain(words, chain):
    if sorted(chain) != sorted(words):
        return False
    return all(a[-1] == b[0] for a, b in zip(chain, chain[1:]))

def main() -> None:
    words = ["ab", "bc", "cd"]
    c = build_chain(words)
    assert _valid_chain(words, c)
    words2 = ["ab", "bc", "ca"]
    assert _valid_chain(words2, build_chain(words2))
    assert build_chain(["ab", "cd"]) == []
    assert build_chain([]) == []
    words3 = ["abc", "cde", "efg", "gha"]
    assert _valid_chain(words3, build_chain(words3))
    assert stdlib_only()
    print("euler-30.v1 OK")

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
