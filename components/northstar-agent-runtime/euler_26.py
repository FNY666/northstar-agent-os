"""De Bruijn sequence B(2,3) via Eulerian circuit (EULER-026), Real."""
from __future__ import annotations
import ast

VERSION = "euler-26.v1"

def debruijn(k, n):
    """De Bruijn sequence for alphabet size k, order n, via Eulerian circuit."""
    from itertools import product
    alpha = [str(i) for i in range(k)]
    if n == 1:
        return "".join(alpha)
    verts = ["".join(p) for p in product(alpha, repeat=n - 1)]
    adj = {}
    for v in verts:
        for c in alpha:
            w = (v + c)[1:]
            adj.setdefault(v, []).append(w)
    start = verts[0]
    stack = [start]
    path = []
    while stack:
        u = stack[-1]
        if adj.get(u):
            stack.append(adj[u].pop())
        else:
            path.append(stack.pop())
    path.reverse()
    seq = path[0] + "".join(w[-1] for w in path[1:])
    return seq


def is_debruijn(seq, k, n):
    from itertools import product
    alpha = [str(i) for i in range(k)]
    need = {"".join(p) for p in product(alpha, repeat=n)}
    seen = {seq[i:i + n] for i in range(len(seq) - n + 1)}
    cyc = seq + seq[:n - 1]
    seen_cyc = {cyc[i:i + n] for i in range(len(seq))}
    return need <= seen or need <= seen_cyc

def main() -> None:
    s = debruijn(2, 3)
    assert len(s) == 8 + 2
    assert is_debruijn(s, 2, 3)
    s1 = debruijn(2, 1)
    assert sorted(s1) == ["0", "1"]
    s2 = debruijn(2, 2)
    assert is_debruijn(s2, 2, 2) and len(s2) == 4 + 1
    assert not is_debruijn("000111", 2, 3)
    assert stdlib_only()
    print("euler-26.v1 OK")

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
