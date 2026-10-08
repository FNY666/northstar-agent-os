"""De Bruijn sequence B(2,4) via Eulerian circuit (EULER-027), Real."""
from __future__ import annotations
import ast

VERSION = "euler-27.v1"

def debruijn_b24():
    """De Bruijn B(2,4): 16 edges, cyclic sequence length 16."""
    from itertools import product
    alpha = ["0", "1"]
    verts = ["".join(p) for p in product(alpha, repeat=3)]
    adj = {}
    for v in verts:
        for c in alpha:
            adj.setdefault(v, []).append((v + c)[1:])
    start = "000"
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


def all_4mers_present(seq):
    from itertools import product
    need = {"".join(p) for p in product("01", repeat=4)}
    cyc = seq + seq[:3]
    seen = {cyc[i:i + 4] for i in range(len(seq))}
    return need <= seen

def main() -> None:
    s = debruijn_b24()
    assert len(s) == 16 + 3
    assert all_4mers_present(s)
    assert len(set(s)) == 2
    cyc = s + s[:3]
    assert len({cyc[i:i + 4] for i in range(16)}) == 16
    assert s[:3] == "000"
    assert stdlib_only()
    print("euler-27.v1 OK")

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
