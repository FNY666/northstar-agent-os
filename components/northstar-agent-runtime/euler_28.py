"""De Bruijn sequence B(3,2) via Eulerian circuit (EULER-028), Real."""
from __future__ import annotations
import ast

VERSION = "euler-28.v1"

def debruijn_b32():
    """De Bruijn B(3,2): 9 edges over alphabet {0,1,2}."""
    from itertools import product
    alpha = ["0", "1", "2"]
    adj = {a: [b for b in alpha] for a in alpha}
    start = "0"
    stack = [start]
    path = []
    while stack:
        u = stack[-1]
        if adj.get(u):
            stack.append(adj[u].pop())
        else:
            path.append(stack.pop())
    path.reverse()
    return path[0] + "".join(w[-1] for w in path[1:])


def all_2mers_present(seq):
    from itertools import product
    need = {"".join(p) for p in product("012", repeat=2)}
    cyc = seq + seq[:1]
    seen = {cyc[i:i + 2] for i in range(len(seq))}
    return need <= seen

def main() -> None:
    s = debruijn_b32()
    assert len(s) == 9 + 1
    assert all_2mers_present(s)
    assert set(s) == {"0", "1", "2"}
    cyc = s + s[:1]
    assert len({cyc[i:i + 2] for i in range(9)}) == 9
    assert s[0] == "0"
    assert stdlib_only()
    print("euler-28.v1 OK")

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
