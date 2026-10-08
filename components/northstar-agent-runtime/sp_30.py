"""Bidirectional BFS (SP-030), Real."""
from __future__ import annotations
import ast

VERSION = "sp-30.v1"

from collections import deque

def bidir_bfs(n, adj, src, dst):
    if src == dst:
        return 0
    df = {src: 0}
    db = {dst: 0}
    qf = deque([src])
    qb = deque([dst])
    while qf and qb:
        u = qf.popleft()
        for v in adj[u]:
            if v not in df:
                df[v] = df[u] + 1
                qf.append(v)
                if v in db:
                    return df[v] + db[v]
        u = qb.popleft()
        for v in adj[u]:
            if v not in db:
                db[v] = db[u] + 1
                qb.append(v)
                if v in df:
                    return df[v] + db[v]
    return -1

def main() -> None:
    line = [[1], [0, 2], [1, 3], [2]]
    assert bidir_bfs(4, line, 0, 3) == 3
    assert bidir_bfs(4, line, 1, 1) == 0
    assert bidir_bfs(3, [[1], [], []], 0, 2) == -1
    star = [[1, 2, 3], [0], [0], [0]]
    assert bidir_bfs(4, star, 1, 3) == 2
    assert stdlib_only()
    print("sp-30 OK")

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
