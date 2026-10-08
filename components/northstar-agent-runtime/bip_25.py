"""Single augmenting path search.

What this IS: finds one augmenting path for a given matching, fail-closed on bad input
What this IS NOT: a full matching; one augmenting step only
"""

from __future__ import annotations

import ast

#: Module version.
BIP_25_VERSION = "bip-augment-path.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bip-augment-path.v1"


class BipError(Exception):
    """Fail-closed."""



def find_augmenting_path(n_left: int, n_right: int, edges: list, match_l: dict):
    adj = [[] for _ in range(n_left)]
    for u, v in edges:
        if not (0 <= u < n_left and 0 <= v < n_right):
            raise BipError("edge out of range")
        adj[u].append(v)
    match_r = {v: u for u, v in match_l.items()}
    from collections import deque
    prev_l = {}
    prev_r = {}
    q = deque()
    for u in range(n_left):
        if u not in match_l:
            q.append(u)
            prev_l[u] = -1
    found = None
    while q and found is None:
        u = q.popleft()
        for v in adj[u]:
            if v in prev_r:
                continue
            prev_r[v] = u
            if v not in match_r:
                found = v
                break
            w = match_r[v]
            if w not in prev_l:
                prev_l[w] = v
                q.append(w)
    if found is None:
        return None
    # reconstruct
    path = []
    v = found
    while v != -1:
        u = prev_r[v]
        path.append((u, v))
        v = prev_l.get(u, -1)
        if v == -1:
            break
        v = prev_l[u]
    return path


def test_aug_trivial():
    p = find_augmenting_path(2, 2, [(0, 0), (1, 1)], {})
    assert p is not None and len(p) >= 1


def test_aug_none():
    # perfect matching already
    p = find_augmenting_path(1, 1, [(0, 0)], {0: 0})
    assert p is None


def test_aug_extends():
    p = find_augmenting_path(2, 2, [(0, 0), (0, 1), (1, 0)], {0: 0})
    assert p is not None


def test_aug_bad():
    try:
        find_augmenting_path(1, 1, [(0, 3)], {})
    except BipError:
        return
    raise AssertionError("expected BipError")



def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "collections", "heapq", "itertools", "functools", "math"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    """Self-check."""
    test_aug_trivial()
    test_aug_none()
    test_aug_extends()
    test_aug_bad()
    assert stdlib_only()
    print("bip-25 OK: augmenting path")


if __name__ == "__main__":
    main()
