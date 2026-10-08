"""Hypercube Hamiltonian cycle verifier (HAM-020), Real."""
from __future__ import annotations
import ast

VERSION = "ham-20.v1"

def _onebit(a, b):
    x = a ^ b
    return x != 0 and x & (x - 1) == 0

def is_hypercube_ham_cycle(d, seq):
    n = 1 << d
    if len(seq) != n or len(set(seq)) != n:
        return False
    if any(v < 0 or v >= n for v in seq):
        return False
    cyc = seq + [seq[0]]
    return all(_onebit(cyc[i], cyc[i + 1]) for i in range(n))

def _gray(d):
    seq = [0]
    for i in range(d):
        seq = seq + [x | (1 << i) for x in reversed(seq)]
    return seq

def main() -> None:
    assert is_hypercube_ham_cycle(3, _gray(3)) is True
    assert is_hypercube_ham_cycle(2, [0, 1, 2, 3]) is False
    assert is_hypercube_ham_cycle(2, [0, 1, 3]) is False
    assert is_hypercube_ham_cycle(2, [0, 1, 3, 2, 0]) is False
    assert is_hypercube_ham_cycle(1, [0, 1]) is True
    assert stdlib_only()
    print('ham-20.v1 OK')
def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing", "heapq", "collections", "math", "itertools", "functools", "dataclasses", "random"}
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
