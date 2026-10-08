"""Hypercube Gray code Hamiltonian cycle (HAM-019), Real."""
from __future__ import annotations
import ast

VERSION = "ham-19.v1"

def _onebit(a, b):
    x = a ^ b
    return x != 0 and x & (x - 1) == 0

def gray_cycle(d):
    seq = [0]
    for i in range(d):
        seq = seq + [x | (1 << i) for x in reversed(seq)]
    return seq

def is_gray_ham_cycle(d, seq):
    n = 1 << d
    if len(seq) != n or len(set(seq)) != n:
        return False
    if any(v < 0 or v >= n for v in seq):
        return False
    cyc = seq + [seq[0]]
    return all(_onebit(cyc[i], cyc[i + 1]) for i in range(n))

def main() -> None:
    assert is_gray_ham_cycle(3, gray_cycle(3))
    assert is_gray_ham_cycle(1, gray_cycle(1))
    assert is_gray_ham_cycle(4, gray_cycle(4))
    assert gray_cycle(2) == [0, 1, 3, 2]
    assert not is_gray_ham_cycle(2, [0, 1, 2, 3])
    assert stdlib_only()
    print('ham-19.v1 OK')
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
