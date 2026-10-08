"""Bipartite random model G(nl,nr,p) stats.

What this IS: expected edges and degrees of the bipartite Erdos-Renyi model, fail-closed on bad p
What this IS NOT: a sampled graph; closed-form expectations only
"""

from __future__ import annotations

import ast

#: Module version.
BIP_48_VERSION = "bip-gnp-stats.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.bip-gnp-stats.v1"


class BipError(Exception):
    """Fail-closed."""



def gnp_expected(n_left: int, n_right: int, p: float) -> tuple:
    if not (0.0 <= p <= 1.0):
        raise BipError("p out of range")
    if n_left < 0 or n_right < 0:
        raise BipError("negative size")
    exp_edges = n_left * n_right * p
    return exp_edges, n_right * p, n_left * p


def test_gnp_basic():
    e, dl, dr = gnp_expected(10, 20, 0.5)
    assert e == 100.0 and dl == 10.0 and dr == 5.0


def test_gnp_zero():
    assert gnp_expected(5, 5, 0.0) == (0.0, 0.0, 0.0)


def test_gnp_one():
    assert gnp_expected(2, 3, 1.0) == (6.0, 3.0, 2.0)


def test_gnp_bad_p():
    try:
        gnp_expected(2, 2, 1.5)
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
    test_gnp_basic()
    test_gnp_zero()
    test_gnp_one()
    test_gnp_bad_p()
    assert stdlib_only()
    print("bip-48 OK: G(nl,nr,p) stats")


if __name__ == "__main__":
    main()
