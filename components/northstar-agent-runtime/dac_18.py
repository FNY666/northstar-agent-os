"""dac-18: Tower of Hanoi.

Move n-1 disks aside, move the largest, move n-1 back: 2**n - 1 moves.
"""
import ast
import sys

DAC_18_VERSION = "dac-18.v1"

def _hanoi(n, src, dst, aux, moves):
    if n == 1:
        moves.append((src, dst))
        return
    _hanoi(n - 1, src, aux, dst, moves)
    moves.append((src, dst))
    _hanoi(n - 1, aux, dst, src, moves)


def tower_of_hanoi(n):
    """Move list for the n-disk Tower of Hanoi (A -> C using B)."""
    if n < 1:
        raise ValueError("n must be >= 1")
    moves = []
    _hanoi(n, "A", "C", "B", moves)
    return moves

def stdlib_only() -> bool:
    # Parse this file with ast; every import must be a used stdlib module.
    with open(__file__, encoding="utf-8") as f:
        source = f.read()
    tree = ast.parse(source)
    imported = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported[alias.asname or alias.name.split(".")[0]] = alias.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                imported[alias.asname or alias.name] = (node.module or "").split(".")[0]
    used = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            used.add(node.id)
    for alias, top in imported.items():
        assert top in sys.stdlib_module_names, "non-stdlib import: %s" % top
        assert alias in used, "imported but unused: %s" % alias
    return True


def main() -> None:
    assert tower_of_hanoi(1) == [("A", "C")]
    assert len(tower_of_hanoi(2)) == 3
    assert len(tower_of_hanoi(4)) == 15
    assert tower_of_hanoi(2) == [("A", "B"), ("A", "C"), ("B", "C")]
    try:
        tower_of_hanoi(0)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert stdlib_only()
    print("dac-18 OK")


if __name__ == "__main__":
    main()
