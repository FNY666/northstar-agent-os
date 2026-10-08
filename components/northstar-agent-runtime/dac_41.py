"""dac-41: Recursive block matrix multiplication.

Naive 8-product block recursion (the baseline Strassen improves on). n must be a power of two.
"""
import ast
import sys

DAC_41_VERSION = "dac-41.v1"

def _add(A, B):
    return [[x + y for x, y in zip(r1, r2)] for r1, r2 in zip(A, B)]


def _split(M):
    n = len(M)
    m = n // 2
    return ([row[:m] for row in M[:m]], [row[m:] for row in M[:m]],
            [row[:m] for row in M[m:]], [row[m:] for row in M[m:]])


def _join(C11, C12, C21, C22):
    return [r1 + r2 for r1, r2 in zip(C11, C12)] + [r1 + r2 for r1, r2 in zip(C21, C22)]


def matmul_naive(A, B):
    n = len(A)
    return [[sum(A[i][k] * B[k][j] for k in range(n)) for j in range(n)] for i in range(n)]


def matmul_recursive(A, B):
    """Naive recursive block multiplication (8 subproducts)."""
    n = len(A)
    if n == 1:
        return [[A[0][0] * B[0][0]]]
    A11, A12, A21, A22 = _split(A)
    B11, B12, B21, B22 = _split(B)
    C11 = _add(matmul_recursive(A11, B11), matmul_recursive(A12, B21))
    C12 = _add(matmul_recursive(A11, B12), matmul_recursive(A12, B22))
    C21 = _add(matmul_recursive(A21, B11), matmul_recursive(A22, B21))
    C22 = _add(matmul_recursive(A21, B12), matmul_recursive(A22, B22))
    return _join(C11, C12, C21, C22)

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
    assert matmul_recursive([[2]], [[3]]) == [[6]]
    A = [[1, 2], [3, 4]]
    B = [[5, 6], [7, 8]]
    assert matmul_recursive(A, B) == matmul_naive(A, B) == [[19, 22], [43, 50]]
    C = [[i * 4 + j + 1 for j in range(4)] for i in range(4)]
    assert matmul_recursive(C, C) == matmul_naive(C, C)
    assert stdlib_only()
    print("dac-41 OK")


if __name__ == "__main__":
    main()
