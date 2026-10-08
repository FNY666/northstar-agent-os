"""dac-09: Strassen matrix multiplication.

Seven half-size products instead of eight: O(n^2.81). n must be a power of two.
"""
import ast
import sys

DAC_09_VERSION = "dac-09.v1"

def _add(A, B):
    return [[x + y for x, y in zip(r1, r2)] for r1, r2 in zip(A, B)]


def _sub(A, B):
    return [[x - y for x, y in zip(r1, r2)] for r1, r2 in zip(A, B)]


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


def strassen(A, B):
    """Strassen multiplication; n must be a power of two."""
    n = len(A)
    if n == 1:
        return [[A[0][0] * B[0][0]]]
    A11, A12, A21, A22 = _split(A)
    B11, B12, B21, B22 = _split(B)
    M1 = strassen(_add(A11, A22), _add(B11, B22))
    M2 = strassen(_add(A21, A22), B11)
    M3 = strassen(A11, _sub(B12, B22))
    M4 = strassen(A22, _sub(B21, B11))
    M5 = strassen(_add(A11, A12), B22)
    M6 = strassen(_sub(A21, A11), _add(B11, B12))
    M7 = strassen(_sub(A12, A22), _add(B21, B22))
    C11 = _add(_sub(_add(M1, M4), M5), M7)
    C12 = _add(M3, M5)
    C21 = _add(M2, M4)
    C22 = _add(_sub(_add(M1, M3), M2), M6)
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
    assert strassen([[2]], [[3]]) == [[6]]
    A = [[1, 2], [3, 4]]
    B = [[5, 6], [7, 8]]
    assert strassen(A, B) == matmul_naive(A, B) == [[19, 22], [43, 50]]
    C = [[i * 4 + j for j in range(4)] for i in range(4)]
    D = [[(i + j) % 5 for j in range(4)] for i in range(4)]
    assert strassen(C, D) == matmul_naive(C, D)
    assert stdlib_only()
    print("dac-09 OK")


if __name__ == "__main__":
    main()
