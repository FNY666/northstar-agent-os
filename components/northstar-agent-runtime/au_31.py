"""au_31: Transpose a matrix."""
def transpose(m):
    """Transpose a rectangular matrix (list of lists)."""
    return [list(r) for r in zip(*m)]

def _run_tests():
    assert transpose([[1, 2], [3, 4]]) == [[1, 3], [2, 4]]
    assert transpose([]) == []

if __name__ == "__main__":
    _run_tests()
    print("au_31 OK")
