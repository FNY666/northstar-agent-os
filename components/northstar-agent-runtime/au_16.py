"""au_16: Rotate list left."""
def rotate_left(xs, k):
    """Rotate list left by k positions."""
    if not xs:
        return []
    k %= len(xs)
    return xs[k:] + xs[:k]

def _run_tests():
    assert rotate_left([1, 2, 3], 1) == [2, 3, 1]
    assert rotate_left([], 5) == []

if __name__ == "__main__":
    _run_tests()
    print("au_16 OK")
