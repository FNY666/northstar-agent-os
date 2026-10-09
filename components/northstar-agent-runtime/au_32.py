"""au_32: Check sorted order."""
def is_sorted(xs):
    """True if xs is non-decreasing."""
    return all(xs[i] <= xs[i+1] for i in range(len(xs)-1))

def _run_tests():
    assert is_sorted([1, 2, 2, 3])
    assert not is_sorted([3, 1])

if __name__ == "__main__":
    _run_tests()
    print("au_32 OK")
