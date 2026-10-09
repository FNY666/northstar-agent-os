"""au_09: Binary search in sorted list."""
def binary_search(xs, target):
    """Return index of target in sorted xs, else -1."""
    lo, hi = 0, len(xs)-1
    while lo <= hi:
        mid = (lo+hi)//2
        if xs[mid] == target:
            return mid
        lo, hi = (mid+1, hi) if xs[mid] < target else (lo, mid-1)
    return -1

def _run_tests():
    assert binary_search([1, 2, 3, 4], 3) == 2
    assert binary_search([1, 2, 3], 9) == -1

if __name__ == "__main__":
    _run_tests()
    print("au_09 OK")
