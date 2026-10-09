"""au_44: Median of numbers."""
def median(xs):
    """Return the median value."""
    s = sorted(xs)
    n = len(s)
    if not n:
        raise ValueError('empty')
    m = n // 2
    return s[m] if n % 2 else (s[m-1] + s[m]) / 2

def _run_tests():
    assert median([1, 3, 2]) == 2
    assert median([1, 2, 3, 4]) == 2.5

if __name__ == "__main__":
    _run_tests()
    print("au_44 OK")
