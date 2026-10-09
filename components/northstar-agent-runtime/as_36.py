"""binary_search utility."""

def binary_search(xs, x):
    lo, hi = 0, len(xs) - 1
    while lo <= hi:
        m = (lo + hi) // 2
        if xs[m] == x:
            return m
        lo, hi = (m + 1, hi) if xs[m] < x else (lo, m - 1)
    return -1


def _selftest():
    assert binary_search([1, 2, 3], 2) == 1
    assert binary_search([1, 2, 3], 9) == -1


if __name__ == "__main__":
    _selftest()
    print("ok")
