"""ao_16: binary_search utility (stdlib only)."""

def binary_search(xs, target):
    lo, hi = 0, len(xs) - 1
    while lo <= hi:
        m = (lo + hi) // 2
        if xs[m] == target: return m
        lo, hi = (m + 1, hi) if xs[m] < target else (lo, m - 1)
    return -1


def _self_test():
    assert binary_search([1, 2, 3, 4], 3) == 2, 'binary_search([1, 2, 3, 4], 3) == 2'
    assert binary_search([1, 2, 3], 9) == -1, 'binary_search([1, 2, 3], 9) == -1'


if __name__ == "__main__":
    _self_test()
    print("ok")
