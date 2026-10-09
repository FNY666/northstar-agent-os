"""Utility ay_24: cumsum_vals."""


def cumsum_vals(lst):
    """Return cumsum_vals result."""
    r, t = [], 0
    for v in lst:
        t += v
        r.append(t)
    return r


def _run_tests():
    assert cumsum_vals([1, 2, 3]) == [1, 3, 6]
    assert cumsum_vals([]) == []


if __name__ == '__main__':
    _run_tests()
    print('OK')
