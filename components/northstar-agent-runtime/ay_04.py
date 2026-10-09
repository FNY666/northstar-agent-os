"""Utility ay_04: rotate_left."""


def rotate_left(lst, k):
    """Return rotate_left result."""
    k %= len(lst) if lst else 1; return lst[k:] + lst[:k]


def _run_tests():
    assert rotate_left([1,2,3,4], 1) == [2,3,4,1]
    assert rotate_left([1,2], 2) == [1,2]


if __name__ == '__main__':
    _run_tests()
    print('OK')
