"""Utility ay_38: partition_by."""


def partition_by(lst, pred):
    """Return partition_by result."""
    t, f = [], []
    for x in lst:
        (t if pred(x) else f).append(x)
    return t, f


def _run_tests():
    assert partition_by([1, 2, 3, 4], lambda x: x % 2 == 0) == ([2, 4], [1, 3])
    assert partition_by([], bool) == ([], [])


if __name__ == '__main__':
    _run_tests()
    print('OK')
