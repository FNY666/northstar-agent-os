"""Utility ay_27: group_by_key."""


def group_by_key(lst, key):
    """Return group_by_key result."""
    d = {}
    for x in lst:
        d.setdefault(key(x), []).append(x)
    return d


def _run_tests():
    assert group_by_key([1, 2, 3, 4], lambda x: x % 2) == {1: [1, 3], 0: [2, 4]}
    assert group_by_key([], str) == {}


if __name__ == '__main__':
    _run_tests()
    print('OK')
