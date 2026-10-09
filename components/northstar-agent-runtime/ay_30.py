"""Utility ay_30: intersection_all."""


def intersection_all(lists):
    """Return intersection_all result."""
    r = set(lists[0]) if lists else set()
    for l in lists[1:]:
        r &= set(l)
    return sorted(r)


def _run_tests():
    assert intersection_all([[1, 2, 3], [2, 3, 4], [2, 5]]) == [2]
    assert intersection_all([]) == []


if __name__ == '__main__':
    _run_tests()
    print('OK')
