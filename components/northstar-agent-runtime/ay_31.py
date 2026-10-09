"""Utility ay_31: union_all."""


def union_all(lists):
    """Return union_all result."""
    r = set()
    for l in lists:
        r |= set(l)
    return sorted(r)


def _run_tests():
    assert union_all([[1, 2], [2, 3]]) == [1, 2, 3]
    assert union_all([]) == []


if __name__ == '__main__':
    _run_tests()
    print('OK')
