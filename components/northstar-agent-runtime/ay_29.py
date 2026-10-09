"""Utility ay_29: unique_sorted."""


def unique_sorted(lst):
    """Return unique_sorted result."""
    return sorted(set(lst))


def _run_tests():
    assert unique_sorted([3,1,3,2]) == [1,2,3]
    assert unique_sorted([]) == []


if __name__ == '__main__':
    _run_tests()
    print('OK')
