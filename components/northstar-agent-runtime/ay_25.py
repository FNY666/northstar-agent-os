"""Utility ay_25: diff_vals."""


def diff_vals(lst):
    """Return diff_vals result."""
    return [b - a for a, b in zip(lst, lst[1:])]


def _run_tests():
    assert diff_vals([1,3,6]) == [2,3]
    assert diff_vals([5]) == []


if __name__ == '__main__':
    _run_tests()
    print('OK')
