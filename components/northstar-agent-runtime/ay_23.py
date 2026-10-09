"""Utility ay_23: range_vals."""


def range_vals(lst):
    """Return range_vals result."""
    return max(lst) - min(lst) if lst else 0


def _run_tests():
    assert range_vals([1,5,3]) == 4
    assert range_vals([]) == 0


if __name__ == '__main__':
    _run_tests()
    print('OK')
