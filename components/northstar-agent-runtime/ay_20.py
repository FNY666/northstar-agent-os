"""Utility ay_20: mean_vals."""


def mean_vals(lst):
    """Return mean_vals result."""
    return sum(lst) / len(lst) if lst else 0.0


def _run_tests():
    assert mean_vals([1,2,3]) == 2.0
    assert mean_vals([]) == 0.0


if __name__ == '__main__':
    _run_tests()
    print('OK')
