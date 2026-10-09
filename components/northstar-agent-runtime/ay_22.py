"""Utility ay_22: mode_val."""


def mode_val(lst):
    """Return mode_val result."""
    from collections import Counter
    return Counter(lst).most_common(1)[0][0] if lst else None


def _run_tests():
    assert mode_val([1, 2, 2, 3]) == 2
    assert mode_val([]) is None


if __name__ == '__main__':
    _run_tests()
    print('OK')
