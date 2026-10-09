"""Utility ay_42: norm_l2."""


def norm_l2(v):
    """Return norm_l2 result."""
    return sum(x*x for x in v) ** 0.5


def _run_tests():
    assert norm_l2([3,4]) == 5.0
    assert norm_l2([]) == 0.0


if __name__ == '__main__':
    _run_tests()
    print('OK')
