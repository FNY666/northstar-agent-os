"""Utility ay_41: dot_product."""


def dot_product(a, b):
    """Return dot_product result."""
    return sum(x*y for x, y in zip(a, b))


def _run_tests():
    assert dot_product([1,2],[3,4]) == 11
    assert dot_product([],[]) == 0


if __name__ == '__main__':
    _run_tests()
    print('OK')
