"""Utility ay_45: mat_add."""


def mat_add(a, b):
    """Return mat_add result."""
    return [[x+y for x, y in zip(ra, rb)] for ra, rb in zip(a, b)]


def _run_tests():
    assert mat_add([[1]],[[2]]) == [[3]]
    assert mat_add([],[]) == []


if __name__ == '__main__':
    _run_tests()
    print('OK')
