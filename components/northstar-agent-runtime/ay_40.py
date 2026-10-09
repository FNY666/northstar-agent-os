"""Utility ay_40: pairwise_sum."""


def pairwise_sum(a, b):
    """Return pairwise_sum result."""
    return [x + y for x, y in zip(a, b)]


def _run_tests():
    assert pairwise_sum([1,2],[3,4]) == [4,6]
    assert pairwise_sum([1],[9,9]) == [10]


if __name__ == '__main__':
    _run_tests()
    print('OK')
