"""Utility ay_28: top_k."""


def top_k(lst, k):
    """Return top_k result."""
    return sorted(lst, reverse=True)[:k]


def _run_tests():
    assert top_k([3,1,4,2], 2) == [4,3]
    assert top_k([1], 5) == [1]


if __name__ == '__main__':
    _run_tests()
    print('OK')
