"""Utility ay_39: sliding_window."""


def sliding_window(lst, n):
    """Return sliding_window result."""
    return [lst[i:i+n] for i in range(len(lst)-n+1)] if n > 0 else []


def _run_tests():
    assert sliding_window([1,2,3,4], 2) == [[1,2],[2,3],[3,4]]
    assert sliding_window([1], 3) == []


if __name__ == '__main__':
    _run_tests()
    print('OK')
