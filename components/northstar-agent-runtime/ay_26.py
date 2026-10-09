"""Utility ay_26: zip_longest_fill."""


def zip_longest_fill(a, b, fill=None):
    """Return zip_longest_fill result."""
    n = max(len(a), len(b)); return [(a[i] if i < len(a) else fill, b[i] if i < len(b) else fill) for i in range(n)]


def _run_tests():
    assert zip_longest_fill([1,2],[3]) == [(1,3),(2,None)]
    assert zip_longest_fill([],[]) == []


if __name__ == '__main__':
    _run_tests()
    print('OK')
