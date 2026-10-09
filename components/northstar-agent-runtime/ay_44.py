"""Utility ay_44: transpose_m."""


def transpose_m(m):
    """Return transpose_m result."""
    return [list(r) for r in zip(*m)] if m else []


def _run_tests():
    assert transpose_m([[1,2],[3,4]]) == [[1,3],[2,4]]
    assert transpose_m([]) == []


if __name__ == '__main__':
    _run_tests()
    print('OK')
