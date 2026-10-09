"""Utility ay_01: chunk_list."""


def chunk_list(lst, n):
    """Return chunk_list result."""
    return [lst[i:i+n] for i in range(0, len(lst), n)]


def _run_tests():
    assert chunk_list([1,2,3,4,5], 2) == [[1,2],[3,4],[5]]
    assert chunk_list([], 3) == []
    assert chunk_list([1], 1) == [[1]]


if __name__ == '__main__':
    _run_tests()
    print('OK')
