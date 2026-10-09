"""Utility ay_02: flatten_once."""


def flatten_once(lst):
    """Return flatten_once result."""
    return [x for sub in lst for x in (sub if isinstance(sub, (list, tuple)) else [sub])]


def _run_tests():
    assert flatten_once([[1,2],[3],[4,5]]) == [1,2,3,4,5]
    assert flatten_once([1,2]) == [1,2]


if __name__ == '__main__':
    _run_tests()
    print('OK')
