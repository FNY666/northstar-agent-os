"""Utility ay_36: strip_empty."""


def strip_empty(lst):
    """Return strip_empty result."""
    return [x for x in lst if x not in (None, '', [], {})]


def _run_tests():
    assert strip_empty([1,None,'',2]) == [1,2]
    assert strip_empty([]) == []


if __name__ == '__main__':
    _run_tests()
    print('OK')
