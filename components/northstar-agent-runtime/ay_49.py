"""Utility ay_49: pad_center."""


def pad_center(s, w, fill=' '):
    """Return pad_center result."""
    return s.center(w, fill)


def _run_tests():
    assert pad_center('ab', 6) == '  ab  '
    assert pad_center('abcdef', 4) == 'abcdef'


if __name__ == '__main__':
    _run_tests()
    print('OK')
