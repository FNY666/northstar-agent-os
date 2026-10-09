"""Utility ay_47: initials_of."""


def initials_of(name):
    """Return initials_of result."""
    return ''.join(w[0].upper() for w in name.split() if w)


def _run_tests():
    assert initials_of('John Doe') == 'JD'
    assert initials_of('') == ''


if __name__ == '__main__':
    _run_tests()
    print('OK')
