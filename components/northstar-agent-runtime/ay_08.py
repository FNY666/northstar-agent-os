"""Utility ay_08: reverse_words."""


def reverse_words(s):
    """Return reverse_words result."""
    return ' '.join(s.split()[::-1])


def _run_tests():
    assert reverse_words('a b c') == 'c b a'
    assert reverse_words('x') == 'x'


if __name__ == '__main__':
    _run_tests()
    print('OK')
