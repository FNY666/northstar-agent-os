"""Utility ay_06: is_palindrome."""


def is_palindrome(s):
    """Return is_palindrome result."""
    t = ''.join(c.lower() for c in s if c.isalnum())
    return t == t[::-1]


def _run_tests():
    assert is_palindrome('Able was I ere I saw Elba') is True
    assert is_palindrome('hello') is False
    assert is_palindrome('') is True


if __name__ == '__main__':
    _run_tests()
    print('OK')
