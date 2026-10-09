"""Utility ay_46: count_vowels."""


def count_vowels(s):
    """Return count_vowels result."""
    return sum(1 for c in s.lower() if c in 'aeiou')


def _run_tests():
    assert count_vowels('Hello') == 2
    assert count_vowels('xyz') == 0


if __name__ == '__main__':
    _run_tests()
    print('OK')
