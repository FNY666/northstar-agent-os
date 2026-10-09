"""Utility ay_07: word_count."""


def word_count(s):
    """Return word_count result."""
    return len(s.split())


def _run_tests():
    assert word_count('hello world') == 2
    assert word_count('  ') == 0


if __name__ == '__main__':
    _run_tests()
    print('OK')
