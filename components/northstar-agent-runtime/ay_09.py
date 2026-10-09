"""Utility ay_09: title_case."""


def title_case(s):
    """Return title_case result."""
    return ' '.join(w[:1].upper() + w[1:].lower() for w in s.split())


def _run_tests():
    assert title_case('hello WORLD') == 'Hello World'
    assert title_case('a') == 'A'


if __name__ == '__main__':
    _run_tests()
    print('OK')
