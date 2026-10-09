"""Utility ay_11: snake_to_camel."""


def snake_to_camel(s):
    """Return snake_to_camel result."""
    parts = s.split('_'); return parts[0] + ''.join(p.capitalize() for p in parts[1:])


def _run_tests():
    assert snake_to_camel('hello_world') == 'helloWorld'
    assert snake_to_camel('x') == 'x'


if __name__ == '__main__':
    _run_tests()
    print('OK')
