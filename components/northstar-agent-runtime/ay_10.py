"""Utility ay_10: camel_to_snake."""


def camel_to_snake(s):
    """Return camel_to_snake result."""
    return ''.join('_' + c.lower() if c.isupper() else c for c in s).lstrip('_')


def _run_tests():
    assert camel_to_snake('helloWorld') == 'hello_world'
    assert camel_to_snake('A') == 'a'


if __name__ == '__main__':
    _run_tests()
    print('OK')
