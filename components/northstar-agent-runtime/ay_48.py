"""Utility ay_48: truncate_str."""


def truncate_str(s, n, ell='...'):
    """Return truncate_str result."""
    return s if len(s) <= n else s[:n] + ell


def _run_tests():
    assert truncate_str('hello world', 5) == 'hello...'
    assert truncate_str('hi', 5) == 'hi'


if __name__ == '__main__':
    _run_tests()
    print('OK')
