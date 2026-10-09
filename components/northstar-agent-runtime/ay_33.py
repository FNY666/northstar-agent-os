"""Utility ay_33: dict_invert."""


def dict_invert(d):
    """Return dict_invert result."""
    return {v: k for k, v in d.items()}


def _run_tests():
    assert dict_invert({'a':1,'b':2}) == {1:'a',2:'b'}
    assert dict_invert({}) == {}


if __name__ == '__main__':
    _run_tests()
    print('OK')
