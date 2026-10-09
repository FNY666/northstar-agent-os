"""Utility ay_35: nested_get."""


def nested_get(d, keys, default=None):
    """Return nested_get result."""
    for k in keys:
        if isinstance(d, dict):
            d = d.get(k, default)
        else:
            return default
    return d


def _run_tests():
    assert nested_get({'a': {'b': 5}}, ['a', 'b']) == 5
    assert nested_get({}, ['x'], 'd') == 'd'


if __name__ == '__main__':
    _run_tests()
    print('OK')
