"""Utility ay_34: flatten_dict."""


def flatten_dict(d, prefix=''):
    """Return flatten_dict result."""
    r = {}
    for k, v in d.items():
        key = prefix + str(k)
        if isinstance(v, dict):
            r.update(flatten_dict(v, key + '.'))
        else:
            r[key] = v
    return r


def _run_tests():
    assert flatten_dict({'a': {'b': 1}}) == {'a.b': 1}
    assert flatten_dict({'x': 1}) == {'x': 1}


if __name__ == '__main__':
    _run_tests()
    print('OK')
