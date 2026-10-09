"""Utility ay_32: dict_merge."""


def dict_merge(ds):
    """Return dict_merge result."""
    r = {}
    for d in ds:
        r.update(d)
    return r


def _run_tests():
    assert dict_merge([{'a': 1}, {'b': 2}]) == {'a': 1, 'b': 2}
    assert dict_merge([]) == {}


if __name__ == '__main__':
    _run_tests()
    print('OK')
