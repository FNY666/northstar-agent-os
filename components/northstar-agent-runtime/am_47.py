"""am_47: dict_merge utility (stdlib only)."""

def dict_merge(a, b):
    r = dict(a)
    r.update(b)
    return r

def _run_tests():
    assert dict_merge({'a': 1}, {'b': 2}) == {'a': 1, 'b': 2}, 'am_47'
    assert dict_merge({}, {}) == {}, 'am_47'
    return True

if __name__ == "__main__":
    _run_tests()
    print("am_47: all tests passed")
