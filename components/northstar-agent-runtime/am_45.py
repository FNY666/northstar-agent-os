"""am_45: dict_get utility (stdlib only)."""

def dict_get(d, k):
    return d.get(k)

def _run_tests():
    assert dict_get({'a': 1}, 'a') == 1, 'am_45'
    assert dict_get({'a': 1}, 'z') is None, 'am_45'
    return True

if __name__ == "__main__":
    _run_tests()
    print("am_45: all tests passed")
