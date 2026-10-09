"""am_46: dict_keys utility (stdlib only)."""

def dict_keys(d):
    return sorted(d.keys())

def _run_tests():
    assert dict_keys({'b': 1, 'a': 2}) == ['a', 'b'], 'am_46'
    assert dict_keys({}) == [], 'am_46'
    return True

if __name__ == "__main__":
    _run_tests()
    print("am_46: all tests passed")
