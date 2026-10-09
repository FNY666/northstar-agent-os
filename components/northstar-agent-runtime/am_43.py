"""am_43: contains utility (stdlib only)."""

def contains(items, v):
    return v in items

def _run_tests():
    assert contains([1, 2], 2) is True, 'am_43'
    assert contains([1, 2], 9) is False, 'am_43'
    return True

if __name__ == "__main__":
    _run_tests()
    print("am_43: all tests passed")
