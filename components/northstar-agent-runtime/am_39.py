"""am_39: list_unique utility (stdlib only)."""

def list_unique(items):
    return list(dict.fromkeys(items))

def _run_tests():
    assert list_unique([1, 2, 2, 3]) == [1, 2, 3], 'am_39'
    assert list_unique([]) == [], 'am_39'
    return True

if __name__ == "__main__":
    _run_tests()
    print("am_39: all tests passed")
