"""am_37: list_reverse utility (stdlib only)."""

def list_reverse(items):
    return items[::-1]

def _run_tests():
    assert list_reverse([1, 2, 3]) == [3, 2, 1], 'am_37'
    assert list_reverse([]) == [], 'am_37'
    return True

if __name__ == "__main__":
    _run_tests()
    print("am_37: all tests passed")
