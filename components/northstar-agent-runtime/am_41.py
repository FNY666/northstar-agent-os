"""am_41: list_tail utility (stdlib only)."""

def list_tail(items):
    return items[1:] if items else []

def _run_tests():
    assert list_tail([1, 2, 3]) == [2, 3], 'am_41'
    assert list_tail([]) == [], 'am_41'
    return True

if __name__ == "__main__":
    _run_tests()
    print("am_41: all tests passed")
