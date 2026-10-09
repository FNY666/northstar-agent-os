"""am_38: list_sorted utility (stdlib only)."""

def list_sorted(items):
    return sorted(items)

def _run_tests():
    assert list_sorted([3, 1, 2]) == [1, 2, 3], 'am_38'
    assert list_sorted([]) == [], 'am_38'
    return True

if __name__ == "__main__":
    _run_tests()
    print("am_38: all tests passed")
