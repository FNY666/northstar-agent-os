"""am_35: list_min utility (stdlib only)."""

def list_min(items):
    return min(items)

def _run_tests():
    assert list_min([1, 9, 3]) == 1, 'am_35'
    assert list_min([-5, -1]) == -5, 'am_35'
    return True

if __name__ == "__main__":
    _run_tests()
    print("am_35: all tests passed")
