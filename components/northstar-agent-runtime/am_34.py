"""am_34: list_max utility (stdlib only)."""

def list_max(items):
    return max(items)

def _run_tests():
    assert list_max([1, 9, 3]) == 9, 'am_34'
    assert list_max([-5, -1]) == -1, 'am_34'
    return True

if __name__ == "__main__":
    _run_tests()
    print("am_34: all tests passed")
