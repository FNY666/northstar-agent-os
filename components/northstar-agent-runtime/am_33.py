"""am_33: list_sum utility (stdlib only)."""

def list_sum(items):
    return sum(items)

def _run_tests():
    assert list_sum([1, 2, 3]) == 6, 'am_33'
    assert list_sum([]) == 0, 'am_33'
    return True

if __name__ == "__main__":
    _run_tests()
    print("am_33: all tests passed")
