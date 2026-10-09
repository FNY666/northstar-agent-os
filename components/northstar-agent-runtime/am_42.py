"""am_42: list_last utility (stdlib only)."""

def list_last(items):
    return items[-1] if items else None

def _run_tests():
    assert list_last([1, 2, 3]) == 3, 'am_42'
    assert list_last([]) is None, 'am_42'
    return True

if __name__ == "__main__":
    _run_tests()
    print("am_42: all tests passed")
