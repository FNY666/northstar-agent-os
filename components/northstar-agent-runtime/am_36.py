"""am_36: list_len utility (stdlib only)."""

def list_len(items):
    return len(items)

def _run_tests():
    assert list_len([1, 2]) == 2, 'am_36'
    assert list_len([]) == 0, 'am_36'
    return True

if __name__ == "__main__":
    _run_tests()
    print("am_36: all tests passed")
