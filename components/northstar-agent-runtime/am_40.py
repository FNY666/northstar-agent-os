"""am_40: list_head utility (stdlib only)."""

def list_head(items):
    return items[0] if items else None

def _run_tests():
    assert list_head([1, 2]) == 1, 'am_40'
    assert list_head([]) is None, 'am_40'
    return True

if __name__ == "__main__":
    _run_tests()
    print("am_40: all tests passed")
