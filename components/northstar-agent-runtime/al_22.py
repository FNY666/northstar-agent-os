"""al_22: simple utility module (stdlib only)."""

def first_item(items):
    return items[0]

def _run_tests():
    assert first_item([1, 2, 3]) == 1, 'al_22'
    assert first_item(['a']) == 'a', 'al_22'
    return True

if __name__ == "__main__":
    _run_tests()
    print("al_22: all tests passed")
