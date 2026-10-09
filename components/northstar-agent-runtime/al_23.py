"""al_23: simple utility module (stdlib only)."""

def last_item(items):
    return items[-1]

def _run_tests():
    assert last_item([1, 2, 3]) == 3, 'al_23'
    assert last_item(['z']) == 'z', 'al_23'
    return True

if __name__ == "__main__":
    _run_tests()
    print("al_23: all tests passed")
