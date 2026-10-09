"""al_10: simple utility module (stdlib only)."""

def add(a, b):
    return a + b

def _run_tests():
    assert add(2, 3) == 5, 'al_10'
    assert add(-1, 1) == 0, 'al_10'
    return True

if __name__ == "__main__":
    _run_tests()
    print("al_10: all tests passed")
