"""al_11: simple utility module (stdlib only)."""

def subtract(a, b):
    return a - b

def _run_tests():
    assert subtract(5, 3) == 2, 'al_11'
    assert subtract(1, 5) == -4, 'al_11'
    return True

if __name__ == "__main__":
    _run_tests()
    print("al_11: all tests passed")
