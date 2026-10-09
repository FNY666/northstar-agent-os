"""al_12: simple utility module (stdlib only)."""

def multiply(a, b):
    return a * b

def _run_tests():
    assert multiply(3, 4) == 12, 'al_12'
    assert multiply(-2, 3) == -6, 'al_12'
    return True

if __name__ == "__main__":
    _run_tests()
    print("al_12: all tests passed")
