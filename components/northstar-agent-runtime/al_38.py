"""al_38: simple utility module (stdlib only)."""

def power(a, b):
    return a ** b

def _run_tests():
    assert power(2, 10) == 1024, 'al_38'
    assert power(3, 0) == 1, 'al_38'
    return True

if __name__ == "__main__":
    _run_tests()
    print("al_38: all tests passed")
