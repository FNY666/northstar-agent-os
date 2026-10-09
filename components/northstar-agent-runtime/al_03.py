"""al_03: simple utility module (stdlib only)."""

def square(x):
    return x ** 2

def _run_tests():
    assert square(5) == 25, 'al_03'
    assert square(-3) == 9, 'al_03'
    return True

if __name__ == "__main__":
    _run_tests()
    print("al_03: all tests passed")
