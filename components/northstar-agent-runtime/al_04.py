"""al_04: simple utility module (stdlib only)."""

def cube(x):
    return x ** 3

def _run_tests():
    assert cube(3) == 27, 'al_04'
    assert cube(-2) == -8, 'al_04'
    return True

if __name__ == "__main__":
    _run_tests()
    print("al_04: all tests passed")
