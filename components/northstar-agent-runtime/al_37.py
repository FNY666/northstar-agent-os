"""al_37: simple utility module (stdlib only)."""

def modulo(a, b):
    return a % b

def _run_tests():
    assert modulo(7, 3) == 1, 'al_37'
    assert modulo(10, 5) == 0, 'al_37'
    return True

if __name__ == "__main__":
    _run_tests()
    print("al_37: all tests passed")
