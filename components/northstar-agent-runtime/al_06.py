"""al_06: simple utility module (stdlib only)."""

def is_odd(x):
    return x % 2 == 1

def _run_tests():
    assert is_odd(5) == True, 'al_06'
    assert is_odd(4) == False, 'al_06'
    return True

if __name__ == "__main__":
    _run_tests()
    print("al_06: all tests passed")
