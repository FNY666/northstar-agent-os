"""al_05: simple utility module (stdlib only)."""

def is_even(x):
    return x % 2 == 0

def _run_tests():
    assert is_even(4) == True, 'al_05'
    assert is_even(5) == False, 'al_05'
    return True

if __name__ == "__main__":
    _run_tests()
    print("al_05: all tests passed")
