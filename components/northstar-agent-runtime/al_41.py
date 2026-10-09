"""al_41: simple utility module (stdlib only)."""

def sum_three(a, b, c):
    return a + b + c

def _run_tests():
    assert sum_three(1, 2, 3) == 6, 'al_41'
    assert sum_three(0, 0, 0) == 0, 'al_41'
    return True

if __name__ == "__main__":
    _run_tests()
    print("al_41: all tests passed")
