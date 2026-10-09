"""al_16: simple utility module (stdlib only)."""

def max_of_two(a, b):
    return a if a > b else b

def _run_tests():
    assert max_of_two(3, 5) == 5, 'al_16'
    assert max_of_two(7, 2) == 7, 'al_16'
    return True

if __name__ == "__main__":
    _run_tests()
    print("al_16: all tests passed")
