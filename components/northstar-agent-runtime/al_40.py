"""al_40: simple utility module (stdlib only)."""

def average_two(a, b):
    return (a + b) / 2

def _run_tests():
    assert average_two(2, 4) == 3.0, 'al_40'
    assert average_two(1, 2) == 1.5, 'al_40'
    return True

if __name__ == "__main__":
    _run_tests()
    print("al_40: all tests passed")
