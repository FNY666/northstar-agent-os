"""am_04: cube utility (stdlib only)."""

def cube(x):
    return x ** 3

def _run_tests():
    assert cube(2) == 8, 'am_04'
    assert cube(-2) == -8, 'am_04'
    return True

if __name__ == "__main__":
    _run_tests()
    print("am_04: all tests passed")
