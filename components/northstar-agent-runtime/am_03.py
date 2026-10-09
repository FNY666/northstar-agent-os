"""am_03: square utility (stdlib only)."""

def square(x):
    return x * x

def _run_tests():
    assert square(4) == 16, 'am_03'
    assert square(-3) == 9, 'am_03'
    return True

if __name__ == "__main__":
    _run_tests()
    print("am_03: all tests passed")
