"""am_15: min_of_two utility (stdlib only)."""

def min_of_two(a, b):
    return a if a <= b else b

def _run_tests():
    assert min_of_two(3, 7) == 3, 'am_15'
    assert min_of_two(9, 2) == 2, 'am_15'
    return True

if __name__ == "__main__":
    _run_tests()
    print("am_15: all tests passed")
