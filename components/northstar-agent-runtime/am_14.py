"""am_14: max_of_two utility (stdlib only)."""

def max_of_two(a, b):
    return a if a >= b else b

def _run_tests():
    assert max_of_two(3, 7) == 7, 'am_14'
    assert max_of_two(9, 2) == 9, 'am_14'
    return True

if __name__ == "__main__":
    _run_tests()
    print("am_14: all tests passed")
