"""am_16: power_two utility (stdlib only)."""

def power_two(n):
    return 2 ** n

def _run_tests():
    assert power_two(3) == 8, 'am_16'
    assert power_two(0) == 1, 'am_16'
    return True

if __name__ == "__main__":
    _run_tests()
    print("am_16: all tests passed")
