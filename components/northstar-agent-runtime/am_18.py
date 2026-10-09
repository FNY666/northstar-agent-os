"""am_18: sum_range utility (stdlib only)."""

def sum_range(n):
    return sum(range(1, n + 1))

def _run_tests():
    assert sum_range(10) == 55, 'am_18'
    assert sum_range(1) == 1, 'am_18'
    return True

if __name__ == "__main__":
    _run_tests()
    print("am_18: all tests passed")
