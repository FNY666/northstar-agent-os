"""Utility ay_21: median_vals."""


def median_vals(lst):
    """Return median_vals result."""
    s = sorted(lst); n = len(s); return s[n//2] if n % 2 else (s[n//2-1]+s[n//2])/2 if n else 0


def _run_tests():
    assert median_vals([3,1,2]) == 2
    assert median_vals([1,2,3,4]) == 2.5


if __name__ == '__main__':
    _run_tests()
    print('OK')
