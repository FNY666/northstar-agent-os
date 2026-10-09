"""au_49: Center-pad a string."""
def pad_center(s, width, fill=' '):
    """Center s in a field of width using fill."""
    return s.center(width, fill)

def _run_tests():
    assert pad_center('ab', 6) == '  ab  '
    assert pad_center('abc', 2) == 'abc'

if __name__ == "__main__":
    _run_tests()
    print("au_49 OK")
