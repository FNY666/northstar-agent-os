"""au_50: Truncate with ellipsis."""
def truncate(s, n):
    """Truncate s to n chars, adding ... if cut."""
    return s if len(s) <= n else s[:max(n-3, 0)] + '...'

def _run_tests():
    assert truncate('hello world', 8) == 'hello...'
    assert truncate('hi', 5) == 'hi'

if __name__ == "__main__":
    _run_tests()
    print("au_50 OK")
