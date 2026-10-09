"""au_48: Repeat with separator."""
def repeat_str(s, n, sep=''):
    """Repeat s n times joined by sep."""
    return sep.join([s] * n)

def _run_tests():
    assert repeat_str('ab', 3) == 'ababab'
    assert repeat_str('x', 2, '-') == 'x-x'

if __name__ == "__main__":
    _run_tests()
    print("au_48 OK")
