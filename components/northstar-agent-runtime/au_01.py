"""au_01: Reverse a string."""
def reverse_string(s):
    """Return the reverse of s."""
    return s[::-1]

def _run_tests():
    assert reverse_string('abc') == 'cba'
    assert reverse_string('') == ''

if __name__ == "__main__":
    _run_tests()
    print("au_01 OK")
