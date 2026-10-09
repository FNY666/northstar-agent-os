"""au_03: Count words in a string."""
def word_count(s):
    """Return number of whitespace-separated words."""
    return len(s.split())

def _run_tests():
    assert word_count('a b c') == 3
    assert word_count('') == 0

if __name__ == "__main__":
    _run_tests()
    print("au_03 OK")
