"""au_20: Longest word in string."""
def longest_word(s):
    """Return the longest whitespace-separated word (first wins ties)."""
    words = s.split()
    return max(words, key=len) if words else ''

def _run_tests():
    assert longest_word('a bb ccc') == 'ccc'
    assert longest_word('') == ''

if __name__ == "__main__":
    _run_tests()
    print("au_20 OK")
