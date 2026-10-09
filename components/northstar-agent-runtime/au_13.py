"""au_13: Anagram check."""
def is_anagram(a, b):
    """True if a and b are anagrams (letters only, case-insensitive)."""
    f = lambda s: sorted(ch for ch in s.lower() if ch.isalpha())
    return f(a) == f(b)

def _run_tests():
    assert is_anagram('listen', 'silent')
    assert not is_anagram('abc', 'abd')

if __name__ == "__main__":
    _run_tests()
    print("au_13 OK")
