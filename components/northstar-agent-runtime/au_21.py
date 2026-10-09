"""au_21: Count vowels."""
def vowel_count(s):
    """Count aeiou vowels, case-insensitive."""
    return sum(1 for ch in s.lower() if ch in 'aeiou')

def _run_tests():
    assert vowel_count('hello') == 2
    assert vowel_count('xyz') == 0

if __name__ == "__main__":
    _run_tests()
    print("au_21 OK")
