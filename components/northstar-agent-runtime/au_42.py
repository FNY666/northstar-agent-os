"""au_42: Character frequencies."""
def char_freq(s):
    """Return dict of character counts."""
    d = {}
    for ch in s:
        d[ch] = d.get(ch, 0) + 1
    return d

def _run_tests():
    assert char_freq('aab') == {'a': 2, 'b': 1}
    assert char_freq('') == {}

if __name__ == "__main__":
    _run_tests()
    print("au_42 OK")
