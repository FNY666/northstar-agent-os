"""ak_13: Anagram check."""

def is_anagram(a, b):
    from collections import Counter
    return Counter(a.replace(' ', '').lower()) == Counter(b.replace(' ', '').lower())

if __name__ == '__main__':
    assert is_anagram('listen', 'silent')
    assert not is_anagram('abc', 'abd')
    print('ok')
