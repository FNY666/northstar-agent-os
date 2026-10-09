"""ak_34: First non-repeating character."""

def first_unique(s):
    from collections import Counter
    c = Counter(s)
    for ch in s:
        if c[ch] == 1: return ch
    return None

if __name__ == '__main__':
    assert first_unique('aabbc') == 'c'
    assert first_unique('aabb') is None
    print('ok')
