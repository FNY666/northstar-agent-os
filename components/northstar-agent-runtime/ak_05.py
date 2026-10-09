"""ak_05: Count word frequency in text."""

def word_freq(text):
    from collections import Counter
    return dict(Counter(text.lower().split()))

if __name__ == '__main__':
    assert word_freq('a b a') == {'a': 2, 'b': 1}
    assert word_freq('') == {}
    print('ok')
