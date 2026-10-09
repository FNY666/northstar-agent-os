"""ak_07: Reverse words in a sentence."""

def reverse_words(s):
    return ' '.join(s.split()[::-1])

if __name__ == '__main__':
    assert reverse_words('a b c') == 'c b a'
    assert reverse_words('  x  y ') == 'y x'
    print('ok')
