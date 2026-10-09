"""Count words in string. stdlib only."""

def count_words(s):
    return len(s.split())

def test():
    assert count_words('a b c') == 3
    assert count_words('') == 0
    assert count_words('  x  ') == 1

if __name__ == '__main__':
    test(); print('ok')
