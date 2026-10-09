"""ak_18: Longest word in text."""

def longest_word(text):
    words = text.split()
    return max(words, key=len) if words else ''

if __name__ == '__main__':
    assert longest_word('a bb ccc') == 'ccc'
    assert longest_word('') == ''
    print('ok')
