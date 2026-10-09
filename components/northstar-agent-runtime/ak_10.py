"""ak_10: Title-case words in a string."""

def title_words(s):
    return ' '.join(w[:1].upper() + w[1:].lower() for w in s.split())

if __name__ == '__main__':
    assert title_words('hello WORLD') == 'Hello World'
    assert title_words('') == ''
    print('ok')
