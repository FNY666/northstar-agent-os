"""Title-case a string. stdlib only."""

def title_case(s):
    return ' '.join(w[:1].upper() + w[1:].lower() for w in s.split())

def test():
    assert title_case('hello world') == 'Hello World'
    assert title_case('') == ''
    assert title_case('ABC') == 'Abc'

if __name__ == '__main__':
    test(); print('ok')
