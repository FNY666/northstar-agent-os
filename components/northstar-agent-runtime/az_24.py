"""Snake to camel case. stdlib only."""

def camel_case(s):
    parts = s.split('_')
    return parts[0] + ''.join(p.capitalize() for p in parts[1:])

def test():
    assert camel_case('hello_world') == 'helloWorld'
    assert camel_case('a') == 'a'
    assert camel_case('') == ''

if __name__ == '__main__':
    test(); print('ok')
