"""ak_41: Repeat each char n times."""

def repeat_chars(s, n):
    return ''.join(c * n for c in s)

if __name__ == '__main__':
    assert repeat_chars('ab', 2) == 'aabb'
    assert repeat_chars('x', 0) == ''
    print('ok')
