"""ak_37: Normalize whitespace."""

def normalize_ws(s):
    return ' '.join(s.split())

if __name__ == '__main__':
    assert normalize_ws('  a   b\t c ') == 'a b c'
    assert normalize_ws('') == ''
    print('ok')
