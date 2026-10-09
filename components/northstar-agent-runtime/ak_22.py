"""ak_22: Common prefix of strings."""

def common_prefix(strs):
    if not strs: return ''
    p = strs[0]
    for s in strs[1:]:
        while not s.startswith(p): p = p[:-1]
    return p

if __name__ == '__main__':
    assert common_prefix(['flower', 'flow', 'flight']) == 'fl'
    assert common_prefix([]) == ''
    print('ok')
