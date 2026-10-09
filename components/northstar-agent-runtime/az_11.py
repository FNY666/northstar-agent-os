"""Most common element. stdlib only."""

def mode(xs):
    return max(set(xs), key=xs.count)

def test():
    assert mode([1,2,2,3]) == 2
    assert mode(['a','b','a']) == 'a'
    assert mode([7]) == 7

if __name__ == '__main__':
    test(); print('ok')
