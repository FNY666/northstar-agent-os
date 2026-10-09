"""Invert dict (values unique). stdlib only."""

def invert_dict(d):
    return {v: k for k, v in d.items()}

def test():
    assert invert_dict({'a':1,'b':2}) == {1:'a', 2:'b'}
    assert invert_dict({}) == {}
    assert invert_dict({1:1}) == {1:1}

if __name__ == '__main__':
    test(); print('ok')
