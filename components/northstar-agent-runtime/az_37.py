"""Merge dicts (later wins). stdlib only."""

def merge_dicts(*ds):
    out = {}
    for d in ds:
        out.update(d)
    return out

def test():
    assert merge_dicts({'a':1},{'a':2,'b':3}) == {'a':2,'b':3}
    assert merge_dicts() == {}
    assert merge_dicts({'x':1}) == {'x':1}

if __name__ == '__main__':
    test(); print('ok')
