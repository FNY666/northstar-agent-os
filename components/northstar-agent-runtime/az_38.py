"""Nested dict get. stdlib only."""

def safe_get(d, path, default=None):
    cur = d
    for k in path:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur

def test():
    assert safe_get({'a':{'b':1}}, ['a','b']) == 1
    assert safe_get({'a':{}}, ['a','b'], 9) == 9
    assert safe_get({}, ['x']) is None

if __name__ == '__main__':
    test(); print('ok')
