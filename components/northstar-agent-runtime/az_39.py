"""Flatten dict keys with dots. stdlib only."""

def flat_keys(d, prefix=''):
    out = {}
    for k, v in d.items():
        key = f'{prefix}.{k}' if prefix else str(k)
        if isinstance(v, dict):
            out.update(flat_keys(v, key))
        else:
            out[key] = v
    return out

def test():
    assert flat_keys({'a':{'b':1}}) == {'a.b':1}
    assert flat_keys({}) == {}
    assert flat_keys({'x':1}) == {'x':1}

if __name__ == '__main__':
    test(); print('ok')
