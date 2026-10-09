"""ak_39: Flatten dict one level."""

def flat_dict(d):
    out = {}
    for k, v in d.items():
        if isinstance(v, dict):
            for k2, v2 in v.items(): out[f'{k}.{k2}'] = v2
        else: out[k] = v
    return out

if __name__ == '__main__':
    assert flat_dict({'a': {'b': 1}, 'c': 2}) == {'a.b': 1, 'c': 2}
    assert flat_dict({}) == {}
    print('ok')
