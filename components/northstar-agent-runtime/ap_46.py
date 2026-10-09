"""flatten_dict utility."""

def flatten_dict(d, sep='.', prefix=''):
    out = {}
    for k, v in d.items():
        key = f'{prefix}{sep}{k}' if prefix else str(k)
        if isinstance(v, dict): out.update(flatten_dict(v, sep, key))
        else: out[key] = v
    return out


def _self_test():
    assert flatten_dict({'a': {'b': 1}}) == {'a.b': 1}
    assert flatten_dict({}) == {}


if __name__ == "__main__":
    _self_test()
    print("ap_46: OK")
