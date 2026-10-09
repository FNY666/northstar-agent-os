"""unflatten_dict utility."""

def unflatten_dict(d, sep='.'):
    out = {}
    for k, v in d.items():
        parts = k.split(sep); cur = out
        for p in parts[:-1]:
            cur = cur.setdefault(p, {})
        cur[parts[-1]] = v
    return out


def _self_test():
    assert unflatten_dict({'a.b': 1}) == {'a': {'b': 1}}
    assert unflatten_dict({}) == {}


if __name__ == "__main__":
    _self_test()
    print("ap_47: OK")
