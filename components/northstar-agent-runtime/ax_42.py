"""ax_42: unflatten_dict utility (stdlib only)."""
def unflatten_dict(d, sep='.'):
    out = {}
    for k, v in d.items():
        cur = out
        *parts, last = k.split(sep)
        for p in parts: cur = cur.setdefault(p, {})
        cur[last] = v
    return out


def run_tests():
    assert (unflatten_dict({'a.b': 1})) == {'a': {'b': 1}}, "unflatten_dict({'a.b': 1})"
    assert (unflatten_dict({})) == {}, 'unflatten_dict({})'
    return True


if __name__ == "__main__":
    run_tests()
    print("ax_42: ok")
