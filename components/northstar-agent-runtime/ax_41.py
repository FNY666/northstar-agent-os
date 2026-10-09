"""ax_41: flatten_dict utility (stdlib only)."""
def flatten_dict(d, sep='.'):
    out = {}
    def rec(o, p):
        for k, v in o.items():
            nk = f'{p}{sep}{k}' if p else str(k)
            rec(v, nk) if isinstance(v, dict) else out.__setitem__(nk, v)
    rec(d, ''); return out


def run_tests():
    assert (flatten_dict({'a': {'b': 1}})) == {'a.b': 1}, "flatten_dict({'a': {'b': 1}})"
    assert (flatten_dict({})) == {}, 'flatten_dict({})'
    return True


if __name__ == "__main__":
    run_tests()
    print("ax_41: ok")
