"""ao_43: deep_get utility (stdlib only)."""

def deep_get(d, path, default=None):
    for k in path:
        if not isinstance(d, dict): return default
        d = d.get(k, default)
    return d


def _self_test():
    assert deep_get({'a':{'b':1}}, ['a','b']) == 1, "deep_get({'a':{'b':1}}, ['a','b']) == 1"
    assert deep_get({}, ['x'], 'd') == 'd', "deep_get({}, ['x'], 'd') == 'd'"


if __name__ == "__main__":
    _self_test()
    print("ok")
