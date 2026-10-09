"""ao_44: deep_set utility (stdlib only)."""

def deep_set(d, path, val):
    root = d
    for k in path[:-1]: d = d.setdefault(k, {})
    d[path[-1]] = val
    return root


def _self_test():
    assert deep_set({}, ['a','b'], 1) == {'a':{'b':1}}, "deep_set({}, ['a','b'], 1) == {'a':{'b':1}}"
    assert deep_set({}, ['x'], 0) == {'x':0}, "deep_set({}, ['x'], 0) == {'x':0}"


if __name__ == "__main__":
    _self_test()
    print("ok")
