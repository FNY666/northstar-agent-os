"""an_50: merge two dicts. Stdlib only."""

def merged(a, b):
    c = dict(a)
    c.update(b)
    return c

if __name__ == "__main__":
    assert merged({'a': 1}, {'b': 2}) == {'a': 1, 'b': 2}
    assert merged({}, {}) == {}
    print("ok")
