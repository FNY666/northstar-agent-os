"""an_48: dict keys as list. Stdlib only."""

def keys(d):
    return list(d.keys())

if __name__ == "__main__":
    assert keys({'a': 1}) == ['a']
    assert keys({}) == []
    print("ok")
