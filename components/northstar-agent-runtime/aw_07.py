"""Group items by key function into a dict."""
def group_by(xs, key):
    d = {}
    for x in xs:
        d.setdefault(key(x), []).append(x)
    return d
if __name__ == "__main__":
    assert group_by([1,2,3,4], lambda x: x % 2) == {1:[1,3],0:[2,4]}
    assert group_by([], str) == {}
    assert group_by("aab", str) == {"a":["a","a"],"b":["b"]}
    print("ok")
