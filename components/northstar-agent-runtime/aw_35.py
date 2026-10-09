"""Count items by key function."""
def count_by(xs, key):
    d = {}
    for x in xs:
        k = key(x)
        d[k] = d.get(k, 0) + 1
    return d
if __name__ == "__main__":
    assert count_by([1,2,3,4], lambda x: x % 2) == {1: 2, 0: 2}
    assert count_by([], str) == {}
    assert count_by("aab", str) == {"a": 2, "b": 1}
    print("ok")
