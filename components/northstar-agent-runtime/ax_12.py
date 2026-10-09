"""ax_12: group_by utility (stdlib only)."""
def group_by(items, key):
    d = {}
    for x in items: d.setdefault(key(x), []).append(x)
    return d


def run_tests():
    assert (group_by([1,2,3,4], lambda x: x % 2)) == {1: [1, 3], 0: [2, 4]}, 'group_by([1,2,3,4], lambda x: x % 2)'
    assert (group_by([], str)) == {}, 'group_by([], str)'
    return True


if __name__ == "__main__":
    run_tests()
    print("ax_12: ok")
