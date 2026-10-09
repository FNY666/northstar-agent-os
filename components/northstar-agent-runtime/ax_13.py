"""ax_13: merge_dicts utility (stdlib only)."""
def merge_dicts(a, b):
    r = dict(a); r.update(b); return r


def run_tests():
    assert (merge_dicts({'a': 1}, {'b': 2})) == {'a': 1, 'b': 2}, "merge_dicts({'a': 1}, {'b': 2})"
    assert (merge_dicts({}, {})) == {}, 'merge_dicts({}, {})'
    return True


if __name__ == "__main__":
    run_tests()
    print("ax_13: ok")
