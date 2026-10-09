"""ax_43: deep_get utility (stdlib only)."""
def deep_get(d, keys, default=None):
    cur = d
    for k in keys:
        if not isinstance(cur, dict) or k not in cur: return default
        cur = cur[k]
    return cur


def run_tests():
    assert (deep_get({'a': {'b': 1}}, ['a', 'b'])) == 1, "deep_get({'a': {'b': 1}}, ['a', 'b'])"
    assert (deep_get({}, ['x'], 'd')) == 'd', "deep_get({}, ['x'], 'd')"
    return True


if __name__ == "__main__":
    run_tests()
    print("ax_43: ok")
