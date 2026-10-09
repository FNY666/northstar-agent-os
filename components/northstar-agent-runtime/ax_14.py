"""ax_14: invert_dict utility (stdlib only)."""
def invert_dict(d):
    return {v: k for k, v in d.items()}


def run_tests():
    assert (invert_dict({'a': 1})) == {1: 'a'}, "invert_dict({'a': 1})"
    assert (invert_dict({})) == {}, 'invert_dict({})'
    return True


if __name__ == "__main__":
    run_tests()
    print("ax_14: ok")
