"""ax_01: flatten_list utility (stdlib only)."""
def flatten_list(nested):
    out = []
    for x in nested:
        out.extend(flatten_list(x)) if isinstance(x, list) else out.append(x)
    return out


def run_tests():
    assert (flatten_list([1,[2,[3]]])) == [1, 2, 3], 'flatten_list([1,[2,[3]]])'
    assert (flatten_list([])) == [], 'flatten_list([])'
    return True


if __name__ == "__main__":
    run_tests()
    print("ax_01: ok")
