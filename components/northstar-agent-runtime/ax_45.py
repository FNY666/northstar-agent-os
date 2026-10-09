"""ax_45: zip_longest_pad utility (stdlib only)."""
def zip_longest_pad(a, b, fill=None):
    from itertools import zip_longest
    return list(zip_longest(a, b, fillvalue=fill))


def run_tests():
    assert (zip_longest_pad([1], [1,2])) == [(1, 1), (None, 2)], 'zip_longest_pad([1], [1,2])'
    assert (zip_longest_pad([], [])) == [], 'zip_longest_pad([], [])'
    return True


if __name__ == "__main__":
    run_tests()
    print("ax_45: ok")
