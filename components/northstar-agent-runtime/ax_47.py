"""ax_47: interleave utility (stdlib only)."""
def interleave(a, b):
    out = []
    for x, y in zip(a, b): out += [x, y]
    rest = a[len(b):] if len(a) > len(b) else b[len(a):]
    return out + list(rest)


def run_tests():
    assert (interleave([1,3], [2,4])) == [1, 2, 3, 4], 'interleave([1,3], [2,4])'
    assert (interleave([1], [])) == [1], 'interleave([1], [])'
    return True


if __name__ == "__main__":
    run_tests()
    print("ax_47: ok")
