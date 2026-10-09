"""ak_45: Prefix sums."""

def prefix_sums(xs):
    t, out = 0, []
    for x in xs:
        t += x; out.append(t)
    return out

if __name__ == '__main__':
    assert prefix_sums([1, 2, 3]) == [1, 3, 6]
    assert prefix_sums([]) == []
    print('ok')
