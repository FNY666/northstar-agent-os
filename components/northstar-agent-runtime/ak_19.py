"""ak_19: Running total of numbers."""

def running_total(xs):
    t, out = 0, []
    for x in xs:
        t += x; out.append(t)
    return out

if __name__ == '__main__':
    assert running_total([1, 2, 3]) == [1, 3, 6]
    assert running_total([]) == []
    print('ok')
