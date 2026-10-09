"""Running sum. stdlib only."""

def running_sum(xs):
    out, total = [], 0
    for x in xs:
        total += x
        out.append(total)
    return out

def test():
    assert running_sum([1,2,3]) == [1,3,6]
    assert running_sum([]) == []
    assert running_sum([5]) == [5]

if __name__ == '__main__':
    test(); print('ok')
