"""Remove duplicates, keep order. stdlib only."""

def dedup(xs):
    seen, out = set(), []
    for x in xs:
        if x not in seen:
            seen.add(x); out.append(x)
    return out

def test():
    assert dedup([1,2,2,3,1]) == [1,2,3]
    assert dedup([]) == []
    assert dedup([1,1,1]) == [1]

if __name__ == '__main__':
    test(); print('ok')
