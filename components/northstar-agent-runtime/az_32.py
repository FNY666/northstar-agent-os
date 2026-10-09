"""List union (ordered). stdlib only."""

def union(a, b):
    out, seen = [], set()
    for x in list(a) + list(b):
        if x not in seen:
            seen.add(x); out.append(x)
    return out

def test():
    assert union([1,2],[2,3]) == [1,2,3]
    assert union([], []) == []
    assert union([1],[1]) == [1]

if __name__ == '__main__':
    test(); print('ok')
