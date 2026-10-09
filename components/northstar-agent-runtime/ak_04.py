"""ak_04: Remove duplicates preserving order."""

def dedupe(xs):
    seen, out = set(), []
    for x in xs:
        if x not in seen:
            seen.add(x); out.append(x)
    return out

if __name__ == '__main__':
    assert dedupe([1, 2, 1, 3, 2]) == [1, 2, 3]
    assert dedupe([]) == []
    print('ok')
