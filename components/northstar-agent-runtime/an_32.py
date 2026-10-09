"""an_32: unique preserving order. Stdlib only."""

def uniq(xs):
    seen = []
    for x in xs:
        if x not in seen:
            seen.append(x)
    return seen

if __name__ == "__main__":
    assert uniq([1, 2, 1, 3]) == [1, 2, 3]
    assert uniq([]) == []
    print("ok")
