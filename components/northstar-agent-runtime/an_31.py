"""an_31: flatten one level. Stdlib only."""

def flat(xs):
    out = []
    for x in xs:
        out.extend(x)
    return out

if __name__ == "__main__":
    assert flat([[1, 2], [3]]) == [1, 2, 3]
    assert flat([]) == []
    print("ok")
